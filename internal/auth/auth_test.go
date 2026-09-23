package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestHashThenVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword(right) = %v, %v; want true, nil", ok, err)
	}
	ok, err = VerifyPassword("correct horse battery stapler", hash)
	if err != nil || ok {
		t.Fatalf("VerifyPassword(wrong) = %v, %v; want false, nil", ok, err)
	}
}

func TestHashIsPHCFormattedWithTheConfiguredCost(t *testing.T) {
	hash, err := HashPassword("a long enough password")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$", argon2.Version, argonMemory, argonTime, argonThreads)
	if !strings.HasPrefix(hash, want) {
		t.Fatalf("hash %q does not start with %q", hash, want)
	}
}

func TestHashIsSaltedPerCall(t *testing.T) {
	a, _ := HashPassword("same password twice")
	b, _ := HashPassword("same password twice")
	if a == b {
		t.Fatal("two hashes of the same password are identical: the salt is not random")
	}
}

// A hash stored under older cost parameters must keep verifying after the
// constants change, or raising the cost would lock every existing account out.
func TestVerifyHonoursTheParametersInTheHash(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte("an older password"), salt, 1, 8*1024, 2, 16)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, 8*1024, 1, 2,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))

	ok, err := VerifyPassword("an older password", encoded)
	if err != nil || !ok {
		t.Fatalf("VerifyPassword = %v, %v; want true, nil", ok, err)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	good, err := HashPassword("a long enough password")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, "$")

	cases := map[string]string{
		"empty":          "",
		"bcrypt":         "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
		"argon2i":        strings.Replace(good, "$argon2id$", "$argon2i$", 1),
		"wrong version":  strings.Replace(good, fmt.Sprintf("v=%d", argon2.Version), "v=16", 1),
		"no params":      strings.Join([]string{"", parts[1], parts[2], "garbage", parts[4], parts[5]}, "$"),
		"bad salt":       strings.Join([]string{"", parts[1], parts[2], parts[3], "!!!", parts[5]}, "$"),
		"bad key":        strings.Join([]string{"", parts[1], parts[2], parts[3], parts[4], "!!!"}, "$"),
		"missing a part": strings.Join(parts[:5], "$"),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPassword("a long enough password", encoded)
			if ok || !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("VerifyPassword = %v, %v; want false, ErrInvalidHash", ok, err)
			}
		})
	}
}

func TestOversizedPasswordsAreRefusedBeforeHashing(t *testing.T) {
	long := strings.Repeat("a", MaxPasswordBytes+1)
	if _, err := HashPassword(long); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("HashPassword(too long) error = %v; want ErrPasswordTooLong", err)
	}

	hash, err := HashPassword("a long enough password")
	if err != nil {
		t.Fatal(err)
	}
	// Answered as a plain mismatch, not an error, so a login form cannot tell
	// "too long" from "wrong" and nobody pays for hashing a megabyte.
	ok, err := VerifyPassword(long, hash)
	if ok || err != nil {
		t.Fatalf("VerifyPassword(too long) = %v, %v; want false, nil", ok, err)
	}

	if _, err := HashPassword(strings.Repeat("a", MaxPasswordBytes)); err != nil {
		t.Fatalf("HashPassword at exactly the limit: %v", err)
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		name     string
		password string
		ok       bool
	}{
		{"empty", "", false},
		{"one short", strings.Repeat("a", MinPasswordLength-1), false},
		{"exactly the minimum", strings.Repeat("a", MinPasswordLength), true},
		// Length is counted in characters, not bytes: twelve accented letters
		// are a twelve-character password even though they take 24 bytes.
		{"multibyte at the minimum", strings.Repeat("é", MinPasswordLength), true},
		{"multibyte one short", strings.Repeat("é", MinPasswordLength-1), false},
		{"at the byte ceiling", strings.Repeat("a", MaxPasswordBytes), true},
		{"over the byte ceiling", strings.Repeat("a", MaxPasswordBytes+1), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePassword(c.password)
			if (err == nil) != c.ok {
				t.Fatalf("ValidatePassword error = %v; want ok=%v", err, c.ok)
			}
		})
	}
}

func TestSessionTokenHashMatchesHashToken(t *testing.T) {
	token, hash, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if HashToken(token) != hash {
		t.Fatal("the stored hash does not match HashToken of the token handed out")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not URL-safe base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("token carries %d bytes of entropy; want 32", len(raw))
	}
	if len(hash) != 64 {
		t.Fatalf("hash is %d hex characters; want 64 (SHA-256)", len(hash))
	}

	other, _, _ := NewSessionToken()
	if other == token {
		t.Fatal("two session tokens are identical")
	}
}

func TestAPIToken(t *testing.T) {
	token, hash, prefix, err := NewAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, TokenPrefix) {
		t.Fatalf("token %q does not start with %q", token, TokenPrefix)
	}
	if len(prefix) != PrefixLength || !strings.HasPrefix(token, prefix) {
		t.Fatalf("prefix %q is not the first %d characters of the token", prefix, PrefixLength)
	}
	if HashToken(token) != hash {
		t.Fatal("the stored hash does not match HashToken of the token handed out")
	}
}
