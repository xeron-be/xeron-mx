package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

const MinPasswordLength = 12

const MaxPasswordBytes = 1024

var ErrInvalidHash = errors.New("auth: malformed password hash")

var ErrPasswordTooLong = fmt.Errorf("auth: password exceeds %d bytes", MaxPasswordBytes)

var hashSlots = make(chan struct{}, hashConcurrency())

func hashConcurrency() int {
	n := runtime.GOMAXPROCS(0)
	if n < 2 {
		n = 2
	}
	if n > 8 {
		n = 8
	}
	return n
}

func argonKey(password string, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
}

func HashPassword(password string) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}
	key := argonKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(password, encoded string) (bool, error) {

	if len(password) > MaxPasswordBytes {
		return false, nil
	}

	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, ErrInvalidHash
	}
	if version != argon2.Version {
		return false, ErrInvalidHash
	}

	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	got := argonKey(password, salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > MaxPasswordBytes {

		return fmt.Errorf("password must be at most %d bytes", MaxPasswordBytes)
	}
	return nil
}

func NewSessionToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("auth: generate session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

const TokenPrefix = "xmx_"

const PrefixLength = len(TokenPrefix) + 8

func NewAPIToken() (token, hash, prefix string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("auth: generate api token: %w", err)
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), token[:PrefixLength], nil
}
