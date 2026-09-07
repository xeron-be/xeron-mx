package blob

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "spool"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func roundTrip(t *testing.T, s *Store, id string, data []byte) {
	t.Helper()
	n, err := s.Put(id, bytes.NewReader(data), 0)
	if err != nil {
		t.Fatalf("Put(%d bytes): %v", len(data), err)
	}
	if n != int64(len(data)) {
		t.Fatalf("Put reported %d bytes, want %d", n, len(data))
	}
	rc, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

func TestRoundTripSizes(t *testing.T) {
	s := newStore(t)
	sizes := []int{
		0, 1, 100,
		chunkSize - 1, chunkSize, chunkSize + 1,
		2 * chunkSize, 2*chunkSize + 17,
		5*chunkSize + 999,
	}
	for i, size := range sizes {
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		roundTrip(t, s, idFor(i), data)
	}
}

func TestPutRefusesDuplicateID(t *testing.T) {
	s := newStore(t)
	if _, err := s.Put("aa01", bytes.NewReader([]byte("first")), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("aa01", bytes.NewReader([]byte("second")), 0); err == nil {
		t.Fatal("expected duplicate Put to fail, it succeeded")
	}

	rc, err := s.Get("aa01")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "first" {
		t.Fatalf("original body was damaged: %q", got)
	}
}

func TestPutEnforcesMaxBytes(t *testing.T) {
	s := newStore(t)
	data := make([]byte, 4*chunkSize)
	if _, err := s.Put("bb01", bytes.NewReader(data), int64(chunkSize)); err == nil {
		t.Fatal("expected oversized Put to fail, it succeeded")
	}

	if _, err := s.Get("bb01"); !os.IsNotExist(err) {
		t.Fatalf("partial file left behind after refused Put: %v", err)
	}
}

func TestCiphertextDoesNotLeakPlaintext(t *testing.T) {
	s := newStore(t)
	secret := []byte("Subject: salary review\r\n\r\nthis must never appear on disk")
	if _, err := s.Put("cc01", bytes.NewReader(secret), 0); err != nil {
		t.Fatal(err)
	}
	path, err := s.pathFor("cc01")
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte("salary review")) {
		t.Fatal("plaintext found in the encrypted file")
	}
	if bytes.Contains(onDisk, []byte("never appear")) {
		t.Fatal("plaintext body found in the encrypted file")
	}
}

func TestTruncationIsDetected(t *testing.T) {
	s := newStore(t)
	data := make([]byte, 3*chunkSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("dd01", bytes.NewReader(data), 0); err != nil {
		t.Fatal(err)
	}
	path, _ := s.pathFor("dd01")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, raw[:len(raw)-(chunkSize+tagSize)], 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Get("dd01")
	if err != nil {
		t.Fatalf("Get should still open the file: %v", err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("truncated file decrypted without error")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	s := newStore(t)
	if _, err := s.Put("ee01", bytes.NewReader(bytes.Repeat([]byte("x"), 5000)), 0); err != nil {
		t.Fatal(err)
	}
	path, _ := s.pathFor("ee01")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[headerSize+10] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := s.Get("ee01")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); err != ErrCorrupt {
		t.Fatalf("tampered file gave %v, want ErrCorrupt", err)
	}
}

func TestAppendedBytesAreDetected(t *testing.T) {
	s := newStore(t)
	if _, err := s.Put("ff01", bytes.NewReader([]byte("short body")), 0); err != nil {
		t.Fatal(err)
	}
	path, _ := s.pathFor("ff01")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("extra data appended after the final chunk"))
	f.Close()

	rc, err := s.Get("ff01")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("appended file decrypted without error")
	}
}

func TestWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")

	s1, err := Open(spool, filepath.Join(dir, "key1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Put("aa99", bytes.NewReader([]byte("confidential")), 0); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(spool, filepath.Join(dir, "key2"))
	if err != nil {
		t.Fatal(err)
	}
	rc, err := s2.Get("aa99")
	if err != nil {
		return
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); err == nil {
		t.Fatal("a different master key decrypted the body")
	}
}

func TestKeyIsStableAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	spool, keyPath := filepath.Join(dir, "spool"), filepath.Join(dir, "master.key")

	s1, err := Open(spool, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Put("ab01", bytes.NewReader([]byte("persisted")), 0); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(spool, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := s2.Get("ab01")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reopened store could not read its own spool: %v", err)
	}
	if string(got) != "persisted" {
		t.Fatalf("got %q, want %q", got, "persisted")
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	s := newStore(t)
	if _, err := s.Put("ac01", bytes.NewReader([]byte("body")), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("ac01"); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete("ac01"); err != nil {
		t.Fatalf("second Delete returned %v, want nil", err)
	}
}

func TestRejectsPathTraversalID(t *testing.T) {
	s := newStore(t)
	for _, id := range []string{"../escape", "a/b", "", "x"} {
		if _, err := s.Put(id, bytes.NewReader([]byte("x")), 0); err == nil {
			t.Fatalf("Put accepted unsafe id %q", id)
		}
	}
}

func idFor(i int) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[i%16], hex[(i/16)%16]}) + "0000deadbeef"
}

func TestSealRoundTrip(t *testing.T) {
	s := newStore(t)

	secret := []byte("-----BEGIN PRIVATE KEY-----\nnot really a key\n-----END PRIVATE KEY-----\n")
	sealed, err := s.Seal(secret)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("the sealed value contains the plaintext")
	}

	back, err := s.Unseal(sealed)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(back, secret) {
		t.Fatalf("round trip returned %q", back)
	}
}

func TestSealIsNotDeterministic(t *testing.T) {
	s := newStore(t)

	a, err := s.Seal([]byte("same input"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Seal([]byte("same input"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("sealing the same value twice produced identical bytes; the salt or nonce is fixed")
	}
}

func TestUnsealRejectsTampering(t *testing.T) {
	s := newStore(t)

	sealed, err := s.Seal([]byte("a signing key"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0x01

	if _, err := s.Unseal(sealed); err == nil {
		t.Fatal("a tampered value was accepted")
	}
	if _, err := s.Unseal(sealed[:4]); err == nil {
		t.Fatal("a truncated value was accepted")
	}
}
