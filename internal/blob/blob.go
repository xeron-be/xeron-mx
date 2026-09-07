package blob

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
)

const (
	magic       = "XMXB"
	formatVer   = 1
	saltSize    = 16
	keySize     = 32
	nonceSize   = 12
	tagSize     = 16
	chunkSize   = 64 << 10
	headerSize  = len(magic) + 1 + saltSize
	hkdfInfoStr = "xeronmx blob v1"
)

var ErrCorrupt = errors.New("blob: corrupt or tampered file")

type Store struct {
	root string
	key  []byte
}

func Open(dir, keyPath string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("blob: create spool dir: %w", err)
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &Store{root: dir, key: key}, nil
}

func (s *Store) Root() string {
	return s.root
}

func loadOrCreateKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != keySize {
			return nil, fmt.Errorf("blob: master key at %s is %d bytes, want %d", path, len(raw), keySize)
		}
		return raw, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("blob: read master key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("blob: create key dir: %w", err)
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("blob: generate master key: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return loadOrCreateKey(path)
		}
		return nil, fmt.Errorf("blob: create master key: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return nil, fmt.Errorf("blob: write master key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("blob: sync master key: %w", err)
	}
	return key, nil
}

func (s *Store) pathFor(id string) (string, error) {
	if len(id) < 2 || filepath.Base(id) != id {
		return "", fmt.Errorf("blob: invalid id %q", id)
	}
	return filepath.Join(s.root, id[:2], id+".eml.enc"), nil
}

func (s *Store) aeadFor(salt []byte) (cipher.AEAD, error) {
	derived := make([]byte, keySize)
	kdf := hkdf.New(sha256.New, s.key, salt, []byte(hkdfInfoStr))
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, fmt.Errorf("blob: derive key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("blob: new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func nonceFor(counter uint64, last bool) []byte {
	var n [nonceSize]byte
	binary.BigEndian.PutUint64(n[3:11], counter)
	if last {
		n[11] = 1
	}
	return n[:]
}

func (s *Store) Put(id string, src io.Reader, maxBytes int64) (written int64, err error) {
	path, err := s.pathFor(id)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, fmt.Errorf("blob: create shard dir: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		return 0, fmt.Errorf("blob: id %q already exists", id)
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return 0, fmt.Errorf("blob: generate salt: %w", err)
	}
	aead, err := s.aeadFor(salt)
	if err != nil {
		return 0, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return 0, fmt.Errorf("blob: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return 0, fmt.Errorf("blob: chmod temp: %w", err)
	}

	header := make([]byte, 0, headerSize)
	header = append(header, magic...)
	header = append(header, formatVer)
	header = append(header, salt...)
	if _, err = tmp.Write(header); err != nil {
		return 0, fmt.Errorf("blob: write header: %w", err)
	}

	var (
		plain   = make([]byte, chunkSize)
		sealed  = make([]byte, 0, chunkSize+tagSize)
		counter uint64
	)
	for {
		n, readErr := io.ReadFull(src, plain)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return written, fmt.Errorf("blob: read source: %w", readErr)
		}
		written += int64(n)
		if maxBytes > 0 && written > maxBytes {
			return written, fmt.Errorf("blob: source exceeds %d bytes", maxBytes)
		}

		last := readErr == io.EOF || readErr == io.ErrUnexpectedEOF

		sealed = aead.Seal(sealed[:0], nonceFor(counter, last), plain[:n], nil)
		if _, err = tmp.Write(sealed); err != nil {
			return written, fmt.Errorf("blob: write chunk: %w", err)
		}
		counter++
		if last {
			break
		}
	}

	if err = tmp.Sync(); err != nil {
		return written, fmt.Errorf("blob: sync: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return written, fmt.Errorf("blob: close temp: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return written, fmt.Errorf("blob: rename into place: %w", err)
	}
	return written, nil
}

func (s *Store) Get(id string) (io.ReadCloser, error) {
	path, err := s.pathFor(id)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	header := make([]byte, headerSize)
	if _, err := io.ReadFull(f, header); err != nil {
		f.Close()
		return nil, ErrCorrupt
	}
	if string(header[:len(magic)]) != magic || header[len(magic)] != formatVer {
		f.Close()
		return nil, ErrCorrupt
	}
	aead, err := s.aeadFor(header[len(magic)+1:])
	if err != nil {
		f.Close()
		return nil, err
	}
	return &reader{f: f, aead: aead, buf: make([]byte, chunkSize+tagSize)}, nil
}

func (s *Store) Delete(id string) error {
	path, err := s.pathFor(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("blob: delete: %w", err)
	}
	return nil
}

func (s *Store) Size(id string) (int64, error) {
	path, err := s.pathFor(id)
	if err != nil {
		return 0, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

type reader struct {
	f       *os.File
	aead    cipher.AEAD
	buf     []byte
	plain   []byte
	counter uint64
	done    bool
}

func (r *reader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.done {
			return 0, io.EOF
		}
		if err := r.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

func (r *reader) next() error {
	n, err := io.ReadFull(r.f, r.buf)
	switch {
	case err == nil:

	case err == io.ErrUnexpectedEOF || err == io.EOF:

	default:
		return fmt.Errorf("blob: read chunk: %w", err)
	}
	if n < tagSize {
		return ErrCorrupt
	}

	for _, last := range []bool{false, true} {
		out, openErr := r.aead.Open(nil, nonceFor(r.counter, last), r.buf[:n], nil)
		if openErr != nil {
			continue
		}
		r.plain = out
		r.counter++
		if last {
			r.done = true

			var probe [1]byte
			if _, err := r.f.Read(probe[:]); err == nil {
				return ErrCorrupt
			}
		}
		return nil
	}
	return ErrCorrupt
}

func (r *reader) Close() error { return r.f.Close() }

func (s *Store) Seal(plaintext []byte) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("blob: generate salt: %w", err)
	}
	aead, err := s.aeadFor(salt)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("blob: generate nonce: %w", err)
	}

	out := make([]byte, 0, saltSize+nonceSize+len(plaintext)+tagSize)
	out = append(out, salt...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, nil), nil
}

func (s *Store) Unseal(sealed []byte) ([]byte, error) {
	if len(sealed) < saltSize+nonceSize+tagSize {
		return nil, ErrCorrupt
	}
	salt := sealed[:saltSize]
	nonce := sealed[saltSize : saltSize+nonceSize]

	aead, err := s.aeadFor(salt)
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, nonce, sealed[saltSize+nonceSize:], nil)
	if err != nil {
		return nil, ErrCorrupt
	}
	return out, nil
}
