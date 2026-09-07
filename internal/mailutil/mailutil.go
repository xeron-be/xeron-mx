package mailutil

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"
)

func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func PeekHeaders(r io.Reader, limit int) ([]byte, io.Reader) {
	buf := make([]byte, limit)
	n, _ := io.ReadFull(r, buf)
	head := buf[:n]
	return head, io.MultiReader(bytes.NewReader(head), r)
}

func ExtractSubject(head []byte) string {
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	for i, line := range lines {
		if line == "" {
			return ""
		}
		if len(line) < 8 || !strings.EqualFold(line[:8], "subject:") {
			continue
		}
		subject := strings.TrimSpace(line[8:])
		for _, cont := range lines[i+1:] {
			if cont == "" || (!strings.HasPrefix(cont, " ") && !strings.HasPrefix(cont, "\t")) {
				break
			}
			subject += " " + strings.TrimSpace(cont)
		}
		if len(subject) > 500 {
			subject = subject[:500]
		}
		return strings.ToValidUTF8(subject, "")
	}
	return ""
}
