package mailutil

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

const maxSubjectBytes = 500

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return nil, err
	}
	return enc.NewDecoder().Reader(input), nil
}

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
		return DecodeHeader(subject)
	}
	return ""
}

func DecodeHeader(value string) string {
	if strings.Contains(value, "=?") {
		if decoded, err := wordDecoder.DecodeHeader(value); err == nil {
			value = decoded
		}
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(value, ""))
	return truncateUTF8(strings.TrimSpace(value), maxSubjectBytes)
}

func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
