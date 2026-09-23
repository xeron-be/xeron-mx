package arc

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

type field struct {
	name string
	raw  string
}

func (f field) value() string {
	if i := strings.IndexByte(f.raw, ':'); i >= 0 {
		return f.raw[i+1:]
	}
	return ""
}

func normalizeLineEndings(raw []byte) []byte {
	if !bytes.Contains(raw, []byte("\n")) {
		return raw
	}
	out := make([]byte, 0, len(raw)+len(raw)/40)
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\r':
			if i+1 < len(raw) && raw[i+1] == '\n' {
				out = append(out, '\r', '\n')
				i++
			} else {
				out = append(out, '\r', '\n')
			}
		case '\n':
			out = append(out, '\r', '\n')
		default:
			out = append(out, raw[i])
		}
	}
	return out
}

func splitMessage(raw []byte) ([]field, []byte) {
	var head, body []byte
	switch {
	case bytes.HasPrefix(raw, []byte("\r\n")):
		head, body = nil, raw[2:]
	default:
		if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
			head, body = raw[:i+2], raw[i+4:]
		} else {
			head, body = raw, nil
		}
	}

	var fields []field
	for _, line := range strings.SplitAfter(string(head), "\r\n") {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(fields) > 0 {
			fields[len(fields)-1].raw += line
			continue
		}
		fields = append(fields, field{raw: line})
	}
	out := fields[:0]
	for _, f := range fields {
		f.raw = strings.TrimSuffix(f.raw, "\r\n")
		colon := strings.IndexByte(f.raw, ':')
		if colon <= 0 {
			continue
		}
		f.name = strings.TrimRight(f.raw[:colon], " \t")
		out = append(out, f)
	}
	return out, body
}

func compressWSP(s string) string {
	var b strings.Builder
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			space = true
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteByte(c)
	}
	if space {
		b.WriteByte(' ')
	}
	return b.String()
}

func unfold(s string) string {
	return strings.NewReplacer("\r\n", "", "\n", "", "\r", "").Replace(s)
}

func canonHeader(f field, relaxed bool) string {
	if !relaxed {
		return f.raw + "\r\n"
	}
	name := strings.ToLower(strings.TrimSpace(f.name))
	val := strings.TrimSpace(compressWSP(unfold(f.value())))
	return name + ":" + val + "\r\n"
}

func canonBody(body []byte, relaxed bool) []byte {
	lines := strings.Split(string(body), "\r\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if relaxed {
		for i, l := range lines {
			lines[i] = strings.TrimRight(compressWSP(l), " ")
		}
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		if relaxed {
			return nil
		}
		return []byte("\r\n")
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

type tagList map[string]string

func parseTags(v string) (tagList, bool) {
	tags := tagList{}
	for _, part := range strings.Split(unfold(v), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			return nil, false
		}
		name := strings.TrimSpace(part[:eq])
		if _, dup := tags[name]; dup {
			return nil, false
		}
		tags[name] = strings.TrimSpace(part[eq+1:])
	}
	return tags, true
}

func (t tagList) compact(name string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, t[name])
}

var bTag = regexp.MustCompile(`(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*`)

func stripSignature(f field) field {
	colon := strings.IndexByte(f.raw, ':')
	f.raw = f.raw[:colon+1] + bTag.ReplaceAllString(f.raw[colon+1:], "$1$2")
	return f
}

func instanceOf(f field) (int, bool) {
	var raw string
	if strings.EqualFold(f.name, aarName) {
		v := strings.TrimSpace(unfold(f.value()))
		semi := strings.IndexByte(v, ';')
		if semi < 0 {
			semi = len(v)
		}
		tag := strings.TrimSpace(v[:semi])
		if !strings.HasPrefix(tag, "i") {
			return 0, false
		}
		name, val, ok := strings.Cut(tag, "=")
		if !ok || strings.TrimSpace(name) != "i" {
			return 0, false
		}
		raw = strings.TrimSpace(val)
	} else {
		tags, ok := parseTags(f.value())
		if !ok {
			return 0, false
		}
		raw = tags["i"]
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > MaxInstances {
		return 0, false
	}
	return n, true
}
