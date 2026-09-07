package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

var jsonOut bool

func emit(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type table struct {
	w *tabwriter.Writer
}

func newTable(header ...string) *table {
	t := &table{w: tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)}
	if len(header) > 0 {
		fmt.Fprintln(t.w, strings.Join(header, "\t"))
	}
	return t
}

func (t *table) row(cells ...string) {
	fmt.Fprintln(t.w, strings.Join(cells, "\t"))
}

func (t *table) flush() { t.w.Flush() }

func note(format string, args ...any) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func warn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func ago(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := time.Since(*t)
	if d < 0 {
		return "in " + short(-d)
	}
	return short(d) + " ago"
}

func until(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := time.Until(*t)
	if d <= 0 {
		return "expired"
	}
	return "in " + short(d)
}

func short(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func bytesHuman(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return string(r[:max])
	}
	return string(r[:max-1]) + "…"
}

func writeOut(w io.Writer, raw []byte) error {
	_, err := w.Write(raw)
	return err
}
