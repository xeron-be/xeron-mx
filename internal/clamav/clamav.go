package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
)

type Scanner struct {
	enabled bool
	network string
	target  string
	timeout time.Duration
	action  string
}

type Result struct {
	Infected  bool          `json:"infected"`
	VirusName string        `json:"virus_name,omitempty"`
	Duration  time.Duration `json:"duration"`
}

func New(cfg config.ClamAVConfig) *Scanner {
	network := "tcp"
	target := cfg.Addr

	if strings.HasPrefix(target, "unix://") {
		network = "unix"
		target = strings.TrimPrefix(target, "unix://")
	} else if strings.HasPrefix(target, "tcp://") {
		network = "tcp"
		target = strings.TrimPrefix(target, "tcp://")
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	action := cfg.Action
	if action == "" {
		action = "quarantine"
	}

	return &Scanner{
		enabled: cfg.Enabled,
		network: network,
		target:  target,
		timeout: timeout,
		action:  action,
	}
}

func (s *Scanner) Enabled() bool {
	return s.enabled
}

func (s *Scanner) Action() string {
	return s.action
}

func (s *Scanner) Addr() string {
	if s.network == "unix" {
		return "unix://" + s.target
	}
	return s.target
}

func (s *Scanner) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	timeout := s.timeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}
	d.Timeout = timeout
	return d.DialContext(ctx, s.network, s.target)
}

func (s *Scanner) Ping(ctx context.Context) error {
	if !s.enabled {
		return errors.New("clamav disabled")
	}
	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(s.timeout))
	}

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\x00')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) > 0 {
			line = strings.TrimSpace(line)
		} else {
			return err
		}
	} else {
		line = strings.TrimRight(line, "\x00\r\n")
	}

	if strings.Contains(line, "PONG") {
		return nil
	}
	return fmt.Errorf("unexpected ping response: %q", line)
}

func (s *Scanner) Scan(ctx context.Context, r io.Reader) (*Result, error) {
	start := time.Now()
	res := &Result{}

	if !s.enabled {
		res.Duration = time.Since(start)
		return res, nil
	}

	conn, err := s.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("clamav dial %s: %w", s.target, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(s.timeout))
	}

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, fmt.Errorf("clamav write command: %w", err)
	}

	buf := make([]byte, 32*1024)
	lenBuf := make([]byte, 4)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		n, readErr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := conn.Write(lenBuf); err != nil {
				return nil, fmt.Errorf("clamav write chunk size: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return nil, fmt.Errorf("clamav write chunk data: %w", err)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read stream: %w", readErr)
		}
	}

	binary.BigEndian.PutUint32(lenBuf, 0)
	if _, err := conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("clamav write terminator: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\x00')
	if err != nil {
		if len(resp) == 0 {
			resp2, err2 := reader.ReadString('\n')
			if err2 != nil && !errors.Is(err2, io.EOF) {
				return nil, fmt.Errorf("clamav read response: %w", err)
			}
			resp = resp2
		}
	}
	resp = strings.Trim(resp, "\x00\r\n ")

	res.Duration = time.Since(start)

	if strings.HasSuffix(resp, "OK") {
		res.Infected = false
		return res, nil
	}

	if strings.HasSuffix(resp, "FOUND") {
		res.Infected = true
		parts := strings.Fields(resp)
		if len(parts) >= 3 {
			res.VirusName = parts[1]
		} else {
			res.VirusName = strings.TrimPrefix(resp, "stream: ")
			res.VirusName = strings.TrimSuffix(res.VirusName, " FOUND")
		}
		return res, nil
	}

	if strings.Contains(resp, "ERROR") {
		return nil, fmt.Errorf("clamav returned error: %s", resp)
	}

	return nil, fmt.Errorf("clamav unknown response: %q", resp)
}
