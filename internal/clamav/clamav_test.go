package clamav

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
)

func startMockClamAV(t *testing.T, handler func(conn net.Conn)) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				handler(c)
			}(conn)
		}
	}()

	cleanup := func() {
		close(stop)
		ln.Close()
	}

	return ln.Addr().String(), cleanup
}

func readClamAVStream(conn net.Conn) ([]byte, error) {
	cmd := make([]byte, 10)
	n, err := conn.Read(cmd)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(cmd[:n]), "zINSTREAM") {
		return nil, io.ErrUnexpectedEOF
	}

	var data bytes.Buffer
	lenBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if chunkLen == 0 {
			break
		}
		chunk := make([]byte, chunkLen)
		if _, err := io.ReadFull(conn, chunk); err != nil {
			return nil, err
		}
		data.Write(chunk)
	}
	return data.Bytes(), nil
}

func TestScanCleanMessage(t *testing.T) {
	addr, cleanup := startMockClamAV(t, func(conn net.Conn) {
		_, err := readClamAVStream(conn)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("stream: OK\x00"))
	})
	defer cleanup()

	scanner := New(config.ClamAVConfig{
		Enabled: true,
		Addr:    addr,
		Timeout: 2 * time.Second,
		Action:  "quarantine",
	})

	body := strings.NewReader("Subject: Clean mail\r\n\r\nThis is a harmless message.")
	res, err := scanner.Scan(context.Background(), body)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}
	if res.Infected {
		t.Fatalf("expected message to be clean, got infected")
	}
	if res.VirusName != "" {
		t.Fatalf("expected empty virus name, got %q", res.VirusName)
	}
}

func TestScanInfectedMessage(t *testing.T) {
	addr, cleanup := startMockClamAV(t, func(conn net.Conn) {
		_, err := readClamAVStream(conn)
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("stream: Win.Test.EICAR_HDB-1 FOUND\x00"))
	})
	defer cleanup()

	scanner := New(config.ClamAVConfig{
		Enabled: true,
		Addr:    addr,
		Timeout: 2 * time.Second,
		Action:  "reject",
	})

	body := strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	res, err := scanner.Scan(context.Background(), body)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}
	if !res.Infected {
		t.Fatalf("expected message to be infected")
	}
	if res.VirusName != "Win.Test.EICAR_HDB-1" {
		t.Fatalf("expected virus Win.Test.EICAR_HDB-1, got %q", res.VirusName)
	}
}

func TestPing(t *testing.T) {
	addr, cleanup := startMockClamAV(t, func(conn net.Conn) {
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if strings.Contains(string(buf[:n]), "PING") {
			_, _ = conn.Write([]byte("PONG\x00"))
		}
	})
	defer cleanup()

	scanner := New(config.ClamAVConfig{
		Enabled: true,
		Addr:    addr,
		Timeout: 2 * time.Second,
	})

	if err := scanner.Ping(context.Background()); err != nil {
		t.Fatalf("expected ping to succeed, got %v", err)
	}
}

func TestDisabledScanner(t *testing.T) {
	scanner := New(config.ClamAVConfig{
		Enabled: false,
		Addr:    "127.0.0.1:12345",
	})

	body := strings.NewReader("any content")
	res, err := scanner.Scan(context.Background(), body)
	if err != nil {
		t.Fatalf("unexpected scan error for disabled scanner: %v", err)
	}
	if res.Infected {
		t.Fatalf("disabled scanner should not flag as infected")
	}

	if err := scanner.Ping(context.Background()); err == nil {
		t.Fatalf("ping on disabled scanner should return error")
	}
}
