package netlimit

import (
	"bufio"
	"net"
	"sync"
	"testing"
	"time"
)

func echoServer(t *testing.T, ln net.Listener) {
	t.Helper()
	var (
		mu   sync.Mutex
		open []net.Conn
	)
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range open {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("220 ready\r\n"))
			mu.Lock()
			open = append(open, c)
			mu.Unlock()
		}
	}()
}

func dialAndRead(t *testing.T, addr string) (net.Conn, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	return c, line
}

func TestOverTheLimitIsTurnedAway(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })

	ln := Listen(base, 2, "421 4.7.0 too many\r\n")
	echoServer(t, ln)
	addr := base.Addr().String()

	_, g1 := dialAndRead(t, addr)
	_, g2 := dialAndRead(t, addr)
	if g1 != "220 ready\r\n" || g2 != "220 ready\r\n" {
		t.Fatalf("connections under the limit were not served: %q, %q", g1, g2)
	}

	_, g3 := dialAndRead(t, addr)
	if g3 != "421 4.7.0 too many\r\n" {
		t.Fatalf("SECURITY: the connection over the limit got %q, want the 421 refusal", g3)
	}
}

func TestClosingAConnectionFreesItsSlot(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })

	ln := Listen(base, 1, "421 4.7.0 too many\r\n")
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("220 ready\r\n"))
			accepted <- c
		}
	}()
	addr := base.Addr().String()

	if _, g := dialAndRead(t, addr); g != "220 ready\r\n" {
		t.Fatalf("first connection got %q", g)
	}

	(<-accepted).Close()

	if _, g := dialAndRead(t, addr); g != "220 ready\r\n" {
		t.Fatalf("the slot was not released: the next connection got %q", g)
	}
	(<-accepted).Close()
}

func TestDoubleCloseReleasesOnce(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })

	ln := Listen(base, 1, "")
	closed := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
		c.Close()
		close(closed)
	}()

	c, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the accept goroutine never ran")
	}

	slots := ln.(*listener).slots

	select {
	case slots <- struct{}{}:
	default:
		t.Fatal("the slot was never released")
	}
	select {
	case slots <- struct{}{}:
		t.Fatal("a double close released the slot twice: the limit has drifted")
	default:
	}
}

func TestZeroMaxIsUnlimited(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	if ln := Listen(base, 0, "421\r\n"); ln != base {
		t.Fatal("a max of zero should return the listener unchanged")
	}
}
