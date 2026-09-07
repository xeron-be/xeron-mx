package netlimit

import (
	"net"
	"sync"
	"time"
)

const greetTimeout = 5 * time.Second

func Listen(ln net.Listener, max int, greeting string) net.Listener {
	if max <= 0 {
		return ln
	}
	return &listener{
		Listener: ln,
		slots:    make(chan struct{}, max),
		greeting: greeting,
	}
}

type listener struct {
	net.Listener
	slots    chan struct{}
	greeting string
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &conn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			go l.turnAway(c)
		}
	}
}

func (l *listener) turnAway(c net.Conn) {
	defer c.Close()
	if l.greeting == "" {
		return
	}
	c.SetWriteDeadline(time.Now().Add(greetTimeout))
	c.Write([]byte(l.greeting))
}

type conn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
