package smtpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"

	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	TLSNone = "none"

	TLSOpportunistic = "opportunistic"

	TLSRequired = "starttls"

	TLSImplicit = "tls"
)

func Dial(ctx context.Context, d *store.Domain, helloName string) (*smtp.Client, error) {
	addr := net.JoinHostPort(d.PrimaryHost, strconv.Itoa(d.PrimaryPort))
	netDialer := &net.Dialer{}

	tlsConfig := &tls.Config{
		ServerName: d.PrimaryHost,
		MinVersion: tls.VersionTLS12,
	}

	dial := func(implicitTLS bool) (net.Conn, error) {
		var (
			conn net.Conn
			err  error
		)
		if implicitTLS {
			conn, err = (&tls.Dialer{NetDialer: netDialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
		} else {
			conn, err = netDialer.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, fmt.Errorf("connect %s: %w", addr, err)
		}

		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		}
		return conn, nil
	}

	mode := d.PrimaryTLS
	if mode == "" {
		mode = TLSOpportunistic
	}

	conn, err := dial(mode == TLSImplicit)
	if err != nil {
		return nil, err
	}

	var client *smtp.Client
	switch mode {
	case TLSRequired, TLSOpportunistic:

		client, err = smtp.NewClientStartTLS(conn, tlsConfig)
		if err != nil {

			if mode == TLSRequired {
				return nil, fmt.Errorf("STARTTLS: %w", err)
			}

			conn, err = dial(false)
			if err != nil {
				return nil, err
			}
			client = smtp.NewClient(conn)
		}
	default:
		client = smtp.NewClient(conn)
	}

	if err := client.Hello(helloName); err != nil {
		client.Close()
		return nil, fmt.Errorf("EHLO: %w", err)
	}
	return client, nil
}

func ValidTLSMode(mode string) bool {
	switch mode {
	case TLSNone, TLSOpportunistic, TLSRequired, TLSImplicit:
		return true
	}
	return false
}

func HelloName(d *store.Domain) string { return "xeronmx." + d.Name }
