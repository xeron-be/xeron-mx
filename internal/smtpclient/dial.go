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
		context.AfterFunc(ctx, func() { conn.Close() })
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
		if mode == TLSOpportunistic {
			tlsConfig.InsecureSkipVerify = true
		}
		client, err = startTLS(conn, tlsConfig, helloName)
		if err == nil {
			return client, nil
		}
		if mode == TLSRequired || ctx.Err() != nil {
			return nil, stageError(ctx, "STARTTLS", err)
		}

		conn, err = dial(false)
		if err != nil {
			return nil, err
		}
		client = smtp.NewClient(conn)
	default:
		client = smtp.NewClient(conn)
	}

	if err := client.Hello(helloName); err != nil {
		client.Close()
		return nil, stageError(ctx, "EHLO", err)
	}
	return client, nil
}

func startTLS(conn net.Conn, tlsConfig *tls.Config, helloName string) (*smtp.Client, error) {
	client, err := smtp.NewClientStartTLS(conn, tlsConfig)
	if err != nil {
		return nil, err
	}
	if err := client.Hello(helloName); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func stageError(ctx context.Context, stage string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%s: %w", stage, ctxErr)
	}
	return fmt.Errorf("%s: %w", stage, err)
}

func ValidTLSMode(mode string) bool {
	switch mode {
	case TLSNone, TLSOpportunistic, TLSRequired, TLSImplicit:
		return true
	}
	return false
}

func HelloName(d *store.Domain) string { return "xeronmx." + d.Name }
