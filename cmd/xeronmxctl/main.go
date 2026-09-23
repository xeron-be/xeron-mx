package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/xeron-be/xeron-mx/internal/version"
)

const usage = `xeronmxctl: command line client for XeronMX

Usage:
  xeronmxctl [flags] <command> [arguments]

Commands:
  login       Save the server URL and API token for later runs
  status      Overall state: primaries, queue depth, certificate
  domains     list | add | rm | test | recipients
  queue       list | show | retry | rm | release
  events      Recent timeline entries
  filters     list
  webhooks    list | test | deliveries
  tokens      list | rm
  cluster     The fleet as this node sees it
  config      export | import
  drain       Refuse new mail and empty the queue (--wait, --status, --cancel)
  version     Client and server versions

Flags:
  --url string     Base URL of the instance (env XERONMX_URL)
  --token string   API token (env XERONMX_TOKEN)
  --insecure       Skip TLS verification; for an interim self-signed certificate
  --json           Print raw JSON instead of a table

Run "xeronmxctl <command> --help" for the flags a command takes.

The token is read from --token, then XERONMX_TOKEN, then the file written by
"xeronmxctl login". Prefer the environment variable in CI: a flag ends up in the
process list, and the file ends up on disk.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "xeronmxctl:", err)

		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == 401 {
			fmt.Fprintln(os.Stderr,
				"  the token was refused (it may have expired, been revoked, "+
					"or belong to an account that no longer exists")
		}
		os.Exit(1)
	}
}

func run() error {
	var flags Settings
	fs := flag.NewFlagSet("xeronmxctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.StringVar(&flags.URL, "url", "", "base URL of the instance")
	fs.StringVar(&flags.Token, "token", "", "API token")
	fs.BoolVar(&flags.Insecure, "insecure", false, "skip TLS verification")
	fs.BoolVar(&jsonOut, "json", false, "print raw JSON")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	args := fs.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	command, rest := args[0], args[1:]

	switch command {
	case "login":
		return cmdLogin(rest, flags)
	case "version":
		return cmdVersion(ctx, rest, flags)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}

	settings, err := LoadSettings(flags)
	if err != nil {
		return err
	}
	client, err := NewClient(settings)
	if err != nil {
		return err
	}

	switch command {
	case "status":
		return cmdStatus(ctx, client)
	case "domains":
		return cmdDomains(ctx, client, rest)
	case "queue":
		return cmdQueue(ctx, client, rest)
	case "events":
		return cmdEvents(ctx, client, rest)
	case "filters":
		return cmdFilters(ctx, client, rest)
	case "webhooks":
		return cmdWebhooks(ctx, client, rest)
	case "tokens":
		return cmdTokens(ctx, client, rest)
	case "cluster":
		return cmdCluster(ctx, client)
	case "config":
		return cmdConfig(ctx, client, rest)
	case "drain":
		return cmdDrain(ctx, client, rest)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", command)
	}
}

func cmdLogin(args []string, flags Settings) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	url := fs.String("url", flags.URL, "base URL of the instance")
	token := fs.String("token", flags.Token, "API token, created in the UI under Settings")
	insecure := fs.Bool("insecure", flags.Insecure, "skip TLS verification")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *token == "" {
		return errors.New("login needs --url and --token")
	}

	settings := Settings{URL: *url, Token: *token, Insecure: *insecure}
	client, err := NewClient(settings)
	if err != nil {
		return err
	}

	var me struct {
		Email    string `json:"email"`
		Role     string `json:"role"`
		ViaToken *struct {
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"via_token"`
	}
	if err := client.get(context.Background(), "/api/v1/auth/me", &me); err != nil {
		return fmt.Errorf("the server did not accept that token: %w", err)
	}

	path, err := SaveSettings(settings)
	if err != nil {
		return err
	}

	name := "unnamed"
	role := me.Role
	if me.ViaToken != nil {
		name, role = me.ViaToken.Name, me.ViaToken.Role
	}
	note("Signed in to %s as %s (%s access) using token %q.", settings.URL, me.Email, role, name)
	note("Settings written to %s", path)
	if settings.Insecure {
		warn("TLS verification is off for this instance; remove `insecure: true` from %s once a real certificate is in place.", path)
	}
	return nil
}

func cmdVersion(ctx context.Context, args []string, flags Settings) error {
	note("xeronmxctl %s", version.String())

	settings, err := LoadSettings(flags)
	if err != nil || settings.URL == "" {
		return nil
	}
	client, err := NewClient(settings)
	if err != nil {
		return nil
	}

	var setup struct {
		Version string `json:"version"`
	}
	if err := client.get(ctx, "/api/v1/setup", &setup); err != nil {
		warn("could not reach %s: %v", settings.URL, err)
		return nil
	}
	note("server      %s (%s)", setup.Version, settings.URL)
	return nil
}
