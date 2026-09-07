package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var configMapBlock = regexp.MustCompile(`(?s)kind: ConfigMap.*?\n  xeronmx\.yaml: \|\n(.*?)(?:\n---|\z)`)

func TestHelmChartRendersLoadableConfig(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed; the CI chart job installs it")
	}

	chart, err := filepath.Abs(filepath.Join("..", "..", "deploy", "helm", "xeronmx"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(chart, "Chart.yaml")); err != nil {
		t.Skipf("chart not found at %s", chart)
	}

	t.Setenv("XERONMX_CLUSTER_SECRET", "a shared secret of sixteen plus")

	cases := []struct {
		name string
		args []string
	}{
		{"defaults", nil},
		{"cluster", []string{
			"--set", "replicaCount=3",
			"--set", "cluster.enabled=true",
			"--set", "cluster.syncConfig=true",
		}},
		{"oidc", []string{
			"--set", "oidc.enabled=true",
			"--set", "oidc.issuer=https://id.example.com",
			"--set", "oidc.clientID=xeronmx",
			"--set", "ui.baseURL=https://mx2.example.com",
		}},
		{"submission and tls", []string{
			"--set", "submission.enabled=true",
			"--set", "submission.relayHost=smtp.example.com",
			"--set", "smtp.tlsSecretName=mx2-tls",
			"--set", "ui.ingress.enabled=true",
			"--set", "ui.ingress.host=mx2.example.com",
		}},
		{"acme, spam and alerts", []string{
			"--set", "acme.enabled=true",
			"--set", "acme.termsAgreed=true",
			"--set", "acme.domains={mx2.example.com}",
			"--set", "acme.email=ops@example.com",
			"--set", "spam.enabled=true",
			"--set", "spam.url=http://rspamd:11333",
			"--set", "alerts.enabled=true",
			"--set", "alerts.webhookURL=https://hooks.example.com/x",
		}},
		{"extraConfig deep merge", []string{
			"--set", "extraConfig.smtp.max_recipients=50",
			"--set", "extraConfig.queue.retry_max=4h",
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"template", "t", chart}, tc.args...)
			out, err := exec.Command(helm, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}

			m := configMapBlock.FindSubmatch(out)
			if m == nil {
				t.Fatal("the rendered manifest has no ConfigMap carrying xeronmx.yaml")
			}

			var lines []string
			for _, l := range strings.Split(string(m[1]), "\n") {
				lines = append(lines, strings.TrimPrefix(l, "    "))
			}
			rendered := strings.Join(lines, "\n")

			for name, value := range podEnv(string(out)) {
				t.Setenv(name, value)
			}

			path := filepath.Join(t.TempDir(), "xeronmx.yaml")
			if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err != nil {
				t.Fatalf("the chart produced a configuration the daemon rejects: %v\n\n%s", err, rendered)
			}
		})
	}
}

func podEnv(manifest string) map[string]string {
	const podName = "t-xeronmx-0"
	out := map[string]string{}

	for _, m := range envEntry.FindAllStringSubmatch(manifest, -1) {
		name, value := m[1], strings.Trim(m[2], `"`)
		out[name] = strings.ReplaceAll(value, "$(POD_NAME)", podName)
	}
	return out
}

var envEntry = regexp.MustCompile(`- name: (XERONMX_[A-Z_]+)
\s+value: (.+)`)

func TestHelmChartRendersIntegersAsIntegers(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed")
	}
	chart, err := filepath.Abs(filepath.Join("..", "..", "deploy", "helm", "xeronmx"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(chart, "Chart.yaml")); err != nil {
		t.Skipf("chart not found at %s", chart)
	}

	out, err := exec.Command(helm, "template", "t", chart).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "e+0") {
		t.Fatal("a value rendered in scientific notation; wrap it in int64 in the template")
	}
}
