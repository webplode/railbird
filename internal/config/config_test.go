package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func mapGetenv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func egressEnv() map[string]string {
	return map[string]string{
		"MODE":                  "egress",
		"FORWARDS":              "5432=127.0.0.1:5432",
		"NB_MANAGEMENT_URL":     "https://mgmt.example.com/path",
		"NB_SETUP_KEY":          "secret-setup-key",
		"RAILWAY_DEPLOYMENT_ID": "deployment-A",
	}
}

func persistentEnv(t *testing.T) map[string]string {
	t.Helper()
	volume := t.TempDir()
	return map[string]string{
		"MODE":                        "ingress",
		"FORWARDS":                    "5432=127.0.0.1:5432",
		"NB_MANAGEMENT_URL":           "https://mgmt.example.com",
		"NB_IDENTITY_MODE":            "persistent",
		"NB_EXPECTED_PEER_PUBLIC_KEY": publicKeyFixture(),
		"RAILWAY_SERVICE_ID":          "service-A",
		"RAILWAY_VOLUME_MOUNT_PATH":   volume,
	}
}

func bootstrapEnv(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"MODE":                      "ingress",
		"NB_MANAGEMENT_URL":         "https://mgmt.example.com",
		"NB_SETUP_KEY":              "secret-setup-key",
		"NB_IDENTITY_MODE":          "bootstrap",
		"RAILWAY_SERVICE_ID":        "service-A",
		"RAILWAY_VOLUME_MOUNT_PATH": t.TempDir(),
		"RAILWAY_RUN_UID":           "0",
	}
}

func publicKeyFixture() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func TestLoadDefaultsAndPrecedence(t *testing.T) {
	env := egressEnv()
	cfg, err := Load([]string{"--device-name=explicit", "--health-port=9090"}, mapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeEgress || cfg.IdentityMode != IdentityEphemeral || cfg.DeviceName != "explicit" || cfg.HealthPort != 9090 {
		t.Fatalf("unexpected precedence result: %+v", cfg)
	}
	if cfg.StateDir != "/var/lib/railbird/netbird" || cfg.LogLevel != "info" || cfg.MTU != 0 || cfg.ProbePolicy != ProbeRequired {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.StartupTimeout != 90*time.Second || cfg.DNSQueryTimeout != 5*time.Second || cfg.DialAttemptTimeout != 5*time.Second || cfg.DialTotalTimeout != 15*time.Second {
		t.Fatalf("unexpected timeout defaults: %+v", cfg)
	}
	if cfg.MaxConnections != 256 || cfg.IdleTimeout != 0 || cfg.TCPKeepalive != 30*time.Second || cfg.DrainTimeout != 45*time.Second || cfg.NetBirdStopTimeout != 5*time.Second {
		t.Fatalf("unexpected limit defaults: %+v", cfg)
	}
}

func TestFlagHelpAndParseErrorsDoNotExposeEnvironmentValues(t *testing.T) {
	env := egressEnv()
	env["FORWARDS"] = "5432=private-db.internal:5432"
	env["NB_STATIC_HOSTS"] = "private-db.internal=10.0.0.8"

	for _, args := range [][]string{
		{"--help"},
		{"--setup-key=cli-secret", "--unknown-flag"},
	} {
		var output bytes.Buffer
		_, err := load(args, mapGetenv(env), &output)
		if args[0] == "--help" && !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("load(%v) error = %v, want flag.ErrHelp", args, err)
		}
		if err == nil {
			t.Fatalf("load(%v) unexpectedly succeeded", args)
		}
		text := output.String() + err.Error()
		for _, forbidden := range []string{"secret-setup-key", "cli-secret", "private-db.internal", "10.0.0.8"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("load(%v) exposed %q in flag output/error: %s", args, forbidden, text)
			}
		}
	}
}

func TestLoadRequiresExplicitMode(t *testing.T) {
	for _, mode := range []string{"", " ", "sideways"} {
		t.Run(mode, func(t *testing.T) {
			env := egressEnv()
			env["MODE"] = mode
			_, err := Load(nil, mapGetenv(env))
			if err == nil || !strings.Contains(err.Error(), "MODE") {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestManagementURLValidationIsSecretSafe(t *testing.T) {
	for _, value := range []string{"http://mgmt.example.com", "relative", "://bad", "https://user:sentinel@host", "https://host?q=sentinel", "https://host#sentinel"} {
		t.Run(value, func(t *testing.T) {
			env := egressEnv()
			env["NB_MANAGEMENT_URL"] = value
			_, err := Load(nil, mapGetenv(env))
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), "user:") {
				t.Fatalf("secret leaked: %v", err)
			}
		})
	}
}

func TestServingForwardValidationAndAliasWarnings(t *testing.T) {
	t.Run("alias", func(t *testing.T) {
		env := egressEnv()
		delete(env, "FORWARDS")
		env["TARGET_ADDR"] = "1=127.0.0.1:65535"
		cfg, err := Load(nil, mapGetenv(env))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Forwards != env["TARGET_ADDR"] || !contains(cfg.Warnings, WarningTargetAddrAlias) {
			t.Fatalf("alias behavior: %+v", cfg)
		}
	})
	t.Run("canonical wins", func(t *testing.T) {
		env := egressEnv()
		env["TARGET_ADDR"] = "2=127.0.0.1:2"
		cfg, err := Load(nil, mapGetenv(env))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Forwards != env["FORWARDS"] || !contains(cfg.Warnings, WarningTargetAddrIgnored) {
			t.Fatalf("canonical behavior: %+v", cfg)
		}
	})
	for name, forwards := range map[string]string{
		"missing": "", "bad listen": "0=127.0.0.1:1", "bad target": "1=127.0.0.1:65536", "duplicate": "1=127.0.0.1:1,1=127.0.0.1:2",
	} {
		t.Run(name, func(t *testing.T) {
			env := egressEnv()
			env["FORWARDS"] = forwards
			if _, err := Load(nil, mapGetenv(env)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	t.Run("health collision", func(t *testing.T) {
		env := egressEnv()
		env["FORWARDS"] = "05432=127.0.0.1:1"
		env["PORT"] = "5432"
		_, err := Load(nil, mapGetenv(env))
		if err == nil || !strings.Contains(err.Error(), "collides") {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestBootstrapServingInputsAreOpaqueAndInactive(t *testing.T) {
	env := bootstrapEnv(t)
	env["FORWARDS"] = "sentinel-user:sentinel-password@not-a-forward"
	env["TARGET_ADDR"] = "also-malformed"
	env["PORT"] = "not-a-port"
	env["PROBE_POLICY"] = "not-a-policy"
	cfg, err := Load([]string{"--forwards=still-malformed"}, mapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Forwards != "" || cfg.HealthPort != 0 || cfg.ProbePolicy != "" {
		t.Fatalf("bootstrap serving inputs active: %+v", cfg)
	}
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "sentinel") || strings.Contains(warning, "TARGET_ADDR") {
			t.Fatalf("bootstrap leaked inactive input metadata: %q", warning)
		}
	}
}

func TestIdentityModeAndCredentials(t *testing.T) {
	t.Run("egress rejects non-ephemeral", func(t *testing.T) {
		env := egressEnv()
		env["NB_IDENTITY_MODE"] = "persistent"
		if _, err := Load(nil, mapGetenv(env)); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("ingress identity required", func(t *testing.T) {
		env := persistentEnv(t)
		delete(env, "NB_IDENTITY_MODE")
		if _, err := Load(nil, mapGetenv(env)); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("persistent forbids setup key", func(t *testing.T) {
		env := persistentEnv(t)
		env["NB_SETUP_KEY"] = "sentinel-secret"
		_, err := Load(nil, mapGetenv(env))
		if err == nil || strings.Contains(err.Error(), "sentinel-secret") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("persistent requires valid public key", func(t *testing.T) {
		env := persistentEnv(t)
		env["NB_EXPECTED_PEER_PUBLIC_KEY"] = "private-sentinel"
		_, err := Load(nil, mapGetenv(env))
		if err == nil || strings.Contains(err.Error(), "private-sentinel") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("public key rejected elsewhere", func(t *testing.T) {
		env := egressEnv()
		env["NB_EXPECTED_PEER_PUBLIC_KEY"] = publicKeyFixture()
		if _, err := Load(nil, mapGetenv(env)); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestDeviceNameDerivationAndValidation(t *testing.T) {
	env := egressEnv()
	env["RAILWAY_DEPLOYMENT_ID"] = "Deploy ID / With Spaces and a very very very very very very very long tail"
	one, err := Load(nil, mapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	two, err := Load(nil, mapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	if one.DeviceName != two.DeviceName || len(one.DeviceName) > 63 || !validDNSLabel(one.DeviceName) {
		t.Fatalf("bad derived name %q", one.DeviceName)
	}
	env["RAILWAY_DEPLOYMENT_ID"] = "different"
	three, err := Load(nil, mapGetenv(env))
	if err != nil || three.DeviceName == one.DeviceName {
		t.Fatalf("collision or err: %q %v", three.DeviceName, err)
	}
	delete(env, "RAILWAY_DEPLOYMENT_ID")
	if _, err := Load(nil, mapGetenv(env)); err == nil {
		t.Fatal("missing platform ID should fail")
	}
	env["NB_DEVICE_NAME"] = "explicit-name"
	if _, err := Load(nil, mapGetenv(env)); err != nil {
		t.Fatal(err)
	}
	env["NB_DEVICE_NAME"] = "Invalid_Name"
	if _, err := Load(nil, mapGetenv(env)); err == nil {
		t.Fatal("invalid explicit name should fail")
	}
}

func TestDNSLabelsLogLevelAndMTU(t *testing.T) {
	env := egressEnv()
	env["NB_DNS_LABELS"] = "one,two,one"
	env["NB_LOG_LEVEL"] = "warning"
	env["NB_MTU"] = "8192"
	cfg, err := Load(nil, mapGetenv(env))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.DNSLabels, []string{"one", "two"}) || cfg.LogLevel != "warn" || cfg.MTU != 8192 {
		t.Fatalf("unexpected values: %+v", cfg)
	}
	for key, value := range map[string]string{"NB_DNS_LABELS": "one,,two", "NB_LOG_LEVEL": "verbose", "NB_MTU": "575"} {
		t.Run(key, func(t *testing.T) {
			bad := egressEnv()
			bad[key] = value
			if _, err := Load(nil, mapGetenv(bad)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestDNSAndStaticHostValidation(t *testing.T) {
	env := egressEnv()
	env["FORWARDS"] = "5432=db.example.com:5432"
	if _, err := Load(nil, mapGetenv(env)); err == nil {
		t.Fatal("hostname without approved resolver should fail")
	}
	env["NB_DNS_OVER_TCP"] = "YES"
	cfg, err := Load(nil, mapGetenv(env))
	if err != nil || cfg.DNSResolver != "10.32.0.2:53" {
		t.Fatalf("default resolver: %+v %v", cfg, err)
	}
	env["NB_DNS_RESOLVER"] = "resolver.example.com:65535"
	cfg, err = Load(nil, mapGetenv(env))
	if err != nil || cfg.DNSResolver != env["NB_DNS_RESOLVER"] {
		t.Fatalf("explicit resolver: %+v %v", cfg, err)
	}
	for _, value := range []string{"maybe", "2", "truthy"} {
		bad := egressEnv()
		bad["NB_DNS_OVER_TCP"] = value
		if _, err := Load(nil, mapGetenv(bad)); err == nil {
			t.Fatalf("strict bool %q accepted", value)
		}
	}
	static := egressEnv()
	static["FORWARDS"] = "5432=DB.EXAMPLE.COM:5432"
	static["NB_STATIC_HOSTS"] = "db.example.com=192.0.2.1"
	cfg, err = Load(nil, mapGetenv(static))
	if err != nil || cfg.StaticHosts["db.example.com"] != "192.0.2.1" || !contains(cfg.Warnings, WarningStaticHosts) {
		t.Fatalf("static mapping: %+v %v", cfg, err)
	}
	for _, value := range []string{"bad", "host=not-ip", "host=192.0.2.1,HOST=192.0.2.2"} {
		bad := egressEnv()
		bad["NB_STATIC_HOSTS"] = value
		if _, err := Load(nil, mapGetenv(bad)); err == nil {
			t.Fatalf("bad mapping %q accepted", value)
		}
	}
	ingress := persistentEnv(t)
	ingress["NB_DNS_OVER_TCP"] = "true"
	if _, err := Load(nil, mapGetenv(ingress)); err == nil {
		t.Fatal("ingress DNS over TCP accepted")
	}
}

func TestDurationsLimitsAndOrdering(t *testing.T) {
	validBounds := map[string]string{
		"STARTUP_TIMEOUT": "240s", "DNS_QUERY_TIMEOUT": "100ms", "DIAL_ATTEMPT_TIMEOUT": "100ms", "DIAL_TOTAL_TIMEOUT": "60s",
		"MAX_CONNECTIONS": "4096", "IDLE_TIMEOUT": "24h", "TCP_KEEPALIVE": "10m", "DRAIN_TIMEOUT": "10m", "NB_STOP_TIMEOUT": "30s",
	}
	env := mergeEnv(egressEnv(), validBounds)
	if _, err := Load(nil, mapGetenv(env)); err != nil {
		t.Fatal(err)
	}
	invalid := map[string]string{
		"STARTUP_TIMEOUT": "4s", "DNS_QUERY_TIMEOUT": "31s", "DIAL_ATTEMPT_TIMEOUT": "99ms", "DIAL_TOTAL_TIMEOUT": "0s",
		"MAX_CONNECTIONS": "0", "IDLE_TIMEOUT": "500ms", "TCP_KEEPALIVE": "11m", "DRAIN_TIMEOUT": "0", "NB_STOP_TIMEOUT": "31s",
	}
	for key, value := range invalid {
		t.Run(key, func(t *testing.T) {
			bad := egressEnv()
			bad[key] = value
			if _, err := Load(nil, mapGetenv(bad)); err == nil {
				t.Fatalf("%s=%s accepted", key, value)
			}
		})
	}
	for name, overrides := range map[string]map[string]string{
		"dns over total":     {"DNS_QUERY_TIMEOUT": "16s", "DIAL_TOTAL_TIMEOUT": "15s"},
		"attempt over total": {"DIAL_ATTEMPT_TIMEOUT": "16s", "DIAL_TOTAL_TIMEOUT": "15s"},
		"total over startup": {"STARTUP_TIMEOUT": "10s", "DIAL_TOTAL_TIMEOUT": "15s"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(nil, mapGetenv(mergeEnv(egressEnv(), overrides))); err == nil {
				t.Fatal("ordering violation accepted")
			}
		})
	}
}

func TestStateLayoutAndPlatformInputs(t *testing.T) {
	t.Run("ingress derives direct child", func(t *testing.T) {
		env := persistentEnv(t)
		cfg, err := Load(nil, mapGetenv(env))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.StateDir != filepath.Join(env["RAILWAY_VOLUME_MOUNT_PATH"], "netbird") {
			t.Fatalf("state=%q", cfg.StateDir)
		}
		env["NB_STATE_DIR"] = filepath.Join(env["RAILWAY_VOLUME_MOUNT_PATH"], "other")
		if _, err := Load(nil, mapGetenv(env)); err == nil {
			t.Fatal("other child accepted")
		}
	})
	t.Run("symlink rejected", func(t *testing.T) {
		root := t.TempDir()
		target := t.TempDir()
		link := filepath.Join(root, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		env := egressEnv()
		env["NB_STATE_DIR"] = link
		if _, err := Load(nil, mapGetenv(env)); err == nil {
			t.Fatal("symlink path accepted")
		}
	})
	t.Run("run uid profile", func(t *testing.T) {
		env := bootstrapEnv(t)
		env["RAILWAY_RUN_UID"] = "65532"
		if _, err := Load(nil, mapGetenv(env)); err == nil {
			t.Fatal("bootstrap non-root launcher control accepted")
		}
		serving := egressEnv()
		serving["RAILWAY_RUN_UID"] = "0"
		if _, err := Load(nil, mapGetenv(serving)); err == nil {
			t.Fatal("serving root control accepted")
		}
	})
}

func TestProbePolicy(t *testing.T) {
	env := egressEnv()
	env["PROBE_POLICY"] = "listener-only"
	cfg, err := Load(nil, mapGetenv(env))
	if err != nil || cfg.ProbePolicy != ProbeListenerOnly || !contains(cfg.Warnings, WarningListenerOnly) {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	env["PROBE_POLICY"] = "unknown"
	if _, err := Load(nil, mapGetenv(env)); err == nil {
		t.Fatal("unknown policy accepted")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func mergeEnv(a, b map[string]string) map[string]string {
	result := make(map[string]string, len(a)+len(b))
	for key, value := range a {
		result[key] = value
	}
	for key, value := range b {
		result[key] = value
	}
	return result
}
