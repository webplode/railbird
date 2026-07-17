package config

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Mode string

const (
	ModeIngress Mode = "ingress"
	ModeEgress  Mode = "egress"
)

// Config is the fully-validated runtime configuration. Callers should not
// re-validate; Load returns an error for any invalid input.
type Config struct {
	Forwards      string
	Mode          Mode
	ManagementURL string
	SetupKey      string
	DeviceName    string
	DNSLabels     []string
	StateDir      string
	LogLevel      string
	MTU           int
	DNSOverTCP    bool
	DNSResolver   string
}

// option declares one CLI flag and the env-var aliases that may override its
// default. The first non-empty alias is used as the flag's default value, so
// an explicit `--flag` on the command line still takes precedence.
type option struct {
	flag     string
	envs     []string
	def      string
	help     string
	required bool
	target   *string
}

// Load parses args (typically os.Args[1:]) using a fresh FlagSet so it is
// safe to call from tests. getenv is injected (typically os.Getenv) so tests
// can supply a stub.
func Load(args []string, getenv func(string) string) (Config, error) {
	var (
		cfg          Config
		modeStr      string
		dnsLabelsStr string
		mtuStr       string
	)

	opts := []option{
		{flag: "forwards", envs: []string{"FORWARDS", "TARGET_ADDR"}, def: "", required: true,
			help: "comma-separated forwards (host:port or lport=host:port)", target: &cfg.Forwards},
		{flag: "mode", envs: []string{"MODE"}, def: string(ModeIngress),
			help: "ingress | egress", target: &modeStr},
		{flag: "mgmt", envs: []string{"NB_MANAGEMENT_URL"}, def: "", required: true,
			help: "NetBird management URL", target: &cfg.ManagementURL},
		{flag: "setup-key", envs: []string{"NB_SETUP_KEY"}, def: "", required: true,
			help: "NetBird setup key", target: &cfg.SetupKey},
		{flag: "device-name", envs: []string{"NB_DEVICE_NAME"}, def: "railbird",
			help: "peer name in the mesh", target: &cfg.DeviceName},
		{flag: "dns-labels", envs: []string{"NB_DNS_LABELS"}, def: "",
			help: "comma-separated extra DNS labels", target: &dnsLabelsStr},
		{flag: "state", envs: []string{"NB_STATE_DIR"}, def: "/var/lib/netbird",
			help: "state directory", target: &cfg.StateDir},
		{flag: "log-level", envs: []string{"NB_LOG_LEVEL"}, def: "info",
			help: "NetBird log level", target: &cfg.LogLevel},
		{flag: "mtu", envs: []string{"NB_MTU"}, def: "0",
			help: "NetBird tunnel MTU in bytes (0 = NetBird default 1280; valid 576-8192)", target: &mtuStr},
	}

	dnsTCPStr := firstNonEmpty(getenv, []string{"NB_DNS_OVER_TCP"}, "")
	dnsResStr := firstNonEmpty(getenv, []string{"NB_DNS_RESOLVER"}, "10.32.0.2:53")

	fs := flag.NewFlagSet("railbird", flag.ContinueOnError)
	for _, o := range opts {
		fs.StringVar(o.target, o.flag, firstNonEmpty(getenv, o.envs, o.def), o.help)
	}
	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("parse flags: %w", err)
	}

	for _, o := range opts {
		if o.required && strings.TrimSpace(*o.target) == "" {
			return Config{}, fmt.Errorf("required: --%s (or env %s)", o.flag, strings.Join(o.envs, "/"))
		}
	}

	cfg.Mode = Mode(modeStr)
	if cfg.Mode != ModeIngress && cfg.Mode != ModeEgress {
		return Config{}, fmt.Errorf("invalid mode %q: must be %s or %s", modeStr, ModeIngress, ModeEgress)
	}

	cfg.DNSLabels = splitTrim(dnsLabelsStr, ",")

	if mtuStr != "" && mtuStr != "0" {
		mtu, err := strconv.Atoi(mtuStr)
		if err != nil {
			return Config{}, fmt.Errorf("invalid MTU %q: %w", mtuStr, err)
		}
		if mtu < 576 || mtu > 8192 {
			return Config{}, fmt.Errorf("MTU %d out of range (576-8192)", mtu)
		}
		cfg.MTU = mtu
	}

	cfg.DNSOverTCP = dnsOverTCPOn(dnsTCPStr)
	if cfg.DNSOverTCP {
		cfg.DNSResolver = strings.TrimSpace(dnsResStr)
		if cfg.DNSResolver == "" {
			cfg.DNSResolver = "10.32.0.2:53"
		}
		if _, _, err := net.SplitHostPort(cfg.DNSResolver); err != nil {
			cfg.DNSResolver = net.JoinHostPort(cfg.DNSResolver, "53")
		}
	}

	return cfg, nil
}

// firstNonEmpty returns the value of the first env var that is set and
// non-empty after trimming, falling back to def.
func firstNonEmpty(getenv func(string) string, envs []string, def string) string {
	for _, k := range envs {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
	}
	return def
}

// splitTrim splits s by sep, trims each element, and drops empties.
func dnsOverTCPOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitTrim(s, sep string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}

	return out
}
