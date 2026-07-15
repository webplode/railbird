package config

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	forwardspec "github.com/jratienza65/railbird/internal/forward/spec"
)

type Mode string

const (
	ModeIngress Mode = "ingress"
	ModeEgress  Mode = "egress"
)

type IdentityMode string

const (
	IdentityEphemeral  IdentityMode = "ephemeral"
	IdentityBootstrap  IdentityMode = "bootstrap"
	IdentityPersistent IdentityMode = "persistent"
)

type ProbePolicy string

const (
	ProbeRequired     ProbePolicy = "required"
	ProbeListenerOnly ProbePolicy = "listener-only"
)

const (
	WarningTargetAddrAlias   = "TARGET_ADDR is deprecated; use FORWARDS"
	WarningTargetAddrIgnored = "TARGET_ADDR is ignored because FORWARDS is set"
	WarningStaticHosts       = "NB_STATIC_HOSTS overrides DNS and may retain stale addresses"
	WarningListenerOnly      = "listener-only readiness does not verify target reachability"
)

// Config is the fully validated runtime configuration. Bootstrap configurations
// intentionally leave serving-only Forwards, HealthPort, and ProbePolicy inert.
type Config struct {
	Forwards               string
	Mode                   Mode
	ManagementURL          string
	SetupKey               string
	DeviceName             string
	DNSLabels              []string
	StateDir               string
	LogLevel               string
	MTU                    int
	DNSOverTCP             bool
	DNSResolver            string
	StaticHosts            map[string]string
	HealthPort             int
	ProbePolicy            ProbePolicy
	StartupTimeout         time.Duration
	DNSQueryTimeout        time.Duration
	DialAttemptTimeout     time.Duration
	DialTotalTimeout       time.Duration
	MaxConnections         int
	IdleTimeout            time.Duration
	TCPKeepalive           time.Duration
	DrainTimeout           time.Duration
	NetBirdStopTimeout     time.Duration
	IdentityMode           IdentityMode
	ExpectedPeerPublicKey  string
	RailwayDeploymentID    string
	RailwayServiceID       string
	RailwayVolumeMountPath string
	RailwayRunUID          *int
	Warnings               []string
}

type rawConfig struct {
	forwards, mode, managementURL, setupKey, deviceName, dnsLabels string
	stateDir, logLevel, mtu, dnsOverTCP, dnsResolver, staticHosts  string
	healthPort, probePolicy, startupTimeout, dnsQueryTimeout       string
	dialAttemptTimeout, dialTotalTimeout, maxConnections           string
	idleTimeout, tcpKeepalive, drainTimeout, stopTimeout           string
	identityMode, expectedPeerPublicKey                            string
}

type stringOption struct {
	flagName string
	env      string
	def      string
	help     string
	target   *string
}

// Load parses args using a fresh FlagSet. General precedence is CLI, canonical
// environment variable, then default. TARGET_ADDR is the sole legacy alias.
func Load(args []string, getenv func(string) string) (Config, error) {
	return load(args, getenv, os.Stderr)
}

func load(args []string, getenv func(string) string, flagOutput io.Writer) (Config, error) {
	raw := rawConfig{}
	options := []stringOption{
		{"forwards", "FORWARDS", "", "comma-separated forwards", &raw.forwards},
		{"mode", "MODE", "", "egress | ingress", &raw.mode},
		{"mgmt", "NB_MANAGEMENT_URL", "", "NetBird management URL", &raw.managementURL},
		{"setup-key", "NB_SETUP_KEY", "", "NetBird setup key", &raw.setupKey},
		{"device-name", "NB_DEVICE_NAME", "", "peer name", &raw.deviceName},
		{"dns-labels", "NB_DNS_LABELS", "", "comma-separated DNS labels", &raw.dnsLabels},
		{"state", "NB_STATE_DIR", "", "state directory", &raw.stateDir},
		{"log-level", "NB_LOG_LEVEL", "info", "log level", &raw.logLevel},
		{"mtu", "NB_MTU", "0", "tunnel MTU", &raw.mtu},
		{"dns-over-tcp", "NB_DNS_OVER_TCP", "false", "DNS over TCP", &raw.dnsOverTCP},
		{"dns-resolver", "NB_DNS_RESOLVER", "", "DNS resolver", &raw.dnsResolver},
		{"static-hosts", "NB_STATIC_HOSTS", "", "static hostname mappings", &raw.staticHosts},
		{"health-port", "PORT", "8080", "health port", &raw.healthPort},
		{"probe-policy", "PROBE_POLICY", "required", "required | listener-only", &raw.probePolicy},
		{"startup-timeout", "STARTUP_TIMEOUT", "90s", "startup timeout", &raw.startupTimeout},
		{"dns-query-timeout", "DNS_QUERY_TIMEOUT", "5s", "DNS query timeout", &raw.dnsQueryTimeout},
		{"dial-attempt-timeout", "DIAL_ATTEMPT_TIMEOUT", "5s", "per-address dial timeout", &raw.dialAttemptTimeout},
		{"dial-total-timeout", "DIAL_TOTAL_TIMEOUT", "15s", "total dial timeout", &raw.dialTotalTimeout},
		{"max-connections", "MAX_CONNECTIONS", "256", "maximum active sessions", &raw.maxConnections},
		{"idle-timeout", "IDLE_TIMEOUT", "0", "idle timeout", &raw.idleTimeout},
		{"tcp-keepalive", "TCP_KEEPALIVE", "30s", "TCP keepalive", &raw.tcpKeepalive},
		{"drain-timeout", "DRAIN_TIMEOUT", "45s", "drain timeout", &raw.drainTimeout},
		{"nb-stop-timeout", "NB_STOP_TIMEOUT", "5s", "NetBird stop timeout", &raw.stopTimeout},
		{"identity-mode", "NB_IDENTITY_MODE", "", "identity mode", &raw.identityMode},
		{"expected-peer-public-key", "NB_EXPECTED_PEER_PUBLIC_KEY", "", "expected peer public key", &raw.expectedPeerPublicKey},
	}

	fs := flag.NewFlagSet("railbird", flag.ContinueOnError)
	fs.SetOutput(flagOutput)
	for _, option := range options {
		// Register only static defaults. Installing environment values as flag
		// defaults makes flag's help/error output disclose setup keys, targets,
		// and other deployment inventory.
		fs.StringVar(option.target, option.flagName, option.def, option.help)
	}
	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("parse command line: %w", err)
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments")
	}
	for _, option := range options {
		if !optionWasSet(fs, option.flagName) {
			*option.target = envOrDefault(getenv, option.env, option.def)
		}
	}

	cfg := Config{
		RailwayDeploymentID:    strings.TrimSpace(getenv("RAILWAY_DEPLOYMENT_ID")),
		RailwayServiceID:       strings.TrimSpace(getenv("RAILWAY_SERVICE_ID")),
		RailwayVolumeMountPath: strings.TrimSpace(getenv("RAILWAY_VOLUME_MOUNT_PATH")),
	}
	var err error
	if cfg.Mode, err = parseMode(raw.mode); err != nil {
		return Config{}, err
	}
	if cfg.IdentityMode, err = parseIdentityMode(cfg.Mode, raw.identityMode); err != nil {
		return Config{}, err
	}
	bootstrap := cfg.Mode == ModeIngress && cfg.IdentityMode == IdentityBootstrap

	if err := parseManagementURL(raw.managementURL); err != nil {
		return Config{}, err
	}
	cfg.ManagementURL = strings.TrimSpace(raw.managementURL)
	if err := validateCredentials(cfg.Mode, cfg.IdentityMode, raw.setupKey, raw.expectedPeerPublicKey); err != nil {
		return Config{}, err
	}
	cfg.SetupKey = strings.TrimSpace(raw.setupKey)
	cfg.ExpectedPeerPublicKey = strings.TrimSpace(raw.expectedPeerPublicKey)

	if cfg.DeviceName, err = deviceName(cfg.Mode, raw.deviceName, cfg.RailwayDeploymentID, cfg.RailwayServiceID); err != nil {
		return Config{}, err
	}
	if cfg.DNSLabels, err = parseDNSLabels(raw.dnsLabels); err != nil {
		return Config{}, err
	}
	if cfg.StateDir, err = stateDir(cfg.Mode, raw.stateDir, cfg.RailwayVolumeMountPath); err != nil {
		return Config{}, err
	}
	if cfg.LogLevel, err = parseLogLevel(raw.logLevel); err != nil {
		return Config{}, err
	}
	if cfg.MTU, err = parseIntRange("NB_MTU", raw.mtu, 0, 8192); err != nil || (cfg.MTU != 0 && cfg.MTU < 576) {
		if err == nil {
			err = fmt.Errorf("NB_MTU must be 0 or between 576 and 8192")
		}
		return Config{}, err
	}
	if cfg.DNSOverTCP, err = parseBool("NB_DNS_OVER_TCP", raw.dnsOverTCP); err != nil {
		return Config{}, err
	}
	resolverExplicit := optionWasSet(fs, "dns-resolver") || strings.TrimSpace(getenv("NB_DNS_RESOLVER")) != ""
	staticExplicit := optionWasSet(fs, "static-hosts") || strings.TrimSpace(getenv("NB_STATIC_HOSTS")) != ""
	if cfg.Mode == ModeIngress && (cfg.DNSOverTCP || resolverExplicit || staticExplicit) {
		return Config{}, fmt.Errorf("DNS over TCP, resolver, and static hosts are egress-only")
	}
	if !cfg.DNSOverTCP && resolverExplicit {
		return Config{}, fmt.Errorf("NB_DNS_RESOLVER requires NB_DNS_OVER_TCP")
	}
	if cfg.DNSOverTCP {
		resolver := strings.TrimSpace(raw.dnsResolver)
		if resolver == "" {
			resolver = "10.32.0.2:53"
		}
		if cfg.DNSResolver, err = parseAddress("NB_DNS_RESOLVER", resolver); err != nil {
			return Config{}, err
		}
	}
	if cfg.StaticHosts, err = parseStaticHosts(raw.staticHosts); err != nil {
		return Config{}, err
	}
	if len(cfg.StaticHosts) != 0 {
		cfg.Warnings = append(cfg.Warnings, WarningStaticHosts)
	}

	if cfg.StartupTimeout, err = parseDuration("STARTUP_TIMEOUT", raw.startupTimeout, 5*time.Second, 240*time.Second, false); err != nil {
		return Config{}, err
	}
	if cfg.DNSQueryTimeout, err = parseDuration("DNS_QUERY_TIMEOUT", raw.dnsQueryTimeout, 100*time.Millisecond, 30*time.Second, false); err != nil {
		return Config{}, err
	}
	if cfg.DialAttemptTimeout, err = parseDuration("DIAL_ATTEMPT_TIMEOUT", raw.dialAttemptTimeout, 100*time.Millisecond, 30*time.Second, false); err != nil {
		return Config{}, err
	}
	if cfg.DialTotalTimeout, err = parseDuration("DIAL_TOTAL_TIMEOUT", raw.dialTotalTimeout, time.Second, 60*time.Second, false); err != nil {
		return Config{}, err
	}
	if cfg.MaxConnections, err = parseIntRange("MAX_CONNECTIONS", raw.maxConnections, 1, 4096); err != nil {
		return Config{}, err
	}
	if cfg.IdleTimeout, err = parseDuration("IDLE_TIMEOUT", raw.idleTimeout, time.Second, 24*time.Hour, true); err != nil {
		return Config{}, err
	}
	if cfg.TCPKeepalive, err = parseDuration("TCP_KEEPALIVE", raw.tcpKeepalive, time.Second, 10*time.Minute, true); err != nil {
		return Config{}, err
	}
	if cfg.DrainTimeout, err = parseDuration("DRAIN_TIMEOUT", raw.drainTimeout, time.Second, 10*time.Minute, false); err != nil {
		return Config{}, err
	}
	if cfg.NetBirdStopTimeout, err = parseDuration("NB_STOP_TIMEOUT", raw.stopTimeout, time.Second, 30*time.Second, false); err != nil {
		return Config{}, err
	}
	if cfg.DNSQueryTimeout > cfg.DialTotalTimeout || cfg.DialAttemptTimeout > cfg.DialTotalTimeout || cfg.DialTotalTimeout > cfg.StartupTimeout {
		return Config{}, fmt.Errorf("timeouts must satisfy DNS_QUERY_TIMEOUT <= DIAL_TOTAL_TIMEOUT <= STARTUP_TIMEOUT and DIAL_ATTEMPT_TIMEOUT <= DIAL_TOTAL_TIMEOUT")
	}

	if err := parseRailwayRunUID(getenv("RAILWAY_RUN_UID"), bootstrap, &cfg); err != nil {
		return Config{}, err
	}
	if bootstrap {
		return cfg, nil
	}

	forwardsValue, warnings := servingForwards(raw.forwards, getenv("FORWARDS"), getenv("TARGET_ADDR"), optionWasSet(fs, "forwards"))
	cfg.Warnings = append(cfg.Warnings, warnings...)
	parsedForwards, err := forwardspec.Parse(forwardsValue)
	if err != nil {
		return Config{}, fmt.Errorf("invalid forwards: %w", err)
	}
	cfg.Forwards = forwardsValue
	if cfg.HealthPort, err = parseIntRange("PORT", raw.healthPort, 1, 65535); err != nil {
		return Config{}, err
	}
	for _, fwd := range parsedForwards {
		if fwd.ListenPort == strconv.Itoa(cfg.HealthPort) {
			return Config{}, fmt.Errorf("health port %d collides with a forward listener", cfg.HealthPort)
		}
	}
	if cfg.ProbePolicy, err = parseProbePolicy(raw.probePolicy); err != nil {
		return Config{}, err
	}
	if cfg.ProbePolicy == ProbeListenerOnly {
		cfg.Warnings = append(cfg.Warnings, WarningListenerOnly)
	}
	if cfg.Mode == ModeEgress {
		if err := validateEgressResolution(parsedForwards, cfg.DNSOverTCP, cfg.StaticHosts); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func envOrDefault(getenv func(string) string, key, def string) string {
	if value := strings.TrimSpace(getenv(key)); value != "" {
		return value
	}
	return def
}

func optionWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

func parseMode(value string) (Mode, error) {
	switch Mode(strings.TrimSpace(value)) {
	case ModeEgress:
		return ModeEgress, nil
	case ModeIngress:
		return ModeIngress, nil
	default:
		return "", fmt.Errorf("MODE is required and must be egress or ingress")
	}
}

func parseIdentityMode(mode Mode, value string) (IdentityMode, error) {
	v := IdentityMode(strings.TrimSpace(value))
	if mode == ModeEgress {
		if v == "" || v == IdentityEphemeral {
			return IdentityEphemeral, nil
		}
		return "", fmt.Errorf("egress NB_IDENTITY_MODE must be ephemeral")
	}
	if v == IdentityBootstrap || v == IdentityPersistent {
		return v, nil
	}
	return "", fmt.Errorf("ingress NB_IDENTITY_MODE is required and must be bootstrap or persistent")
}

func parseManagementURL(value string) error {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !u.IsAbs() {
		return fmt.Errorf("NB_MANAGEMENT_URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return nil
}

func validateCredentials(mode Mode, identity IdentityMode, setupKey, publicKey string) error {
	setupKey = strings.TrimSpace(setupKey)
	publicKey = strings.TrimSpace(publicKey)
	requiresSetup := mode == ModeEgress || identity == IdentityBootstrap
	if requiresSetup && setupKey == "" {
		return fmt.Errorf("NB_SETUP_KEY is required for the selected identity mode")
	}
	if !requiresSetup && setupKey != "" {
		return fmt.Errorf("NB_SETUP_KEY is forbidden for persistent ingress")
	}
	requiresPublic := identity == IdentityPersistent
	if requiresPublic && !validPublicKey(publicKey) {
		return fmt.Errorf("NB_EXPECTED_PEER_PUBLIC_KEY must be a valid public key for persistent ingress")
	}
	if !requiresPublic && publicKey != "" {
		return fmt.Errorf("NB_EXPECTED_PEER_PUBLIC_KEY is only valid for persistent ingress")
	}
	return nil
}

func validPublicKey(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func deviceName(mode Mode, explicit, deploymentID, serviceID string) (string, error) {
	if explicit = strings.TrimSpace(explicit); explicit != "" {
		if !validDNSLabel(explicit) {
			return "", fmt.Errorf("NB_DEVICE_NAME must be a lowercase DNS label of at most 63 characters")
		}
		return explicit, nil
	}
	platformID := deploymentID
	prefix := "railbird-egress"
	if mode == ModeIngress {
		platformID = serviceID
		prefix = "railbird-ingress"
	}
	if platformID == "" {
		return "", fmt.Errorf("NB_DEVICE_NAME is required when the mode-specific Railway ID is absent")
	}
	slug := dnsSlug(platformID)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(platformID)))[:8]
	maxSlug := 63 - len(prefix) - len(hash) - 2
	if len(slug) > maxSlug {
		slug = strings.Trim(slug[:maxSlug], "-")
	}
	if slug == "" {
		slug = "peer"
	}
	return prefix + "-" + slug + "-" + hash, nil
}

func dnsSlug(value string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(value) {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if valid {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash && b.Len() != 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func validDNSLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func validDNSName(name string) bool {
	if len(name) > 253 || name == "" {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

func parseDNSLabels(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	seen := map[string]struct{}{}
	var labels []string
	for _, raw := range strings.Split(value, ",") {
		label := strings.TrimSpace(raw)
		if !validDNSLabel(label) {
			return nil, fmt.Errorf("NB_DNS_LABELS contains an invalid or empty label")
		}
		if _, ok := seen[label]; !ok {
			seen[label] = struct{}{}
			labels = append(labels, label)
		}
	}
	return labels, nil
}

func stateDir(mode Mode, explicit, volumeRoot string) (string, error) {
	path := strings.TrimSpace(explicit)
	if mode == ModeEgress && path == "" {
		path = "/var/lib/railbird/netbird"
	}
	if mode == ModeIngress {
		if volumeRoot == "" || !filepath.IsAbs(volumeRoot) || filepath.Clean(volumeRoot) != volumeRoot || volumeRoot == "/" {
			return "", fmt.Errorf("RAILWAY_VOLUME_MOUNT_PATH must be a clean absolute dedicated volume path for ingress")
		}
		expected := filepath.Join(volumeRoot, "netbird")
		if path == "" {
			path = expected
		}
		if path != expected {
			return "", fmt.Errorf("ingress NB_STATE_DIR must be the volume root's direct netbird child")
		}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return "", fmt.Errorf("NB_STATE_DIR must be a clean absolute path")
	}
	if err := rejectExistingSymlinks(path); err != nil {
		return "", err
	}
	return path, nil
}

func rejectExistingSymlinks(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect NB_STATE_DIR: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("NB_STATE_DIR must not be a symlink")
	}
	return nil
}

func parseLogLevel(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "warning" {
		value = "warn"
	}
	switch value {
	case "panic", "fatal", "error", "warn", "info", "debug", "trace":
		return value, nil
	default:
		return "", fmt.Errorf("NB_LOG_LEVEL is invalid")
	}
}

func parseBool(name, value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "", "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be a strict boolean", name)
	}
}

func parseAddress(name, value string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || host == "" || !validHost(host) {
		return "", fmt.Errorf("%s must be a valid host:port", name)
	}
	if _, err := parseIntRange(name+" port", port, 1, 65535); err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	portNumber, _ := strconv.Atoi(port)
	return net.JoinHostPort(host, strconv.Itoa(portNumber)), nil
}

func validHost(host string) bool {
	if strings.Contains(host, "%") {
		before, _, ok := strings.Cut(host, "%")
		return ok && net.ParseIP(before) != nil
	}
	return net.ParseIP(host) != nil || validDNSName(strings.ToLower(strings.TrimSuffix(host, ".")))
}

func parseStaticHosts(value string) (map[string]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	result := map[string]string{}
	for _, raw := range strings.Split(value, ",") {
		host, ipText, ok := strings.Cut(strings.TrimSpace(raw), "=")
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		ipText = strings.TrimSpace(ipText)
		ip := net.ParseIP(ipText)
		if !ok || !validDNSName(host) || ip == nil {
			return nil, fmt.Errorf("NB_STATIC_HOSTS contains an invalid mapping")
		}
		if _, duplicate := result[host]; duplicate {
			return nil, fmt.Errorf("NB_STATIC_HOSTS contains a duplicate host")
		}
		result[host] = ip.String()
	}
	return result, nil
}

func parseIntRange(name, value string, min, max int) (int, error) {
	value = strings.TrimSpace(value)
	n, err := strconv.Atoi(value)
	if err != nil || !asciiDigits(value) || n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d", name, min, max)
	}
	return n, nil
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func parseDuration(name, value string, min, max time.Duration, zeroAllowed bool) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || (d == 0 && !zeroAllowed) || d < 0 || (d != 0 && d < min) || d > max {
		if zeroAllowed {
			return 0, fmt.Errorf("%s must be 0 or between %s and %s", name, min, max)
		}
		return 0, fmt.Errorf("%s must be between %s and %s", name, min, max)
	}
	return d, nil
}

func parseProbePolicy(value string) (ProbePolicy, error) {
	switch ProbePolicy(strings.TrimSpace(value)) {
	case ProbeRequired:
		return ProbeRequired, nil
	case ProbeListenerOnly:
		return ProbeListenerOnly, nil
	default:
		return "", fmt.Errorf("PROBE_POLICY must be required or listener-only")
	}
}

func servingForwards(flagValue, canonical, alias string, cliSet bool) (string, []string) {
	canonical = strings.TrimSpace(canonical)
	alias = strings.TrimSpace(alias)
	if cliSet {
		if alias != "" {
			return strings.TrimSpace(flagValue), []string{WarningTargetAddrIgnored}
		}
		return strings.TrimSpace(flagValue), nil
	}
	if canonical != "" {
		if alias != "" {
			return canonical, []string{WarningTargetAddrIgnored}
		}
		return canonical, nil
	}
	if alias != "" {
		return alias, []string{WarningTargetAddrAlias}
	}
	return "", nil
}

func validateEgressResolution(forwards []forwardspec.Forward, dnsOverTCP bool, staticHosts map[string]string) error {
	for _, fwd := range forwards {
		host, _, _ := net.SplitHostPort(fwd.Target)
		if net.ParseIP(host) != nil {
			continue
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if _, staticallyMapped := staticHosts[host]; !dnsOverTCP && !staticallyMapped {
			return fmt.Errorf("egress hostname targets require NB_DNS_OVER_TCP or an explicit NB_STATIC_HOSTS mapping")
		}
	}
	return nil
}

func parseRailwayRunUID(value string, bootstrap bool, cfg *Config) error {
	value = strings.TrimSpace(value)
	if bootstrap {
		if value != "0" {
			return fmt.Errorf("RAILWAY_RUN_UID must be 0 for ingress bootstrap")
		}
		uid := 0
		cfg.RailwayRunUID = &uid
		return nil
	}
	if value != "" {
		return fmt.Errorf("RAILWAY_RUN_UID must be unset for serving modes")
	}
	return nil
}
