package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/milad-raeisi/LANChat/internal/discoverysrv"
)

// envPrefix prefixes every environment variable, e.g.
// LANCHAT_DISCOVERY_LISTEN for the "listen" setting.
const envPrefix = "LANCHAT_DISCOVERY_"

// envConfig names the environment variable holding the config file path.
const envConfig = envPrefix + "CONFIG"

// setting is one configuration key. The same key is used in the TOML file,
// as a flag (underscores become dashes) and as an environment variable
// (upper case with envPrefix).
type setting struct {
	key    string
	usage  string
	isBool bool
	isPath bool
	apply  func(c *discoverysrv.Config, v string) error
	show   func(c discoverysrv.Config) string
}

func (s setting) flagName() string { return strings.ReplaceAll(s.key, "_", "-") }
func (s setting) envName() string  { return envPrefix + strings.ToUpper(s.key) }

func strSetting(key, usage string, isPath bool, f func(*discoverysrv.Config) *string) setting {
	return setting{
		key: key, usage: usage, isPath: isPath,
		apply: func(c *discoverysrv.Config, v string) error { *f(c) = strings.TrimSpace(v); return nil },
		show:  func(c discoverysrv.Config) string { return *f(&c) },
	}
}

func boolSetting(key, usage string, f func(*discoverysrv.Config) *bool) setting {
	return setting{
		key: key, usage: usage, isBool: true,
		apply: func(c *discoverysrv.Config, v string) error {
			b, err := strconv.ParseBool(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%q is not true or false", v)
			}
			*f(c) = b
			return nil
		},
		show: func(c discoverysrv.Config) string {
			if *f(&c) {
				return "true"
			}
			return ""
		},
	}
}

func intSetting(key, usage string, f func(*discoverysrv.Config) *int) setting {
	return setting{
		key: key, usage: usage,
		apply: func(c *discoverysrv.Config, v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%q is not an integer", v)
			}
			*f(c) = n
			return nil
		},
		show: func(c discoverysrv.Config) string { return strconv.Itoa(*f(&c)) },
	}
}

func floatSetting(key, usage string, f func(*discoverysrv.Config) *float64) setting {
	return setting{
		key: key, usage: usage,
		apply: func(c *discoverysrv.Config, v string) error {
			n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				return fmt.Errorf("%q is not a number", v)
			}
			*f(c) = n
			return nil
		},
		show: func(c discoverysrv.Config) string { return strconv.FormatFloat(*f(&c), 'g', -1, 64) },
	}
}

// durSetting accepts Go durations ("90s", "2m") or a plain number of seconds.
func durSetting(key, usage string, f func(*discoverysrv.Config) *time.Duration) setting {
	return setting{
		key: key, usage: usage,
		apply: func(c *discoverysrv.Config, v string) error {
			v = strings.TrimSpace(v)
			if n, err := strconv.Atoi(v); err == nil {
				*f(c) = time.Duration(n) * time.Second
				return nil
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("%q is not a duration such as \"90s\" or \"2m\"", v)
			}
			*f(c) = d
			return nil
		},
		show: func(c discoverysrv.Config) string { return f(&c).String() },
	}
}

// listSetting accepts a comma-separated list (a TOML array in the file).
func listSetting(key, usage string, f func(*discoverysrv.Config) *[]string) setting {
	return setting{
		key: key, usage: usage,
		apply: func(c *discoverysrv.Config, v string) error {
			var out []string
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}
			*f(c) = out
			return nil
		},
		show: func(c discoverysrv.Config) string { return strings.Join(*f(&c), ",") },
	}
}

var settings = []setting{
	strSetting("listen", "TCP address to listen on", false, func(c *discoverysrv.Config) *string { return &c.Listen }),
	strSetting("identity_file", "server identity key, created on first use (ignored when tls_cert_file is set)", true, func(c *discoverysrv.Config) *string { return &c.IdentityFile }),
	strSetting("tls_cert_file", "PEM certificate to serve instead of the identity (e.g. issued by an internal CA)", true, func(c *discoverysrv.Config) *string { return &c.TLSCertFile }),
	strSetting("tls_key_file", "PEM private key for tls_cert_file", true, func(c *discoverysrv.Config) *string { return &c.TLSKeyFile }),
	strSetting("authorized_peers_file", "file listing authorized LANChat peer IDs, one per line (reloaded on change)", true, func(c *discoverysrv.Config) *string { return &c.AuthorizedPeersFile }),
	boolSetting("allow_any", "accept ANY LANChat identity instead of an authorized peers file", func(c *discoverysrv.Config) *bool { return &c.AllowAny }),
	listSetting("allowed_cidrs", "comma-separated source prefixes allowed to use the API (empty = any)", func(c *discoverysrv.Config) *[]string { return &c.AllowedCIDRs }),
	durSetting("presence_ttl", "how long an announcement stays valid without a refresh", func(c *discoverysrv.Config) *time.Duration { return &c.PresenceTTL }),
	intSetting("max_peers", "maximum number of registered peers", func(c *discoverysrv.Config) *int { return &c.MaxPeers }),
	floatSetting("rate_limit", "sustained requests per second allowed per source address", func(c *discoverysrv.Config) *float64 { return &c.RateLimit }),
	intSetting("rate_burst", "request burst allowed per source address", func(c *discoverysrv.Config) *int { return &c.RateBurst }),
	strSetting("log_level", "log level: debug, info, warn or error", false, func(c *discoverysrv.Config) *string { return &c.LogLevel }),
	strSetting("log_file", "write logs to this size-rotated file instead of stderr", true, func(c *discoverysrv.Config) *string { return &c.LogFile }),
}

// argNames are the argument placeholders shown in flag help.
var argNames = map[string]string{
	"listen": "host:port", "identity_file": "path", "tls_cert_file": "path", "tls_key_file": "path",
	"authorized_peers_file": "path", "allowed_cidrs": "cidr,...", "presence_ttl": "duration",
	"max_peers": "n", "rate_limit": "per-second", "rate_burst": "n", "log_level": "level", "log_file": "path",
}

func findSetting(key string) (setting, bool) {
	for _, s := range settings {
		if s.key == key {
			return s, true
		}
	}
	return setting{}, false
}

// defaultConfig returns the built-in defaults.
func defaultConfig() discoverysrv.Config {
	c := discoverysrv.Config{IdentityFile: defaultIdentityFile()}
	return c.WithDefaults()
}

func defaultIdentityFile() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "lanchat-discovery", "identity.key")
	}
	return "lanchat-discovery-identity.key"
}

// flagValue records a flag for later application, after the config file
// and environment, so that flags take precedence.
type flagValue struct {
	s     setting
	value string
	set   bool
}

func (f *flagValue) String() string { return f.value }

func (f *flagValue) Set(v string) error {
	if err := f.s.apply(&discoverysrv.Config{}, v); err != nil {
		return err
	}
	f.value, f.set = v, true
	return nil
}

func (f *flagValue) IsBoolFlag() bool { return f.s.isBool }

// configFlags registers --config and the flags for keys (all settings
// when keys is nil) on fs.
type configFlags struct {
	config string
	values []*flagValue
}

func registerConfigFlags(fs *flag.FlagSet, keys []string) *configFlags {
	cf := &configFlags{}
	fs.StringVar(&cf.config, "config", "", "TOML configuration file (env "+envConfig+")")
	def := defaultConfig()
	for _, s := range settings {
		if keys != nil && !contains(keys, s.key) {
			continue
		}
		fv := &flagValue{s: s, value: s.show(def)}
		cf.values = append(cf.values, fv)
		usage := fmt.Sprintf("%s (env %s)", s.usage, s.envName())
		if arg := argNames[s.key]; arg != "" {
			// flag.PrintDefaults shows the back-quoted word as the argument name.
			usage = fmt.Sprintf("%s (env %s=`%s`)", s.usage, s.envName(), arg)
		}
		fs.Var(fv, s.flagName(), usage)
	}
	return cf
}

// resolve builds the configuration: defaults, then the config file, then
// environment variables, then flags.
func (cf *configFlags) resolve(lookupEnv func(string) (string, bool)) (discoverysrv.Config, error) {
	cfg := defaultConfig()
	path := cf.config
	if path == "" {
		if v, ok := lookupEnv(envConfig); ok {
			path = strings.TrimSpace(v)
		}
	}
	if path != "" {
		if err := applyFile(&cfg, path); err != nil {
			return cfg, err
		}
	}
	for _, s := range settings {
		v, ok := lookupEnv(s.envName())
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		if err := s.apply(&cfg, v); err != nil {
			return cfg, fmt.Errorf("environment variable %s: %v", s.envName(), err)
		}
	}
	for _, fv := range cf.values {
		if fv.set {
			if err := fv.s.apply(&cfg, fv.value); err != nil {
				return cfg, fmt.Errorf("flag -%s: %v", fv.s.flagName(), err)
			}
		}
	}
	return cfg, nil
}

// applyFile reads a flat TOML file whose keys are the setting names.
// Relative paths in the file are resolved against the file's directory.
func applyFile(cfg *discoverysrv.Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	var raw map[string]any
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return fmt.Errorf("config file %s: %w", path, err)
	}
	base := filepath.Dir(path)
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var errs []error
	for _, k := range keys {
		s, ok := findSetting(k)
		if !ok {
			errs = append(errs, fmt.Errorf("unknown key %q", k))
			continue
		}
		v, err := tomlString(raw[k])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", k, err))
			continue
		}
		if s.isPath && v != "" && !filepath.IsAbs(v) {
			v = filepath.Join(base, v)
		}
		if err := s.apply(cfg, v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", k, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("config file %s: %w", path, errors.Join(errs...))
	}
	return nil
}

func tomlString(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), nil
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok || strings.Contains(s, ",") {
				return "", errors.New("expected an array of strings")
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ","), nil
	default:
		return "", fmt.Errorf("unsupported value of type %T", v)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
