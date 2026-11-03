// Package settings loads the host-side Lickren settings file.
package settings

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Values are the supported user overrides. Zero means "not set".
type Values struct {
	DNSUpstream          string
	DefaultPolicyProfile string
	DefaultCPUs          uint32
	DefaultMemoryMiB     uint32
	DockerVolumeSize     string
}

// DefaultPath returns ~/.config/lickren/settings.toml, honoring XDG_CONFIG_HOME.
func DefaultPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "lickren", "settings.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "lickren", "settings.toml")
}

// Load reads the optional settings file. A missing file is not an error.
func Load(path string) (Values, error) {
	var values Values
	if path == "" {
		return values, nil
	}
	file, err := os.Open(path) // #nosec G304 -- path is the user settings location
	if errors.Is(err, os.ErrNotExist) {
		return values, nil
	}
	if err != nil {
		return values, fmt.Errorf("open settings: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return values, fmt.Errorf("stat settings: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return values, errors.New("settings file must be a regular file not writable by group or others")
	}
	if err := parse(file, &values); err != nil {
		return values, err
	}
	if err := validateValues(values); err != nil {
		return values, err
	}
	return values, nil
}

func validateValues(values Values) error {
	if values.DNSUpstream != "" {
		host, port, err := net.SplitHostPort(values.DNSUpstream)
		if err != nil || host == "" || port == "" {
			return errors.New("settings dns_upstream must be HOST:PORT")
		}
		if parsed, err := strconv.ParseUint(port, 10, 16); err != nil || parsed == 0 {
			return errors.New("settings dns_upstream port must be 1..65535")
		}
	}
	switch values.DefaultPolicyProfile {
	case "", "deny-all", "balanced", "sbx-compat", "allow-all":
	default:
		return errors.New("settings default_policy_profile is invalid")
	}
	if values.DefaultCPUs > 64 {
		return errors.New("settings default_cpus must be at most 64")
	}
	if values.DefaultMemoryMiB > 32768 {
		return errors.New("settings default_memory_mib must be at most 32768")
	}
	return nil
}

func parse(r io.Reader, values *Values) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, found := strings.Cut(line, "=")
		if !found {
			return fmt.Errorf("settings line %d: expected key = value", lineNumber)
		}
		key = strings.TrimSpace(key)
		raw = strings.TrimSpace(raw)
		value, err := parseValue(raw)
		if err != nil {
			return fmt.Errorf("settings line %d: %w", lineNumber, err)
		}
		switch key {
		case "dns_upstream":
			values.DNSUpstream = value
		case "default_policy_profile":
			values.DefaultPolicyProfile = value
		case "default_cpus":
			parsed, err := parseUint(key, value, 64)
			if err != nil {
				return err
			}
			values.DefaultCPUs = uint32(parsed) //nolint:gosec // parsed with 32 bits and bounded below.
		case "default_memory_mib":
			parsed, err := parseUint(key, value, 32)
			if err != nil {
				return err
			}
			values.DefaultMemoryMiB = uint32(parsed) //nolint:gosec // parsed with 32 bits and bounded below.
		case "docker_volume_size":
			values.DockerVolumeSize = value
		default:
			return fmt.Errorf("settings line %d: unknown key %q", lineNumber, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read settings: %w", err)
	}
	return nil
}

func parseValue(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("empty value")
	}
	if raw[0] != '"' {
		return raw, nil
	}
	value, err := strconv.Unquote(raw)
	if err != nil {
		return "", fmt.Errorf("invalid quoted string: %w", err)
	}
	return value, nil
}

func parseUint(key, value string, bits int) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, bits)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return parsed, nil
}
