// internal/report/write.go
package report

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Sentinel errors returned by Write for unsafe destinations.
var (
	ErrParentMissing       = errors.New("destination directory does not exist")
	ErrRefusedLocation     = errors.New("destination is a protected location")
	ErrElevatedWriteDenied = errors.New("elevated write outside allowlisted roots requires explicit confirmation")
	ErrNotRegularFile      = errors.New("destination exists and is not a regular file")
	ErrElevatedExposedDir  = errors.New("elevated write refused: destination directory is writable by other users")
)

// Options carries caller decisions that affect write policy.
type Options struct {
	// AllowElevatedWrite is set when --allow-elevated-write is passed
	// and, where a TTY exists, confirmed the prompt.
	AllowElevatedWrite bool
}

// Write validates path through the full guard pipeline and writes data to it,
func Write(path string, data []byte, opts Options) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	// Resolve the parent against the real filesystem s
	parent := filepath.Dir(abs)
	realParent, err := canonicalParent(parent)
	if err != nil {
		return err
	}

	info, err := os.Stat(realParent)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: %s", ErrParentMissing, parent)
	}

	target := filepath.Join(realParent, filepath.Base(abs))

	if reason := refusedReason(target); reason != "" {
		return fmt.Errorf("%w: %s", ErrRefusedLocation, reason)
	}

	elevated, err := isElevated()
	if err != nil {
		return fmt.Errorf("determine privilege: %w", err)
	}
	if elevated {
		// Refuse a root write into a directory other users can control
		exposed, err := parentWritableByOthers(realParent)
		if err != nil {
			return fmt.Errorf("inspect destination directory: %w", err)
		}
		if exposed {
			return fmt.Errorf("%w: %s", ErrElevatedExposedDir, realParent)
		}

		if !opts.AllowElevatedWrite {
			allowed, err := withinAllowlist(target)
			if err != nil {
				return err
			}
			if !allowed {
				return ErrElevatedWriteDenied
			}
		}
	}

	return openAndWrite(target, data)
}

// DefaultPath returns the full path for a generated report file inside dir.
// The filename follows the pattern owatch-<hostname>-<codes>-<timestamp>.<ext>
// where codes is the category-prefixed segment string produced by scan.Codes
// (e.g. "m.os-c.fpsu"). Empty code segments are omitted by the caller.
// dir must be an existing directory; the caller is responsible for validating it.
func DefaultPath(dir, hostname, codes, format string) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	var name string
	if codes != "" {
		name = fmt.Sprintf("owatch-%s-%s-%s.%s", hostname, codes, stamp, extension(format))
	} else {
		name = fmt.Sprintf("owatch-%s-%s.%s", hostname, stamp, extension(format))
	}
	return filepath.Join(dir, name)
}

// ResolveHostname returns a filename-safe host identifier using a fallback
// chain: sanitized os.Hostname(), then unknown-<mac> using the first valid
// non-loopback MAC address (hex, no separators), then unknown.
//
// Exempt from the single-reader rule that makes internal/osfingerprint the
// sole source of host identity: report naming must succeed even when
// fingerprinting was skipped or failed, so it cannot depend on fingerprint
// data existing.
func ResolveHostname() string {
	// hostnameRe retains only characters safe in filenames across all supported
	// platforms; anything else becomes a hyphen.
	hostnameRe := regexp.MustCompile(`[^a-zA-Z0-9\-.]`)

	if h, err := os.Hostname(); err == nil && h != "" {
		sanitized := hostnameRe.ReplaceAllString(h, "-")
		if len(sanitized) > 63 {
			sanitized = sanitized[:63]
		}
		if sanitized != "" {
			return sanitized
		}
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if len(iface.HardwareAddr) == 0 {
				continue
			}
			mac := strings.ReplaceAll(iface.HardwareAddr.String(), ":", "")
			if mac != "" {
				return "unknown-" + mac
			}
		}
	}

	return "unknown"
}

func extension(format string) string {
	switch format {
	case "json":
		return "json"
	case "yaml":
		return "yaml"
	case "csv":
		return "csv"
	case "text":
		return "txt"
	default:
		// Unrecognized format falls back to usable default
		return "json"
	}
}

// pathWithin compares on path boundaries so a sibling is not mistaken for a child
func pathWithin(target, base string) bool {
	if target == base {
		return true
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
