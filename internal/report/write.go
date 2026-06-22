// internal/report/write.go
package report

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// DefaultPath returns a generated report destination in CWD
func DefaultPath(scan, format string) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	return fmt.Sprintf("owatch-%s-%s.%s", scan, stamp, extension(format))
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
