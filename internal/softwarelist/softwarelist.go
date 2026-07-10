// Package softwarelist enumerates installed software packages on the host.
// It provides both a structured list for programmatic consumption and a
// formatted string for human-readable text output.
package softwarelist

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// SoftwareEntry represents a single installed software package with its
// display name and version string as reported by the host platform.
// Name and Version are discrete fields to support downstream CPE lookups
// and enrichment adapter queries against vulnerability databases.
type SoftwareEntry struct {
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version,omitempty" yaml:"version,omitempty"`
}

// GetInstalledSoftwareList returns the installed software packages as a
// structured slice. Each entry carries a discrete name and version field
// suitable for enrichment lookups and structured report output. ctx bounds
// the platform package-manager invocations.
func GetInstalledSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
	entries, err := getPlatformSoftwareList(ctx)
	if err != nil {
		return nil, fmt.Errorf("software enumeration failed: %w", err)
	}
	return entries, nil
}

// GetInstalledSoftware returns the installed software packages as a
// formatted human-readable string. Used for text output and the standalone
// software subcommand. ctx bounds the platform package-manager invocations.
func GetInstalledSoftware(ctx context.Context) (string, error) {
	entries, err := getPlatformSoftwareList(ctx)
	if err != nil {
		return "", fmt.Errorf("software enumeration failed: %w", err)
	}
	var sb strings.Builder
	if err := WriteTable(&sb, entries, true); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// WriteTable writes entries to w as fixed-width name and version columns,
// one package per line. withHeader controls the leading column header row:
// the standalone software subcommand prints it, while the all command's
// verbose listing omits it. This is the single definition of the software
// table row format.
func WriteTable(w io.Writer, entries []SoftwareEntry, withHeader bool) error {
	if withHeader {
		if _, err := fmt.Fprintf(w, "%-60s %s\n", "Name", "Version"); err != nil {
			return fmt.Errorf("software table write failed: %w", err)
		}
	}
	for _, e := range entries {
		if _, err := fmt.Fprintf(w, "%-60s %s\n", e.Name, e.Version); err != nil {
			return fmt.Errorf("software table write failed: %w", err)
		}
	}
	return nil
}
