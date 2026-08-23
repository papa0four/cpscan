// Package softwarelist enumerates installed software packages on the host.
// It provides both a structured list for programmatic consumption and a
// formatted string for human-readable text output.
package softwarelist

import "fmt"

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
// suitable for enrichment lookups and structured report output.
func GetInstalledSoftwareList() ([]SoftwareEntry, error) {
	entries, err := getPlatformSoftwareList()
	if err != nil {
		return nil, fmt.Errorf("software enumeration failed: %w", err)
	}
	return entries, nil
}

// GetInstalledSoftware returns the installed software packages as a
// formatted human-readable string. Used for text output and the standalone
// software subcommand.
func GetInstalledSoftware() (string, error) {
	result, err := getPlatformSoftware()
	if err != nil {
		return "", fmt.Errorf("software enumeration failed: %w", err)
	}
	return result, nil
}
