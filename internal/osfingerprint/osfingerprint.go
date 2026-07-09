// internal/osfingerprint/osfingerprint.go
package osfingerprint

import (
	"fmt"
	"io"
	"runtime"
	"sort"

	"github.com/shirou/gopsutil/host"
)

// OSInfo holds operating system fingerprint details retrieved from the host.
type OSInfo struct {
	OS              string
	Platform        string
	PlatformVersion string
	KernelVersion   string
	Hostname        string
	Architecture    string
	AdditionalInfo  map[string]string // store any additional OS-Specific details
}

// GetOSFingerprint retrieves OS-Specific fingerprinting information
func GetOSFingerprint() (*OSInfo, error) {
	info, err := host.Info()
	if err != nil {
		return nil, err
	}

	osInfo := &OSInfo{
		OS:              info.OS,
		Platform:        info.Platform,
		PlatformVersion: info.PlatformVersion,
		KernelVersion:   info.KernelVersion,
		Hostname:        info.Hostname,
		Architecture:    runtime.GOARCH,
		AdditionalInfo:  make(map[string]string),
	}

	// Check the platform (Windows, Unix, MacOS, etc.)
	switch runtime.GOOS {
	case "windows":
		osInfo.AdditionalInfo["ProductName"] = "Windows"
		osInfo.AdditionalInfo["EditionID"] = info.PlatformFamily // Windows-specific details
	case "darwin":
		osInfo.AdditionalInfo["ProductName"] = "MacOS"
		osInfo.AdditionalInfo["HardwareModel"] = runtime.GOARCH // Specific to MacOS
	case "linux":
		osInfo.AdditionalInfo["DistroFamily"] = info.PlatformFamily // Linux/Unix distribution
	case "freebsd":
		osInfo.AdditionalInfo["ProductName"] = "FreeBSD"
	default:
		osInfo.AdditionalInfo["ProductName"] = "Unknown"
	}

	return osInfo, nil
}

// WriteText writes o's fields to w as labeled lines in fixed order.
// AdditionalInfo keys are sorted before writing so output is deterministic --
// Go map iteration order is randomized and would otherwise produce
// nondeterministic diffs in reports and tests.
func WriteText(w io.Writer, o *OSInfo) error {
	if o == nil {
		return fmt.Errorf("osfingerprint: cannot render nil OSInfo")
	}

	if _, err := fmt.Fprintf(w, "OS: %s\nHostname:%s\nPlatform: %s\nVersion: %s\nKernel Version: %s\nArchitecture: %s\n",
		o.OS, o.Hostname, o.Platform, o.PlatformVersion, o.KernelVersion, o.Architecture); err != nil {
		return fmt.Errorf("osfingerprint: write failed: %w", err)
	}

	keys := make([]string, 0, len(o.AdditionalInfo))
	for key := range o.AdditionalInfo {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if _, err := fmt.Fprintf(w, "%s: %s\n", key, o.AdditionalInfo[key]); err != nil {
			return fmt.Errorf("osfingerprint: write failed: %w", err)
		}
	}
	return nil
}
