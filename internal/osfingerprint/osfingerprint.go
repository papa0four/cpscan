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

// DistinctPlatform returns Platform when it differs from OS, and the empty
// string when they are equal. A caller renders the Platform line only when
// this returns non-empty. OS is the anchor because it is the more general,
// always-meaningful identifier; Platform is the refinement worth showing only
// when it adds information. On darwin the two are identical, so Platform is
// omitted.
func (o *OSInfo) DistinctPlatform() string {
	if o.Platform == o.OS {
		return ""
	}
	return o.Platform
}

// DistinctKernelVersion returns KernelVersion when it differs from
// PlatformVersion, and the empty string when they are equal. A caller renders
// the platform version unconditionally and renders a kernel line only when
// this returns non-empty. PlatformVersion is the anchor: on Windows it and
// KernelVersion are the same build string, and "version" describes that string
// more truthfully than "kernel version," which carries a distinct meaning only
// on Linux where the kernel is versioned separately from the platform. On
// those systems the two differ and both lines appear.
func (o *OSInfo) DistinctKernelVersion() string {
	if o.KernelVersion == o.PlatformVersion {
		return ""
	}
	return o.KernelVersion
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

	if _, err := fmt.Fprintf(w, "OS: %s\nHostname: %s\nPlatform: %s\nVersion: %s\nKernel Version: %s\nArchitecture: %s\n",
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
