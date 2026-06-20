// internal/osfingerprint/osfingerprint.go
package osfingerprint

import (
	"fmt"
	"runtime"

	"github.com/shirou/gopsutil/host"
)

// OSInfo holds operating system fingerprint details retrieved from the host.
type OSInfo struct {
	OS              string
	Platform        string
	PlatformVersion string
	KernelVersion   string
	Hostname        string
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

// PrintOSInfo prints the OS Fingerprint details in a formatted way
func PrintOSInfo() {
	osInfo, err := GetOSFingerprint()
	if err != nil {
		fmt.Printf("Error retrieving OS Information: %v\n", err)
		return
	}

	fmt.Printf("OS: %s\nHostname: %s\nPlatform: %s\nVersion: %s\nKernel Version: %s\n",
		osInfo.OS, osInfo.Hostname, osInfo.Platform, osInfo.PlatformVersion, osInfo.KernelVersion)

	// Print additional OS-specific information
	for key, value := range osInfo.AdditionalInfo {
		fmt.Printf("%s: %s\n", key, value)
	}
}
