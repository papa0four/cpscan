// internal/softwarelist/softwarelist.go
package softwarelist

import (
    "fmt"
    "os/exec"
    "runtime"
)

// GetInstalledSoftware retrieves a list of installed software based on the OS
// It first tries to list software without admin privileges. If the full list cannot be retrieved,
// it prompts the user to rerun the command with admin/root privileges
func GetInstalledSoftware() (string, error) {
    switch runtime.GOOS {
    case "linux":
        return getLinuxSoftware()
    case "windows":
        return getWindowsSoftware()
    case "darwin":
        return getMacSoftware()
    case "freebsd":
        return getFreeBSDSoftware()
    default:
        return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
    }
}

// getLinuxSoftware retrieves installed software for Linux-based systems
func getLinuxSoftware() (string, error) {
    // Try to list software with both dpkg and rpm (Debian and RedHat based)
	if output, err := exec.Command("dpkg-query", "-l").Output(); err == nil {
		return string(output), nil
	}

	if output, err := exec.Command("rpm", "-qa").Output(); err == nil {
		return string(output), nil
	}

    // If neither dpkg nor rpm work, suggest using sudo for full list
    return "", fmt.Errorf("Insufficient permissions to list all software packages.\n" +
        "Try running the command with 'sudo go run ./cmd/main.go software' to get a full list.")
}

// getWindowsSoftware retrieves installed software for Windows systems
func getWindowsSoftware() (string, error) {
	output, err := exec.Command("wmic", "product", "get", "name,version").Output()
	if err == nil {
		return (output), nil
	}
}

// getMacSoftware retrieves installed software for MacOS
func getMacSoftware() (string, error) {
	output, err := exec.Command("system_profiler", "SPApplicationsDataType").Output()
	if err == nil {
		return string(output), nil
	}

    // Suggest running with sudo if command fails
    return "", fmt.Errorf("Insufficient permissions to list all software packages.\n" +
        "Try running the command with 'sudo go run ./cmd/main.go software' to get a full list.")
}

// getFreeBSDSoftware retrieves installed software for FreeBSD systems
func getFreeBSDSoftware() (string, error) {
	output, err := exec.Command("pkg", "info").Output()
	if err == nil {
		return string(output), nil
	}

    // Suggest using sudo if command fails
    return "", fmt.Errorf("Insufficient permissions to list all software packages.\n" +
        "Try running the command with 'sudo go run ./cmd/main.go software' to get a full list.")
}
