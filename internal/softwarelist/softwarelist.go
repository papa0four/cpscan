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
    case "unix":
        return getUnixSoftware() // Handling other Unix-like systems
    default:
        return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
    }
}

// getLinuxSoftware retrieves installed software for Linux-based systems
func getLinuxSoftware() (string, error) {
    // Try to list software with both dpkg and rpm (Debian and RedHat based)
    dpkgCmd := exec.Command("dpkg-query", "-l")
    dpkgOutput, dpkgErr := dpkgCmd.Output()

    if dpkgErr == nil {
        return string(dpkgOutput), nil
    }

    // If dpkg fails, try rpm
    rpmCmd := exec.Command("rpm", "-qa")
    rpmOutput, rpmErr := rpmCmd.Output()

    if rpmErr == nil {
        return string(rpmOutput), nil
    }

    // If neither dpkg nor rpm work, suggest using sudo for full list
    return "", fmt.Errorf("Insufficient permissions to list all software packages.\n" +
        "Try running the command with 'sudo go run ./cmd/main.go software' to get a full list.")
}

// getWindowsSoftware retrieves installed software for Windows systems
func getWindowsSoftware() (string, error) {
    // Use WMIC to list installed products (may require admin privileges for full list)
    cmd := exec.Command("wmic", "product", "get", "name,version")
    output, err := cmd.Output()
    if err == nil {
        return string(output), nil
    }

    return "", fmt.Errorf("Insufficient permissions to list all software packages.\n" +
        "Try running the command in an Administrator CMD Prompt or Powershell for a full list.")
}

// getMacSoftware retrieves installed software for MacOS
func getMacSoftware() (string, error) {
    // Use system_profiler to list installed applications
    cmd := exec.Command("system_profiler", "SPApplicationsDataType")
    output, err := cmd.Output()
    if err == nil {
        return string(output), nil
    }

    // Suggest running with sudo if command fails
    return "", fmt.Errorf("Insufficient permissions to list all software packages.\n" +
        "Try running the command with 'sudo go run ./cmd/main.go software' to get a full list.")
}

// getFreeBSDSoftware retrieves installed software for FreeBSD systems
func getFreeBSDSoftware() (string, error) {
    // use pkg info to list installed software on FreeBSD
    cmd := exec.Command("pkg", "info")
    output, err := cmd.Output()
    if err == nil {
        return string(output), nil
    }

    // Suggest using sudo if command fails
    return "", fmt.Errorf("Insufficient permissions to list all software packages.\n" +
        "Try running the command with 'sudo go run ./cmd/main.go software' to get a full list.")
}

// getUnixSoftware retrieves installed software for generic Unix-based systems
func getUnixSoftware() (string, error) {
    // pkg_add or other package managers if available
    pkgCmd := exec.Command("pkg_add", "-l")
    output, err := pkgCmd.Output()

    if err == nil {
        return string(output), nil
    }

    // Suggest using sudo if command fails
    return "", fmt.Errorf("Insufficient permissions to list all software packages.\n" +
        "Try running the command with 'sudo go run ./cmd/main.go' to get a full list.")
}
