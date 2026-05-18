// internal/softwarelist/softwarelist.go
package softwarelist

import (
	"fmt"
	"os/exec"
	"runtime"
)

// GetInstalledSoftware retrieves a list of installed software based on the OS
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

func getLinuxSoftware() (string, error) {
	if output, err := exec.Command("dpkg-query", "-l").Output(); err == nil {
		return string(output), nil
	}

	if output, err := exec.Command("rpm", "-qa").Output(); err == nil {
		return string(output), nil
	}

	return "", fmt.Errorf("insufficient permissions to list all software packages; try rerunning with sudo")
}

func getWindowsSoftware() (string, error) {
	output, err := exec.Command("wmic", "product", "get", "name,version").Output()
	if err == nil {
		return string(output), nil
	}

	return "", fmt.Errorf("insufficient permissions to list all software packages; try rerunning as Administrator")
}

func getMacSoftware() (string, error) {
	output, err := exec.Command("system_profiler", "SPApplicationsDataType").Output()
	if err == nil {
		return string(output), nil
	}

	return "", fmt.Errorf("insufficient permissions to list all software packages; try rerunning with sudo")
}

func getFreeBSDSoftware() (string, error) {
	output, err := exec.Command("pkg", "info").Output()
	if err == nil {
		return string(output), nil
	}

	return "", fmt.Errorf("insufficient permissions to list all software packages; try rerunning with sudo")
}
