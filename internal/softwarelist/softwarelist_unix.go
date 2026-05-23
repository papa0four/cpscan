//go:build linux || darwin || freebsd

// internal/softwarelist/softwarelist_unix.go
package softwarelist

import (
	"fmt"
	"os/exec"
	"runtime"
)

// getPlatformSoftware enumerates installed software using the appropriate
// package manager or system tool for the current Unix-like platform.
func getPlatformSoftware() (string, error) {
	switch runtime.GOOS {
	case "linux":
		if output, err := exec.Command("dpkg-query", "-l").Output(); err == nil {
			return string(output), nil
		}
		if output, err := exec.Command("rpm", "-qa").Output(); err == nil {
			return string(output), nil
		}
		return "", fmt.Errorf("no supported package manager found; try rerunning with sudo")

	case "darwin":
		output, err := exec.Command("system_profiler", "SPApplicationsDataType").Output()
		if err == nil {
			return string(output), nil
		}
		return "", fmt.Errorf("insufficient permissions to list software packages; try rerunning with sudo")

	case "freebsd":
		output, err := exec.Command("pkg", "info").Output()
		if err == nil {
			return string(output), nil
		}
		return "", fmt.Errorf("insufficient permissions to list software packages; try rerunning with sudo")

	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}
