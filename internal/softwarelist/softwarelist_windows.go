//go:build windows

// internal/softwarelist/softwarelist_windows.go
package softwarelist

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// getPlatformSoftware reads installed software directly from the Windows
// registry. Four locations are checked for complete coverage:
//   - HKLM 64-bit uninstall path (system-wide 64-bit installs)
//   - HKLM 32-bit Wow6432Node path (system-wide 32-bit installs)
//   - HKCU 64-bit uninstall path (current user 64-bit installs)
//   - HKCU 32-bit Wow6432Node path (current user 32-bit installs)
//
// A display name map deduplicates entries that appear in multiple paths.
// wmic is called as a fallback for environments where registry
// access is restricted, but its use is flagged since it is deprecated as of
// Windows 10 21H1.
func getPlatformSoftware() (string, error) {
	const (
		uninstallPath   = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
		uninstallPath32 = `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	)

	type registryTarget struct {
		root registry.Key
		path string
	}

	targets := []registryTarget{
		{registry.LOCAL_MACHINE, uninstallPath},
		{registry.LOCAL_MACHINE, uninstallPath32},
		{registry.CURRENT_USER, uninstallPath},
		{registry.CURRENT_USER, uninstallPath32},
	}

	type entry struct {
		name    string
		version string
	}

	seen := make(map[string]bool)
	var entries []entry

	for _, target := range targets {
		k, err := registry.OpenKey(target.root, target.path,
			registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		subkeys, readErr := k.ReadSubKeyNames(-1)
		if closeErr := k.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "[!] WARNING: failed to close registry key %s: %v\n", target.path, closeErr)
		}
		if readErr != nil {
			continue
		}

		for _, sub := range subkeys {
			sk, err := registry.OpenKey(target.root,
				target.path+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			name, _, err := sk.GetStringValue("DisplayName")
			if err != nil || name == "" {
				if closeErr := sk.Close(); closeErr != nil {
					fmt.Fprintf(os.Stderr, "[!] WARNING: failed to close registry subkey %s: %v\n", sub, closeErr)
				}
				continue
			}

			version, _, _ := sk.GetStringValue("DisplayVersion") //nolint:errcheck // version is optional; missing or unreadable value is treated as empty
			if closeErr := sk.Close(); closeErr != nil {
				fmt.Fprintf(os.Stderr, "[!] WARNING: failed to close registry subkey %s: %v\n", sub, closeErr)
			}

			if seen[name] {
				continue
			}

			seen[name] = true
			entries = append(entries, entry{name: name, version: version})
		}
	}

	if len(entries) > 0 {
		var sb strings.Builder
		fmt.Fprintf(&sb, "%-60s %s\n", "Name", "Version")
		for _, e := range entries {
			fmt.Fprintf(&sb, "%-60s %s\n", e.name, e.version)
		}
		return sb.String(), nil
	}

	// wmic fallback
	fmt.Fprintln(os.Stderr,
		"[!] WARNING: registry read returned no results; falling back to wmic (deprecated on Windows 10 21H1+)")
	output, err := exec.Command("wmic", "product", "get", "name,version").Output()
	if err == nil {
		return string(output), nil
	}

	return "", fmt.Errorf("insufficient permissions to list software packages; try rerunning as Administrator")
}
