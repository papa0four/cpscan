//go:build windows

// internal/softwarelist/softwarelist_windows.go
package softwarelist

import (
	"context"
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
func getPlatformSoftwareList(ctx context.Context) ([]SoftwareEntry, error) {
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

	seen := make(map[string]bool)
	var entries []SoftwareEntry

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
			entries = append(entries, SoftwareEntry{Name: name, Version: version})
		}
	}

	if len(entries) > 0 {
		return entries, nil
	}

	// wmic fallback
	fmt.Fprintln(os.Stderr,
		"[!] WARNING: registry read returned no results; falling back to wmic (deprecated on Windows 10 21H1+)")
	output, err := exec.CommandContext(ctx, "wmic", "product", "get", "name,version").Output()
	if err != nil {
		return nil, fmt.Errorf("insufficient permissions to list software packages; try rerunning as Administrator")
	}

	// parse wmic tab-delimited output into entries
	var wmicEntries []SoftwareEntry
	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] { //skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		version := ""
		name := line
		if len(fields) > 1 {
			version = fields[len(fields)-1]
			name = strings.TrimSpace(strings.TrimSuffix(line, version))
		}
		wmicEntries = append(wmicEntries, SoftwareEntry{Name: name, Version: version})
	}
	return wmicEntries, nil
}
