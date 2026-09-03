//go:build windows

// internal/softwarelist/softwarelist_windows.go

package softwarelist

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

// getPlatformSoftwareList reads installed software directly from the Windows
// registry. Four locations are checked for complete coverage:
//   - HKLM 64-bit uninstall path (system-wide 64-bit installs)
//   - HKLM 32-bit Wow6432Node path (system-wide 32-bit installs)
//   - HKCU 64-bit uninstall path (current user 64-bit installs)
//   - HKCU 32-bit Wow6432Node path (current user 32-bit installs)
//
// A display name map deduplicates entries that appear in multiple paths.
// There is deliberately no exec fallback: the former wmic path queried
// Win32_Product, whose enumeration triggers MSI consistency checks that can
// reconfigure installed packages -- a read that mutates target state has no
// place in an auditing tool. All four hives yielding nothing means the token
// or host is broken, and the honest behavior is the error path. ctx is
// accepted for cross-platform signature parity; the registry API offers no
// cancellation point.
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

	return nil, fmt.Errorf("no software entries readable from any registry uninstall hive; verify registry access or rerun as Administrator")
}
