// internal/security/checker/firewall.go
package checker

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// FirewallChecker defines interface for Firewall configuration checking
type FirewallChecker interface {
	Check(ctx context.Context) types.AuditResult
}

type (
	// UnixFirewallChecker implements FirewallChecker for Unix-like systems
	UnixFirewallChecker struct {
		osCtx registry.OSContext
	}

	// WindowsFirewallChecker implements FirewallChecker for Windows systems
	WindowsFirewallChecker struct {
		osCtx registry.OSContext
	}

	// firewallTool represents a firewall management tool
	firewallTool struct {
		name    string
		command []string
		parser  func([]byte) []string
	}
)

// NewUnixFirewallChecker creates a new Unix firewall checker
func NewUnixFirewallChecker(osCtx registry.OSContext) *UnixFirewallChecker {
	return &UnixFirewallChecker{osCtx: osCtx}
}

// NewWindowsFirewallChecker creates a new Windows firewall checker
func NewWindowsFirewallChecker(osCtx registry.OSContext) *WindowsFirewallChecker {
	return &WindowsFirewallChecker{osCtx: osCtx}
}

// Check implements FirewallChecker interface for Unix systems
func (f *UnixFirewallChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        "Firewall Configuration",
		Status:      "CHECKING",
		Description: "Analyzing firewall configuration and rules",
		Details:     make([]string, 0),
	}

	// Define supported firewall tools
	firewalls := []firewallTool{
		{
			name:    "iptables",
			command: []string{"iptables", "-L", "-n", "-v"},
			parser:  parseIptablesOutput,
		},
		{
			name:    "ufw",
			command: []string{"ufw", "status", "verbose"},
			parser:  parseUfwOutput,
		},
		{
			name:    "firewalld",
			command: []string{"firewall-cmd", "--list-all"},
			parser:  parseFirewalldOutput,
		},
		{
			name:    "pfctl",
			command: []string{"pfctl", "-sr"},
			parser:  parsePfctlOutput,
		},
	}

	activeFirewalls := 0
	uncheckedFirewalls := 0
	for _, fw := range firewalls {
		if _, err := exec.LookPath(fw.command[0]); err != nil {
			continue
		}

		cmd := exec.CommandContext(ctx, fw.command[0], fw.command[1:]...) // #nosec G204 -- command args sourced from hardcoded firewallTool struct definitions, not user
		output, err := cmd.CombinedOutput()

		if err == nil && len(output) > 0 {
			activeFirewalls++
			result.Details = append(result.Details,
				fmt.Sprintf("\n%s %s firewall is active", types.SymbolOK, fw.name))
			parsedRules := fw.parser(output)
			result.Details = append(result.Details, parsedRules...)
			continue
		}

		uncheckedFirewalls++
		result.Details = append(result.Details,
			fmt.Sprintf("%s %s is installed but its status could not be verified in this run",
				types.SymbolWarning, fw.name))
	}

	// Check overall firewall status
	switch {
	case activeFirewalls > 0:
		result.Status = "COMPLETED"
		result.Description = fmt.Sprintf("Found %d active firewall(s)", activeFirewalls)
		if activeFirewalls > 1 {
			result.Details = append(result.Details,
				fmt.Sprintf("%s NOTE: Multiple active firewalls detected - verify configurations don't conflict",
					types.SymbolInfo))
		}
	case uncheckedFirewalls > 0:
		result.Status = "WARNING"
		result.Description = "Firewall status could not be fully verified"
		result.Details = append(result.Details,
			fmt.Sprintf("%s Firewall check skipped: rerun with elevated privileges for a definitive result",
				types.SymbolInfo))
	default:
		result.Status = "WARNING"
		result.Description = "No active firewall detected"
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: No active firewall detected", types.SymbolWarning))
		emitFinding(&result, f.osCtx, "firewall.no_active_manager")
	}

	return result
}

// Check implements FirewallChecker interface for Windows systems
func (f *WindowsFirewallChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        "Windows Firewall Configuration",
		Status:      "CHECKING",
		Description: "Analyzing Windows Firewall Configuration",
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	// Check firewall status for all profiles
	cmd := exec.CommandContext(ctx, "netsh", "advfirewall", "show", "allprofiles", "state")
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Status = "ERROR"
		result.Description = "Failed to check Windows Firewall status"
		result.Details = append(result.Details,
			fmt.Sprintf("%s Error checking firewall status: %v", types.SymbolError, err))
		return result
	}

	// Parse firewall profiles status
	profiles := parseWindowsFirewallStatus(string(output))
	activeProfiles := 0
	inactiveProfiles := 0
	for profile, state := range profiles {
		if state {
			activeProfiles++
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s profile is active", types.SymbolOK, profile))
		} else {
			inactiveProfiles++
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: %s profile is inactive", types.SymbolWarning, profile))
		}
	}

	// One finding per inactive profile
	if inactiveProfiles > 0 && activeProfiles > 0 {
		emitFinding(&result, f.osCtx, "firewall.profile_inactive")
	}

	// Check firewall rules if at least one profile is active
	if activeProfiles > 0 {
		cmd = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "show", "rule", "name=all", "verbose")
		output, err := cmd.CombinedOutput()
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Error enumerating firewall rules: %v", types.SymbolError, err))
		} else {
			rules := parseWindowsFirewallRules(string(output))
			result.Details = append(result.Details, "", "Active Firewall Rules:")
			for _, rule := range rules {
				result.Details = append(result.Details,
					fmt.Sprintf(" %s", rule))
			}
		}
	}

	// Set final status
	if activeProfiles == 0 {
		result.Status = "WARNING"
		result.Description = "Windows Firewall is disabled for all profiles"
		result.Details = append(result.Details,
			fmt.Sprintf("%s CRITICAL: Windows Firewall is completely disabled", types.SymbolCritical))
		emitFinding(&result, f.osCtx, "firewall.all_profiles_disabled")
	} else {
		result.Status = "COMPLETED"
		result.Description = fmt.Sprintf("Windows Firewall is active on %d profile(s)", activeProfiles)
	}

	return result
}

// Helper functions for parsing firewall outputs

func parseIptablesOutput(output []byte) []string {
	lines := strings.Split(string(output), "\n")
	rules := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Chain") && !strings.HasPrefix(line, "target") {
			rules = append(rules, line)
		}
	}
	return rules
}

func parseUfwOutput(output []byte) []string {
	lines := strings.Split(string(output), "\n")
	rules := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "ALLOW") || strings.Contains(line, "DENY") {
			rules = append(rules, line)
		}
	}
	return rules
}

func parseFirewalldOutput(output []byte) []string {
	lines := strings.Split(string(output), "\n")
	rules := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "services:") || strings.Contains(line, "ports:") {
			rules = append(rules, line)
		}
	}
	return rules
}

func parsePfctlOutput(output []byte) []string {
	lines := strings.Split(string(output), "\n")
	rules := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			rules = append(rules, line)
		}
	}
	return rules
}

func parseWindowsFirewallStatus(output string) map[string]bool {
	profiles := make(map[string]bool)
	lines := strings.Split(output, "\n")

	currentProfile := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Domain Profile") {
			currentProfile = "Domain"
		} else if strings.HasPrefix(line, "Private Profile") {
			currentProfile = "Private"
		} else if strings.HasPrefix(line, "Public Profile") {
			currentProfile = "Public"
		}

		if strings.Contains(line, "State") {
			profiles[currentProfile] = strings.Contains(strings.ToLower(line), "on")
		}
	}

	return profiles
}

func parseWindowsFirewallRules(output string) []string {
	lines := strings.Split(output, "\n")
	rules := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Rule Name:") ||
			strings.HasPrefix(line, "Enabled:") ||
			strings.HasPrefix(line, "Direction:") {
			rules = append(rules, line)
		}
	}

	return rules
}
