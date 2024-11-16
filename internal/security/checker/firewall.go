// internal/security/checker/firewall.go
package checker

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/papa0four/cpscan/internal/security/types"
)

// SSHChecker defines interface for SSH configuration checking
type FirewallChecker interface {
	Check() types.AuditResult
}

// UnixFirewallChecker implements FirewallChecker for Unix-like systems
type UnixFirewallChecker struct {}

// WindowsFirewallChecker implements FirewallChecker for Windows systems
type WindowsFirewallChecker struct {}

// NewUnixFirewallChecker creates a new Unix firewall checker
func NewUnixFirewallChecker() *UnixFirewallChecker {
	return &UnixFirewallChecker{}
}

// NewWindowsFirewallChecker creates a new Windows firewall checker
func NewWindowsFirewallChecker() *WindowsFirewallChecker {
	return &WindowsFirewallChecker{}
}

// firewallTool represents a firewall management tool
type firewallTool struct {
	name		string
	command		[]string
	parser		func([]byte) []string
}

// Check implements FirewallChecker interface for Unix systems
func (f *UnixFirewallChecker) Check() types.AuditResult {
	result := types.AuditResult{
		Name:			"Firewall Configuration",
		Status:			"CHECKING",
		Description:	"Analyzing firewall configuration and rules",
		Details:		make([]string, 0),
	}

	// Define supported firewall tools
	firewalls := []firewallTool{
		{
			name:		"iptables",
			command:	[]string{"iptables", "-L", "-n", "-v"},
			parser:		parseIptablesOutput,
		},
		{
			name:		"ufw",
			command:	[]string{"ufw", "status", "verbose"},
			parser:		parseUfwOutput,
		},
		{
			name:		"firewalld",
			command:	[]string{"firewall-cmd", "--list-all"},
			parser:		parseFirewalldOutput,
		},
		{
			name:		"pfctl",
			command:	[]string{"pfctl", "-sr"},
			parser:		parsePfctlOutput,
		},
	}

	activeFirewalls := 0
	for _, fw := range firewalls {
		cmd := exec.Command(fw.command[0], fw.command[1:]...)
		output, err := cmd.CombinedOutput()

		if err == nil && len(output) > 0 {
			activeFirewalls++
			result.Details = append(result.Details,
				fmt.Sprintf("\n%s %s firewall is active", types.SymbolOK, fw.name))

			// Parse and add the firewall rules
			parsedRules := fw.parser(output)
			for _, rule := range parsedRules {
				result.Details = append(result.Details,
					fmt.Sprintf( "%s", rule))
			}
		}
	}

	// Check overall firewall status
	if activeFirewalls == 0 {
		result.Status = "WARNING"
		result.Description = "No active firewall detected"
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: No active firewall detected", types.SymbolWarning))
	} else {
		result.Status = "COMPLETED"
		result.Description = fmt.Sprintf("Found %d active firewall(s)", activeFirewalls)
		if activeFirewalls > 1 {
			result.Details = append(result.Details,
				fmt.Sprintf("%s NOTE: Multiple active firewalls detected - verify configurations don't conflict",
					types.SymbolInfo))
		}
	}

	return result
}

// Check implements FirewallChecker interface for Windows systems
func (f *WindowsFirewallChecker) Check() types.AuditResult {
	result := types.AuditResult{
		Name:			"Windows Firewall Configuration",
		Status:			"CHECKING",
		Description:	"Analyzing Windows Firewall Configuration",
		Details:		make([]string, 0),
	}

	// Check firewall status for all profiles
	cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state")
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
	for profile, state := range profiles {
		if state {
			activeProfiles++
			result.Details = append(result.Details,
				fmt.Sprintf("%s %s profile is active", types.SymbolOK, profile))
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: %s profile is inactive", types.SymbolWarning, profile))
		}
	}

	// Check firewall rules if at least one profile is active
	if activeProfiles > 0 {
		cmd = exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name-all", "verbose")
		output, err := cmd.CombinedOutput()
		if err == nil {
			rules := parseWindowsFirewallRules(string(output))
			result.Details = append(result.Details, "\nActive Firewall Rules:")
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
			fmt.Sprintf("%s CRITICAL: Windows Firewall is completely disabled", types.SymbolWarning))
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