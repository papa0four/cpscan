// internal/security/checker/ssh.go
package checker

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

type (
	// SSHChecker defines interface for SSH configuration checking
	SSHChecker interface {
		Name() string
		Description() string
		Check(ctx context.Context) types.AuditResult
	}

	// UnixSSHChecker implements SSHChecker for Unix-like systems
	UnixSSHChecker struct {
		checkIdentity
		ConfigPaths []string
	}

	// WindowsSSHChecker implements SSHChecker for Windows systems
	WindowsSSHChecker struct {
		checkIdentity
		ConfigPath string
	}

	// sshConfig holds parsed SSH configuration settings
	sshConfig struct {
		rootLogin         bool
		passwordAuth      bool
		permRootFound     bool
		permPasswordFound bool
	}
)

// NewUnixSSHChecker creates a new Unix SSH checker with default paths
func NewUnixSSHChecker(osCtx registry.OSContext) *UnixSSHChecker {
	return &UnixSSHChecker{
		checkIdentity: checkIdentity{
			domain:   "SSH Configuration",
			analyzes: "SSH configuration and security settings",
			osCtx:    osCtx,
		},
		ConfigPaths: []string{
			"/etc/ssh/sshd_config",
			"/private/etc/ssh/sshd_config", // macOS path
		},
	}
}

// NewWindowsSSHChecker creates a new Windows SSH checker
func NewWindowsSSHChecker(osCtx registry.OSContext) *WindowsSSHChecker {
	return &WindowsSSHChecker{
		checkIdentity: checkIdentity{
			domain:   "SSH Configuration",
			analyzes: "SSH configuration and security settings",
			osCtx:    osCtx,
		},
		ConfigPath: "C:\\ProgramData\\ssh\\sshd_config",
	}
}

// Check implements SSHChecker interface for Unix systems
func (s *UnixSSHChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        s.Name(),
		Status:      types.StatusChecking,
		Description: s.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	var file *os.File
	var err error
	var configPath string

	// Try each possible config path
	for _, path := range s.ConfigPaths {
		if file, err = os.Open(path); err == nil { // #nosec G304 -- paths hardcoded in NewUnixSSHChecker; file contents parsed defensively for two known fields only
			configPath = path
			defer file.Close() // nolint:errcheck // read-only file; close error does not affect scan results
			break
		}
	}

	if file == nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("SSH configuration file not found in any of: %v", s.ConfigPaths)
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: No SSH configuration file found", types.SymbolError))
		emitFinding(&result, s.osCtx, "ssh.config_not_found")
		return result
	}

	// Parse SSH Configuration
	config := &sshConfig{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "PermitRootLogin":
			config.permRootFound = true
			config.rootLogin = (fields[1] != "no")
		case "PasswordAuthentication":
			config.permPasswordFound = true
			config.passwordAuth = (fields[1] == "yes")
		}
	}

	if err := scanner.Err(); err != nil {
		result.Status = types.StatusError
		result.Description = fmt.Sprintf("Error reading SSH configuration: %v", err)
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: Failed to read configuration", types.SymbolError))
		return result
	}

	// Build detailed results
	result.Details = append(result.Details,
		fmt.Sprintf("%s Configuration file: %s", types.SymbolInfo, configPath))

	// Check root Login configuration
	if config.permRootFound {
		if config.rootLogin {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Root login is permitted", types.SymbolWarning))
			emitFinding(&result, s.osCtx, "ssh.root_login_permitted")
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Root login is disabled", types.SymbolOK))
		}
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: PermitRootLogin setting not found (defaults may apply)", types.SymbolWarning))
		emitFinding(&result, s.osCtx, "ssh.permit_root_login_not_set")
	}

	// Check password authentication
	if config.permPasswordFound {
		if config.passwordAuth {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Password authentication is enabled", types.SymbolWarning))
			emitFinding(&result, s.osCtx, "ssh.password_auth_enabled")
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Password authentication is disabled", types.SymbolOK))
		}
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: PasswordAuthentication setting not found (defaults may apply)", types.SymbolWarning))
		emitFinding(&result, s.osCtx, "ssh.password_auth_not_set")
	}

	result.Status = types.StatusCompleted
	result.Description = "SSH configuration analysis complete"
	return result
}

// Check implements SSHChecker interface for Windows systems
func (s *WindowsSSHChecker) Check(ctx context.Context) types.AuditResult {
	result := types.AuditResult{
		Name:        s.Name(),
		Status:      types.StatusChecking,
		Description: s.Description(),
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	sshdInstalled := false

	// Check OpenSSH installation
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-Service -Name sshd -ErrorAction SilentlyContinue).Status")
	output, err := cmd.CombinedOutput()
	serviceStatus := strings.TrimSpace(string(output))
	if err == nil && serviceStatus != "" {
		sshdInstalled = true
		switch serviceStatus {
		case "Running":
			result.Details = append(result.Details,
				fmt.Sprintf("%s OpenSSH Server is installed and running", types.SymbolOK))
		case "Stopped":
			result.Details = append(result.Details,
				fmt.Sprintf("%s OpenSSH Server is installed but not running", types.SymbolWarning))
			emitFinding(&result, s.osCtx, "ssh.server_not_running")
		default:
			result.Details = append(result.Details,
				fmt.Sprintf("%s OpenSSH Server service state: %s", types.SymbolInfo, serviceStatus))
		}
	}

	const sshdBinaryPath = `C:\Windows\System32\OpenSSH\sshd.exe`
	if !sshdInstalled {
		if _, err := os.Stat(sshdBinaryPath); err == nil {
			sshdInstalled = true
			result.Details = append(result.Details,
				fmt.Sprintf("%s OpenSSH Server binary found (service not detected)", types.SymbolInfo))
		}
	}

	if !sshdInstalled {
		result.Details = append(result.Details,
			fmt.Sprintf("%s OpenSSH Server is not installed", types.SymbolInfo))
	}

	// Parse sshd_config if installed
	if sshdInstalled {
		if _, err := os.Stat(s.ConfigPath); err == nil {
			file, err := os.Open(s.ConfigPath) // #nosec G304 -- path set in NewWindowsSSHChecker to a hardcoded system location
			if err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("%s ERROR: Cannot read OpenSSH configuration: %v", types.SymbolError, err))
			} else {
				defer file.Close() // nolint:errcheck // read-only file; close error does not affect scan results

				config := &sshConfig{}
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}

					fields := strings.Fields(line)
					if len(fields) < 2 {
						continue
					}

					switch fields[0] {
					case "PermitRootLogin":
						config.permRootFound = true
						config.rootLogin = (fields[1] != "no")
					case "PasswordAuthentication":
						config.permPasswordFound = true
						config.passwordAuth = (fields[1] == "yes")
					}
				}

				if err := scanner.Err(); err != nil {
					result.Details = append(result.Details,
						fmt.Sprintf("%s ERROR: Failed to read OpenSSH configuration: %v",
							types.SymbolError, err))
				}

				if config.permRootFound {
					if config.rootLogin {
						result.Details = append(result.Details,
							fmt.Sprintf("%s WARNING: Root login is permitted", types.SymbolWarning))
						emitFinding(&result, s.osCtx, "ssh.root_login_permitted")
					} else {
						result.Details = append(result.Details,
							fmt.Sprintf("%s Root login is disabled", types.SymbolOK))
					}
				}

				if config.permPasswordFound {
					if config.passwordAuth {
						result.Details = append(result.Details,
							fmt.Sprintf("%s WARNING: Password authentication is enabled", types.SymbolWarning))
						emitFinding(&result, s.osCtx, "ssh.password_auth_enabled")
					} else {
						result.Details = append(result.Details,
							fmt.Sprintf("%s Password authentication is disabled", types.SymbolOK))
					}
				}
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: OpenSSH configuration file not found", types.SymbolWarning))
			emitFinding(&result, s.osCtx, "ssh.config_missing")
		}
	}

	// Check for PuTTY installation
	if _, err := os.Stat(`C:\Program Files\PuTTY\putty.exe`); err == nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s PuTTY is installed", types.SymbolInfo))

		cmd = exec.CommandContext(ctx, "reg", "query", `HKCU\Software\SimonTatham\PuTTY\Sessions`)
		output, err := cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			sessions := strings.Split(string(output), "\n")
			result.Details = append(result.Details,
				fmt.Sprintf("%s PuTTY configured sessions:", types.SymbolInfo))
			for _, session := range sessions {
				if strings.TrimSpace(session) != "" {
					result.Details = append(result.Details,
						fmt.Sprintf(" - %s", strings.TrimSpace(session)))
				}
			}
		}
	}

	result.Status = types.StatusCompleted
	result.Description = "Windows SSH Configuration analysis complete"
	return result
}
