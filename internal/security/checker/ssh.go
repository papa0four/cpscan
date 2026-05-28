// internal/security/checker/ssh.go
package checker

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/papa0four/orkowatch/internal/security/registry"
	"github.com/papa0four/orkowatch/internal/security/types"
)

// SSHChecker defines interface for SSH configuration checking
type SSHChecker interface {
	Check() types.AuditResult
}

// UnixSSHChecker implements SSHChecker for Unix-like systems
type UnixSSHChecker struct {
	ConfigPaths []string
	ctx         registry.OSContext
}

// WindowsSSHChecker implements SSHChecker for Windows systems
type WindowsSSHChecker struct {
	ConfigPath string
	ctx        registry.OSContext
}

// NewUnixSSHChecker creates a new Unix SSH checker with default paths
func NewUnixSSHChecker(ctx registry.OSContext) *UnixSSHChecker {
	return &UnixSSHChecker{
		ConfigPaths: []string{
			"/etc/ssh/sshd_config",
			"/private/etc/ssh/sshd_config", // macOS path
		},
	}
}

// NewWindowsSSHChecker creates a new Windows SSH checker
func NewWindowsSSHChecker(ctx registry.OSContext) *WindowsSSHChecker {
	return &WindowsSSHChecker{
		ConfigPath: "C:\\ProgramData\\ssh\\sshd_config",
		ctx:        ctx,
	}
}

// sshConfig holds parsed SSH configuration settings
type sshConfig struct {
	rootLogin         bool
	passwordAuth      bool
	permRootFound     bool
	permPasswordFound bool
}

// Check implements SSHChecker interface for Unix systems
func (s *UnixSSHChecker) Check() types.AuditResult {
	result := types.AuditResult{
		Name:        "SSH Configuration",
		Status:      "CHECKING",
		Description: "Analyzing SSH Configuration settings",
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
		result.Status = "ERROR"
		result.Description = fmt.Sprintf("SSH configuration file not found in any of: %v", s.ConfigPaths)
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: No SSH configuration file found", types.SymbolError))
		if def, ok := registry.Lookup(s.ctx, "ssh.config_not_found"); ok {
			result.Findings = append(result.Findings, types.Finding{
				Title:       def.Title,
				Severity:    def.Severity,
				Description: def.Description,
				Impact:      def.Impact,
				Resolution:  def.Resolution,
			})
		}
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
		result.Status = "ERROR"
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
			if def, ok := registry.Lookup(s.ctx, "ssh.root_login_permitted"); ok {
				result.Findings = append(result.Findings, types.Finding{
					Title:       def.Title,
					Severity:    def.Severity,
					Description: def.Description,
					Impact:      def.Impact,
					Resolution:  def.Resolution,
				})
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Root login is disabled", types.SymbolOK))
		}
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: PermitRootLogin setting not found (defaults may apply)", types.SymbolWarning))
		if def, ok := registry.Lookup(s.ctx, "ssh.permit_root_login_not_set"); ok {
			result.Findings = append(result.Findings, types.Finding{
				Title:       def.Title,
				Severity:    def.Severity,
				Description: def.Description,
				Impact:      def.Impact,
				Resolution:  def.Resolution,
			})
		}
	}

	// Check password authentication
	if config.permPasswordFound {
		if config.passwordAuth {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Password authentication is enabled", types.SymbolWarning))
			if def, ok := registry.Lookup(s.ctx, "ssh.password_auth_enabled"); ok {
				result.Findings = append(result.Findings, types.Finding{
					Title:       def.Title,
					Severity:    def.Severity,
					Description: def.Description,
					Impact:      def.Impact,
					Resolution:  def.Resolution,
				})
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Password authentication is disabled", types.SymbolOK))
		}
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: PasswordAuthentication setting not found (defaults may apply)", types.SymbolWarning))
		if def, ok := registry.Lookup(s.ctx, "ssh.password_auth_not_set"); ok {
			result.Findings = append(result.Findings, types.Finding{
				Title:       def.Title,
				Severity:    def.Severity,
				Description: def.Description,
				Impact:      def.Impact,
				Resolution:  def.Resolution,
			})
		}
	}

	result.Status = "COMPLETED"
	result.Description = "SSH configuration analysis complete"
	return result
}

// Check implements SSHChecker interface for Windows systems
func (s *WindowsSSHChecker) Check() types.AuditResult {
	result := types.AuditResult{
		Name:        "Windows SSH Configuration",
		Status:      "CHECKING",
		Description: "Analyzing Windows SSH configuration",
		Details:     make([]string, 0),
		Findings:    make([]types.Finding, 0),
	}

	sshdInstalled := false

	// Check OpenSSH installation
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
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
			if def, ok := registry.Lookup(s.ctx, "ssh.server_not_running"); ok {
				result.Findings = append(result.Findings, types.Finding{
					Title:       def.Title,
					Severity:    def.Severity,
					Description: def.Description,
					Impact:      def.Impact,
					Resolution:  def.Resolution,
				})
			}
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
						if def, ok := registry.Lookup(s.ctx, "ssh.root_login_permitted"); ok {
							result.Findings = append(result.Findings, types.Finding{
								Title:       def.Title,
								Severity:    def.Severity,
								Description: def.Description,
								Impact:      def.Impact,
								Resolution:  def.Resolution,
							})
						}
					} else {
						result.Details = append(result.Details,
							fmt.Sprintf("%s Root login is disabled", types.SymbolOK))
					}
				}

				if config.permPasswordFound {
					if config.passwordAuth {
						result.Details = append(result.Details,
							fmt.Sprintf("%s WARNING: Password authentication is enabled", types.SymbolWarning))
						if def, ok := registry.Lookup(s.ctx, "ssh.password_auth_enabled"); ok {
							result.Findings = append(result.Findings, types.Finding{
								Title:       def.Title,
								Severity:    def.Severity,
								Description: def.Description,
								Impact:      def.Impact,
								Resolution:  def.Resolution,
							})
						}
					} else {
						result.Details = append(result.Details,
							fmt.Sprintf("%s Password authentication is disabled", types.SymbolOK))
					}
				}
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: OpenSSH configuration file not found", types.SymbolWarning))
			if def, ok := registry.Lookup(s.ctx, "ssh.config_missing"); ok {
				result.Findings = append(result.Findings, types.Finding{
					Title:       def.Title,
					Severity:    def.Severity,
					Description: def.Description,
					Impact:      def.Impact,
					Resolution:  def.Resolution,
				})
			}
		}
	}

	// Check for PuTTY installation
	if _, err := os.Stat(`C:\Program Files\PuTTY\putty.exe`); err == nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s PuTTY is installed", types.SymbolInfo))

		cmd = exec.Command("reg", "query", `HKCU\Software\SimonTatham\PuTTY\Sessions`)
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

	result.Status = "COMPLETED"
	result.Description = "Windows SSH Configuration analysis complete"
	return result
}
