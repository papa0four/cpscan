// internal/security/checker/ssh.go
package checker

import (
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "github.com/papa0four/cpscan/internal/security/types"
)

// SSHChecker defines interface for SSH configuration checking
type SSHChecker interface {
	Check() types.AuditResult
}

// UnixSSHChecker implements SSHChecker for Unix-like systems
type UnixSSHChecker struct {
	ConfigPaths []string
}

// WindowsSSHChecker implements SSHChecker for Windows systems
type WindowsSSHChecker struct {
	ConfigPath string
}

// NewUnixSSHChecker creates a new Unix SSH checker with default paths
func NewUnixSSHChecker() *UnixSSHChecker {
	return &UnixSSHChecker{
		ConfigPaths: []string{
			"/etc/ssh/sshd_config",
			"/private/etc/ssh/sshd_config", // macOS path
		},
	}
}

// NewWindowsSSHChecker creates a new Windows SSH checker
func NewWindowsSSHChecker() *WindowsSSHChecker {
	return &WindowsSSHChecker{
		ConfigPath: "C:\\ProgramData\\ssh\\sshd_config",
	}
}

// sshConfig holds parsed SSH configuration settings
type sshConfig struct {
	rootLogin			bool
	passwordAuth		bool
	permRootFound		bool
	permPasswordFound	bool
}

// Check implements SSHChecker interface for Unix systems
func (s *UnixSSHChecker) Check() types.AuditResult {
	result := types.AuditResult{
		Name:			"SSH Configuration",
		Status:			"CHECKING",
		Description:	"Analyzing SSH Configuration settings",
		Details:		make([]string, 0),
	}

	var file *os.File
	var err error
	var configPath string

	// Try each possible config path
	for _, path := range s.ConfigPaths {
		if file, err = os.Open(path); err == nil {
			configPath = path
			defer file.Close()
			break
		}
	}

	if file == nil {
		result.Status = "ERROR"
		result.Description = fmt.Sprintf("SSH configuration file not found in any of: %v", s.ConfigPaths)
		result.Details = append(result.Details,
			fmt.Sprintf("%s ERROR: No SSH configuration file found", types.SymbolError))
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
		result.Status = "Error"
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
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s Root login is disabled", types.SymbolOK))
		}
 	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: PermitRootLogin setting not found (defaults may apply)", types.SymbolWarning))
	}

	// Check password authentication
	if config.permPasswordFound {
		if config.passwordAuth {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: Password authentication is enabled", types.SymbolWarning))
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("% Password authentication is disabled", types.SymbolOK))
		}
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s WARNING: PasswordAuthentication setting not found (defaults may apply)", types.SymbolWarning))
	}

	result.Status = "COMPLETED"
	result.Description = "SSH configuration analysis complete"
	return result
}

// Check implements SSHChecker interface for Windows systems
func (s *WindowsSSHChecker) Check() types.AuditResult {
	result := types.AuditResult{
		Name:			"Windows SSH Configuration",
		Status:			"CHECKING",
		Description:	"Analyzing Windows SSH configuration",
		Details:		make([]string, 0),
	}

	// Check OpenSSH installation
	cmd := exec.Command("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-Command",
		"Get-WindowsCapability -Online | Where-Object {$_.Name -like '*OpenSSH.Server*' }")
	output, err := cmd.CombinedOutput()

	if err != nil {
		result.Status = "ERROR"
		result.Description = "Failed to check OpenSSH installation"
		result.Details = append(result.Details,
			fmt.Sprintf("%s Error checking OpenSSH installation: %v", types.SymbolError, err))
		return result
	}

	// Process OpenSSH installation status
	if strings.Contains(string(output), "State : Installed") {
		result.Details = append(result.Details,
			fmt.Sprintf("%s OpenSSH Server is installed", types.SymbolOK))

		// Check OpenSSH configuration if installed
		if _, err := os.Stat(s.ConfigPath); err == nil {
			file, err := os.Open(s.ConfigPath)
			if err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("%s ERROR: Cannot read OpenSSH configuration: %v", types.SymbolError, err))
			} else {
				defer file.Close()
				result.Details = append(result.Details,
					fmt.Sprintf("%s Analyzing OpenSSH configuration...", types.SymbolInfo))

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

				// Report OpenSSH configuration findings
				if config.permRootFound {
					if config.rootLogin {
						result.Details = append(result.Details,
							fmt.Sprintf("%s WARNING: Root login is permitted", types.SymbolWarning))
					} else {
						result.Details = append(result.Details,
							fmt.Sprintf("%s Root login is disabled", types.SymbolOK))
					}
				}

				if config.permPasswordFound {
					if config.passwordAuth {
						result.Details = append(result.Details,
							fmt.Sprintf("%s WARNING: Password authentication is enabled", types.SymbolWarning))
					} else {
						result.Details = append(result.Details,
							fmt.Sprintf("%s Password authentication is disabled", types.SymbolOK))
					}
				}
			}
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("%s WARNING: OpenSSH configuration file not found", types.SymbolWarning))
		}
	} else {
		result.Details = append(result.Details,
			fmt.Sprintf("%s OpenSSH Server is not installed", types.SymbolInfo))
	}

	// Check for PuTTY installation
	if _, err := os.Stat("C:\\Program Files\\PuTTY\\putty.exe"); err == nil {
		result.Details = append(result.Details,
			fmt.Sprintf("%s PuTTY is installed", types.SymbolInfo))

		// Check PuTTY registry settings
		cmd = exec.Command("reg", "query", "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions")
		output, err := cmd.CombinedOutput()
		if err == nil && len(output) > 0 {
			sessions := strings.Split(string(output), "\n")
			result.Details = append(result.Details,
				fmt.Sprintf("%s PuTTY configured sessions:", types.SymbolInfo))
			for _, session := range sessions {
				if strings.TrimSpace(session) != "" {
					result.Details = append(result.Details, fmt.Sprintf(" - %s", strings.TrimSpace(session)))
				}
			}
		}
	}

	result.Status = "COMPLETED"
	result.Description = "Windows SSH Configuration analysis complete"
	return result
}
