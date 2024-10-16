// +build linux darwin

package security

import (
    "fmt"
    "os/exec"
    "github.com/papa0four/cpscan/internal/softwarelist"
)

func RunUnixAudit() {
    fmt.Println("Running Unix-based security audit...")

    checkSSHConfig()
    checkFirewallRules()
    checkFilePermissions()
    checkUserAccounts()
    checkInstalledServices()
}

func checkSSHConfig() {
    // Example SSH configuration check for Linux/Mac/Unix
    cmd := exec.Command("grep", "-E", "^PermitRootLogin", "/etc/ssh/sshd_config")
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println("Error checking SSH configuration:", err)
    } else if string(output) == "PermitRootLogin no" {
        fmt.Println("SSH root login disabled [OK]")
    } else {
        fmt.Println("SSH root login enabled [WARNING]")
    }
}

func checkFirewallRules() {
    // Example firewall check for iptables or ufw
    cmd := exec.Command("iptables", "-L")
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println("Error checking firewall:", err)
    } else {
        fmt.Println("Firewall rules:\n", string(output))
    }
}

func checkFilePermissions() {
    // Example file permission check for sensitive files like /etc/passwd
    cmd := exec.Command("ls", "-l", "/etc/passwd")
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println("Error checking file permissions:", err)
    } else {
        fmt.Println("File permissions:\n", string(output))
    }
}

func checkUserAccounts() {
    // Example user account check for Linux/Unix
    cmd := exec.Command("awk", "-F:", "{print $1}", "/etc/passwd")
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println("Error checking user accounts:", err)
    } else {
        fmt.Println("User accounts:\n", string(output))
    }
}

func checkInstalledServices() {
    // Example service check using existing software list
    fmt.Println("Checking installed services...")
    // Run software listing scan                               
    software, err := softwarelist.GetInstalledSoftware()       
    if err != nil {                                            
        fmt.Println("Error fetching installed software:", err) 
        return                                                 
    }                                                          
    fmt.Println("Installed Software:\n", software)
}

