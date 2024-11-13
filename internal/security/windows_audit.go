// +build windows

package security

import (
    "fmt"
    "os/exec"
    "github.com/papa0four/cpscan/internal/softwarelist"
)

func RunWindowsAudit() {
    fmt.Println("Running Windows-based security audit...")

    checkFirewallStatus()
    checkUserAccounts()
    checkInstalledServices() // Uses the softwarelist package to get installed services
}

func checkFirewallStatus() {
    cmd := exec.Command("netsh", "advfirewall", "show", "allprofiles")
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println("Error checking firewall status:", err)
    } else {
        fmt.Println("Firewall status:\n", string(output))
    }
}

func checkUserAccounts() {
    cmd := exec.Command("net", "user")
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Println("Error checking user accounts:", err)
    } else {
        fmt.Println("User accounts:\n", string(output))
    }
}

func checkInstalledServices() {
    fmt.Println("Checking installed services on Windows...")

    // Use the softwarelist package to retrieve installed services/software
    services, err := softwarelist.GetInstalledSoftware()
    if err != nil {
        fmt.Println("Error retrieving software list:", err)
        return
    }

    for _, service := range services {
        fmt.Printf("Service: %s, Version: %s\n", service.Name, service.Version)
    }
}

