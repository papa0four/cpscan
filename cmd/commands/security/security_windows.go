//go:build windows
// +build windows

package security                                                                                                          
                                                                                                                       
import (                                                                                                               
    "fmt"                                                                                                              
    "runtime"                                                                                                          
                                                                                                                       
    "github.com/papa0four/cpscan/internal/security/audit"
)                                                                                                                                                                                                                                           
                                                                                                                       
func init() {
    SecurityCmd.Run = runWindowsAudit
}

func runWindowsAudit(cmd *cobra.Command, args []string) {
    os := runtime.GOOS
    fmt.Printf("Running security audit for OS: %s\n", os)

    checks := []string{}
    if checkSSH {
        checks = append(checks, "ssh")
    }
    if checkFirewall {
        checks = append(checks, "firewall")
    }
    if checkUsers {
        checks = append(checks, "users")
    }
    if checkFilePerms != "" {
        checks = append(checks, "file-permissions")
    }

    if len(checks) == 0 && !securityVerbose {
        fmt.Println("No specific checks provided. Showing help:")
        audit.PrintHelpMessage()
        return
    }

    audit.RunWindowsAudit(securityVerbose, checks...)
}