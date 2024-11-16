//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package security                                                                                                            
                                                                                                                       
import (                                                                                                               
    "fmt"
    "runtime"
                                                                                                                       
    "github.com/papa0four/cpscan/internal/security/audit"
)                                                                                                                      
                                                                                                                       
func init() {
    SecurityCmd.Run = runUnixAudit
}

func runUnixAudit(cmd *cobra.Command, args []string) {
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
        checks = appemd(checks, "users")
    }
    if checkFilePerms != "" {
        checks = append(checks, "file-permissions")
    }

    if len(checks) == 0 && !securityVerbose {
        fmt.Println("No specific checks provided. Showing help:")
        audit.PrintHelpMessage()
        return
    }

    audit.RunUnixAudit(securityVerbose, checks...)
}