package security

import (
	"github.com/spf13/cobra"
)

var (
	securityVerbose			bool
	checkSSH				bool
	checkFirewall			bool
	checkUsers				bool
	checkFilePerms			string
)

// SecurityCmd represents the security audit command
var SecurityCmd = &cobra.Command{
	Use:	"security_audit",
	Short: 	"Perform a security audit",
	Long: 	"Perform a security audit based on the operating system.",
}

func init() {
	// Define flags for specific checks
	SecurityCmd.Flags().BoolVarP(&securityVerbose, "verbose", "v", false, "Run all check with detailed output")
	SecurityCmd.Flags().BoolVar(&checkSSH, "check-ssh", false, "Check SSH configuration")
	SecurityCmd.Flags().BoolVar(&checkFirewall, "check-firewall", false, "Check firewall rules")
	SecurityCmd.Flags().BoolVar(&checkUsers, "check-users", false, "List user accounts")
	SecurityCmd.Flags().StringVar(&checkFilePerms, "file-permissions", "", "Check permissions of specified file")
}