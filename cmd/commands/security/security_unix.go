// cmd/commands/security/security_unix.go
//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package security

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func init() {
	SecurityCmd.RunE = runUnixAudit
}

func runUnixAudit(cmd *cobra.Command, args []string) error {
	checks := buildChecks()

	if len(checks) == 0 && !verbose {
		fmt.Println("No checks specified. User --help to see available options.")
		return cmd.Help()
	}

	if err := validateFlags(); err != nil {
		return err
	}

	if verbose {
		fmt.Printf("[*] Running security audit for OS: %s\n", runtime.GOOS)
	}
	logVerboseConfig(checks)

	return runAuditWithTimeout(checks)
}
