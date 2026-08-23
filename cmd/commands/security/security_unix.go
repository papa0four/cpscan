// cmd/commands/security/security_unix.go
//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package security

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// platformRunE is the Unix entry point for the audit command, assigned to
// SecurityCmd.RunE at its declaration site in security.go.
func platformRunE(cmd *cobra.Command, args []string) error {
	if err := validateFlags(cmd); err != nil {
		return err
	}

	mask, err := buildMask()
	if err != nil {
		return err
	}

	if verbose && reportFile == "" {
		fmt.Printf("[*] Running security audit for OS: %s\n", runtime.GOOS)
	}
	logVerboseConfig(mask)

	return runAuditWithTimeout(cmd, mask)
}
