// cmd/commands/security/security_windows.go
//go:build windows
// +build windows

package security

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func init() {
	SecurityCmd.RunE = runWindowsAudit
}

func runWindowsAudit(cmd *cobra.Command, args []string) error {
	if err := validateFlags(cmd); err != nil {
		return err
	}

	mask, err := buildMask()
	if err != nil {
		return err
	}

	if verbose {
		fmt.Printf("[*] Running security audit for OS: %s\n", runtime.GOOS)
	}
	logVerboseConfig(mask)

	return runAuditWithTimeout(cmd, mask)
}
