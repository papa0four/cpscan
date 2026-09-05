//go:build windows

// cmd/commands/security/security_windows.go

package security

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// platformRunE is the windows entry point for the audit command, bound to RunE in
// NewCmd.
func (c *auditCmd) platformRunE(cmd *cobra.Command, args []string) error {
	if err := c.validateFlags(cmd); err != nil {
		return err
	}

	mask, err := c.buildMask()
	if err != nil {
		return err
	}

	if c.verbose && c.reportFile == "" {
		fmt.Printf("[*] Running security audit for OS: %s\n", runtime.GOOS)
	}
	c.logVerboseConfig(mask)

	return c.runAuditWithTimeout(cmd, mask)
}
