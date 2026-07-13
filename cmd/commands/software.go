// cmd/commands/software.go
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/papa0four/orkowatch/internal/softwarelist"
)

// softwareCmd represents the software command
var softwareCmd = &cobra.Command{
	Use:   "software",
	Short: "List installed software on the host",
	Long:  `The software command gathers and lists the installed software packages from the host operating system, including version details where available.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		software, err := softwarelist.GetInstalledSoftware(cmd.Context())
		if err != nil {
			return fmt.Errorf("software: %w", err)
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), software)
		if err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(softwareCmd)
}
