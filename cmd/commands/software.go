// cmd/commands/software.go
package cmd

import (
    "fmt"
    "github.com/spf13/cobra"
    "github.com/papa0four/cpscan/internal/softwarelist"
)

//softwareCmd represents the software command
var softwareCmd = &cobra.Command{
    Use: "software",
    Short: "List installed software on the host",
    Long: `The software command gathers and lists the installed software packages from the host operating system, including version details where available.`,
    Run: func(cmd *cobra.Command, args []string) {
        // call the function to get installed software
        software, err := softwarelist.GetInstalledSoftware()
        if err != nil {
            fmt.Println("Error fetching installed software:", err)
            return
        }
        // Print the result
        fmt.Println(software)
    },
}

func init() {
    // Register the software command under the root command
    RootCmd.AddCommand(softwareCmd)
}
