package audit

import "fmt"

// PrintHelpMessage provides help for available submodule options
func PrintHelpMessage() {
	fmt.Println("Usage: cpscan security_audit [options]")
	fmt.Println("Perform a security audit. Available options:")
	fmt.Println("	--check-firewall			Check firewall configuration")
	fmt.Println("	--check-users				List user accounts")
	fmt.Println("	--check-ssh					Check SSH configuration")
	fmt.Println("	--file-permissions FILE		Check permissions for specified file/directory")
	fmt.Println("	-v, --verbose				Run all checks with detailed output")
}

// runCheck is a helper function to format output for each check
func runCheck(title string, checkFunc func() string, verbose bool) {
	if verbose {
		fmt.Println("\n=======================================")
		fmt.Println("==", title)
		fmt.Println("=======================================")
	}
	result := checkFunc()
	fmt.Println(result)
	if verbose {
		fmt.Println("=======================================")
	}
}