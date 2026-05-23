// internal/softwarelist/softwarelist.go
package softwarelist

import "fmt"

// GetInstalledSoftware retrieves a list of installed software based on the OS
func GetInstalledSoftware() (string, error) {
	result, err := getPlatformSoftware()
	if err != nil {
		return "", fmt.Errorf("software enumeration failed: %w", err)
	}
	return result, nil
}
