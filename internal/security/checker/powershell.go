// internal/security/checker/powershell.go

package checker

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// parsePowerShellCSV parses ConvertTo-Csv output into data records, dropping
// the header row. PowerShell emits RFC 4180 CSV terminated with CRLF, so
// fields are quoted and may contain commas; splitting on "," and "\n" corrupts
// the last field of every row and any field holding a comma. fields is the
// expected column count, enforced on every record so a changed projection
// fails here rather than silently shifting values into the wrong struct
// members.
func parsePowershellCSV(output []byte, fields int) ([][]string, error) {
	reader := csv.NewReader(bytes.NewReader(output))
	reader.FieldsPerRecord = fields

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse CSV output: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}

	return records[1:], nil
}

// psError attaches the captured stderr to an exec failure. PowerShell reports
// why a cmdlet failed on stderr, and that text is the difference between an
// actionable diagnostic and "exit status 1".
func psError(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
	}
	return err
}
