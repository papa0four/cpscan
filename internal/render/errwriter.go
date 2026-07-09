// internal/render/errwriter.go
package render

import (
	"fmt"
	"io"
)

// errWriter wraps an io.Writer and remembers the first write error, letting
// rendering code write unconditionally and report the error once. This is
// the same pattern bufio.Writer and text/tabwriter use internally.
type errWriter struct {
	w   io.Writer
	err error
}

// printf formats to the underlying writer unless a previous write failed,
// in which case it is a no-op.
func (ew *errWriter) printf(format string, args ...any) {
	if ew.err != nil {
		return
	}
	_, ew.err = fmt.Fprintf(ew.w, format, args...)
}
