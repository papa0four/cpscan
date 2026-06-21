// internal/report/report_unix.go
//go:build linux || darwin || freebsd || openbsd
// +build linux darwin freebsd openbsd

package report

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
)

// systemRoots are refused because they sensitive to an attacker
var systemRoots = []string{
	"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/boot", "/sys", "/proc", "/dev", "/root",
	"/run", "/var/run", "/var/spool/cron",
	"/System", "/Library/LaunchDaemons", "/Library/LaunchAgents",
}

// userPersistence are home-relative locations that are refused due to their sensitivity
var userPersistence = []string{
	".ssh", ".config/autostart", ".config/systemd/user",
	".bashrc", ".bash_profile", ".profile", ".zshrc",
	"Library/LaunchAgents",
}

// canonicalParent resolves the parent chain so the location checks compare
// against the real directory
func canonicalParent(parent string) (string, error) {
	real, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrParentMissing, parent)
	}
	return real, nil
}

func refusedReason(target string) string {
	for _, root := range systemRoots {
		if pathWithin(target, root) {
			return root
		}
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	for _, rel := range userPersistence {
		base := filepath.Join(home, rel)
		if pathWithin(target, base) {
			return base
		}
	}
	return ""
}

// isElevated reports root, where a write can land anywhere and the tool becomes
// a privileged write primitive.
func isElevated() (bool, error) {
	return os.Geteuid() == 0, nil
}

// withinAllowlist permits an elevated write only under roots the operator clearly owns
func withinAllowlist(target string) (bool, error) {
	for _, root := range allowlistRoots() {
		real, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		if pathWithin(target, real) {
			return true, nil
		}
	}
	return false, nil
}

func allowlistRoots() []string {
	roots := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil {
		roots = append(roots, cwd)
	}
	if home := invokingUserHome(); home != "" {
		roots = append(roots, home)
	}
	return roots
}

// invokingUserHome returns the home of the user behind sudo, so an elevated run
// can still target that user's space rather than only root's.
func invokingUserHome() string {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		return ""
	}
	u, err := user.Lookup(name)
	if err != nil {
		return ""
	}
	return u.HomeDir
}

// openAndWrite writes data to target with no-follow semantics
func openAndWrite(target string, data []byte) error {
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink", ErrNotRegularFile)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s", ErrNotRegularFile, target)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat destination: %w", err)
	}

	// target is validated through the guard pipeline above and opened no-follow.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, reportFileMode) // #nosec G304 -- validated, no-follow write
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		if err := f.Close(); err != nil {
			return fmt.Errorf("close file: %w", err)
		}
		return fmt.Errorf("write report: %w", err)
	}
	return f.Close()
}

// parentWritableByOthers reports whether dir grants write to group or other
func parentWritableByOthers(dir string) (bool, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	const groupOrOtherWrite = 0022
	return info.Mode().Perm()&groupOrOtherWrite != 0, nil
}
