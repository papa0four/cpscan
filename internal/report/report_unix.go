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

const reportFileMode = 0600

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

	homes := make([]string, 0, maxOperatorHomes)
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		homes = append(homes, home)
	}
	if invoker := invokingUserHome(); invoker != "" && (len(homes) == 0 || invoker != homes[0]) {
		homes = append(homes, invoker)
	}
	for _, home := range homes {
		for _, rel := range userPersistence {
			base := filepath.Join(home, rel)
			if pathWithin(target, base) {
				return base
			}
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
	roots := make([]string, 0, maxOperatorHomes)
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
func openAndWrite(target string, data []byte) (err error) {
	if info, lerr := os.Lstat(target); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink", ErrNotRegularFile)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s", ErrNotRegularFile, target)
		}
	} else if !errors.Is(lerr, os.ErrNotExist) {
		return fmt.Errorf("stat destination: %w", lerr)
	}

	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, reportFileMode) // #nosec G304 -- target validated through the guard pipeline and opened no-follow
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	finfo, serr := f.Stat()
	if serr != nil {
		return fmt.Errorf("stat opened destination: %w", serr)
	}
	if !finfo.Mode().IsRegular() {
		return fmt.Errorf("%w: destination replaced during open", ErrNotRegularFile)
	}

	if _, werr := f.Write(data); werr != nil {
		return fmt.Errorf("write report: %w", werr)
	}
	return nil
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
