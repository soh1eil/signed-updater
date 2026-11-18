//go:build !windows

package signing

import (
	"fmt"
	"io/fs"
)

// checkKeyPerm refuses key files readable or writable by group or others
// (anything outside 0600/0400 style modes).
func checkKeyPerm(path string, mode fs.FileMode) error {
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("key file %s has mode %04o: refusing, group/world access is not allowed (chmod 600)", path, mode.Perm())
	}
	return nil
}
