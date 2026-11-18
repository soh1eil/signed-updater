//go:build windows

package signing

import "io/fs"

// checkKeyPerm is a no-op on Windows: POSIX mode bits do not describe NTFS
// ACLs. Protect the key file with an ACL that grants only the signing account.
func checkKeyPerm(path string, mode fs.FileMode) error { return nil }
