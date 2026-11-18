// Package signing implements the Ed25519 signing scheme shared by the updsign
// tool and the signed_updater Dart package.
//
// A signature covers a canonical, newline-separated message that binds a
// domain-separation context to every security-relevant manifest field
// (version, build, platform, artifact digest, size and notes digest). Signing
// the digest alone would let an attacker relabel an old, validly signed
// artifact as a new version; signing the whole tuple closes that.
package signing

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MaxNotesBytes bounds the release notes carried in a manifest entry.
	MaxNotesBytes = 16 * 1024
	// MaxSize bounds the declared artifact size (1 TiB).
	MaxSize = int64(1) << 40
	// MaxBuild bounds the build number.
	MaxBuild = int64(1)<<31 - 1
)

var (
	versionRe  = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,3}$`)
	platformRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	sha256Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sigRe      = regexp.MustCompile(`^[0-9a-f]{128}$`)
)

// ValidVersion reports whether v is 1 to 4 dot-separated numeric components
// without leading zeros, for example "1.4.0".
func ValidVersion(v string) error {
	if !versionRe.MatchString(v) {
		return fmt.Errorf("invalid version %q: want 1-4 numeric components like 1.2.3", v)
	}
	return nil
}

// ValidPlatform reports whether p is a lowercase platform label such as
// "windows", "linux-x64" or "macos".
func ValidPlatform(p string) error {
	if !platformRe.MatchString(p) {
		return fmt.Errorf("invalid platform %q: want [a-z0-9][a-z0-9_-]{0,31}", p)
	}
	return nil
}

// ValidSHA256 reports whether s is a lowercase hex SHA-256 digest.
func ValidSHA256(s string) error {
	if !sha256Re.MatchString(s) {
		return errors.New("invalid sha256: want 64 lowercase hex characters")
	}
	return nil
}

// ValidSig reports whether s is a lowercase hex Ed25519 signature.
func ValidSig(s string) error {
	if !sigRe.MatchString(s) {
		return errors.New("invalid sig: want 128 lowercase hex characters")
	}
	return nil
}

// ValidContext reports whether c is acceptable as a signing context: 1-64
// printable ASCII characters. Newlines are rejected because the context is the
// first line of the signed message.
func ValidContext(c string) error {
	if c == "" || len(c) > 64 {
		return errors.New("invalid context: want 1-64 characters")
	}
	for i := 0; i < len(c); i++ {
		if c[i] < 0x20 || c[i] > 0x7e {
			return errors.New("invalid context: printable ASCII only")
		}
	}
	return nil
}

// ValidNotes reports whether n is valid UTF-8 within the size limit.
func ValidNotes(n string) error {
	if len(n) > MaxNotesBytes {
		return fmt.Errorf("notes too long: %d bytes, max %d", len(n), MaxNotesBytes)
	}
	if !utf8.ValidString(n) {
		return errors.New("notes are not valid UTF-8")
	}
	return nil
}

// ValidRelativeURL enforces that an artifact URL is a plain relative path.
//
// Rejected: any scheme, authority ("//host"), backslashes, control characters,
// whitespace, fragments, "." and ".." segments (also when percent-encoded),
// encoded slashes or backslashes, and a leading slash. A relative path is
// resolved against the manifest URL, so the artifact can never leave the
// origin that served the manifest.
func ValidRelativeURL(u string) error {
	if u == "" || len(u) > 512 {
		return errors.New("invalid url: want 1-512 characters")
	}
	if strings.HasPrefix(u, "/") {
		return errors.New("invalid url: must be relative, not start with '/'")
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c <= 0x20 || c >= 0x7f || c == '\\' || c == '#' {
			return errors.New("invalid url: forbidden character")
		}
	}
	path := u
	if i := strings.IndexByte(u, '?'); i >= 0 {
		path = u[:i]
	}
	if i := strings.IndexByte(path, ':'); i >= 0 {
		return errors.New("invalid url: ':' is not allowed (no scheme, no drive letters)")
	}
	if path == "" {
		return errors.New("invalid url: empty path")
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			return errors.New("invalid url: empty path segment")
		}
		dec, ok := percentDecode(seg)
		if !ok {
			return errors.New("invalid url: bad percent-encoding")
		}
		if dec == "." || dec == ".." || strings.ContainsAny(dec, "/\\") {
			return errors.New("invalid url: dot segment or encoded separator")
		}
		for i := 0; i < len(dec); i++ {
			if dec[i] < 0x20 || dec[i] == 0x7f {
				return errors.New("invalid url: encoded control character")
			}
		}
	}
	return nil
}

func percentDecode(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", false
		}
		b.WriteByte(byte(v))
		i += 2
	}
	return b.String(), true
}

// CompareVersions orders two valid versions numerically; missing components
// count as zero. It returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
