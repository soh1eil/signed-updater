package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testKey() ed25519.PrivateKey {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	return ed25519.NewKeyFromSeed(seed)
}

func goodClaims() Claims {
	return Claims{Version: "1.2.3", Build: 45, Platform: "linux", SHA256: strings.Repeat("ab", 32), Size: 1234, Notes: "fixes"}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k := testKey()
	sig, err := Sign(k, DefaultContext, goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	pub := []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}
	if err := Verify(pub, DefaultContext, goodClaims(), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsEveryTamper(t *testing.T) {
	k := testKey()
	pub := []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}
	sig, _ := Sign(k, DefaultContext, goodClaims())
	mut := map[string]func(*Claims){
		"version":  func(c *Claims) { c.Version = "1.2.4" },
		"build":    func(c *Claims) { c.Build++ },
		"platform": func(c *Claims) { c.Platform = "windows" },
		"sha256":   func(c *Claims) { c.SHA256 = strings.Repeat("cd", 32) },
		"size":     func(c *Claims) { c.Size++ },
		"notes":    func(c *Claims) { c.Notes = "evil" },
	}
	for name, f := range mut {
		c := goodClaims()
		f(&c)
		if err := Verify(pub, DefaultContext, c, sig); err == nil {
			t.Errorf("tampered %s verified", name)
		}
	}
	if err := Verify(pub, "other-context-v1", goodClaims(), sig); err == nil {
		t.Error("different context verified: no domain separation")
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if err := Verify([]ed25519.PublicKey{other}, DefaultContext, goodClaims(), sig); err == nil {
		t.Error("wrong key verified")
	}
	if err := Verify([]ed25519.PublicKey{other, pub[0]}, DefaultContext, goodClaims(), sig); err != nil {
		t.Errorf("rotation set with the right key must verify: %v", err)
	}
}

func TestMessageIsCanonical(t *testing.T) {
	m, err := Message("ctx-v1", goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	notes := sha256.Sum256([]byte("fixes"))
	want := "ctx-v1\nversion=1.2.3\nbuild=45\nplatform=linux\nsha256=" + strings.Repeat("ab", 32) +
		"\nsize=1234\nnotes_sha256=" + hex.EncodeToString(notes[:]) + "\n"
	if string(m) != want {
		t.Fatalf("message mismatch:\n%s\nwant:\n%s", m, want)
	}
}

func FuzzValidRelativeURL(f *testing.F) {
	for _, s := range []string{"a/b", "../x", "a/%2e%2e/b", "https://x", "a b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, u string) {
		if ValidRelativeURL(u) != nil {
			return
		}
		// Accepted URLs must never be able to escape or change the origin.
		path := u
		if i := strings.IndexByte(u, '?'); i >= 0 {
			path = u[:i]
		}
		for _, seg := range strings.Split(path, "/") {
			if seg == "." || seg == ".." || seg == "" {
				t.Fatalf("accepted dangerous url %q", u)
			}
		}
		if strings.HasPrefix(u, "/") || strings.Contains(path, ":") || strings.ContainsAny(u, "\\#") {
			t.Fatalf("accepted dangerous url %q", u)
		}
	})
}

func TestContextValidation(t *testing.T) {
	for _, c := range []string{"", "a\nb", strings.Repeat("x", 65), "caf\u00e9"} {
		if _, err := Message(c, goodClaims()); err == nil {
			t.Errorf("context %q accepted", c)
		}
	}
}

func TestRelativeURL(t *testing.T) {
	good := []string{"app.exe", "downloads/app-1.2.3.exe", "d/a%20b.zip", "a/b.tar.gz?x=1"}
	bad := []string{"", "/abs", "//host/x", "https://x/y", "http:x", "C:/x", "a\\b", "../x", "a/../b", "a/./b",
		"a/%2e%2e/b", "a/%2E/b", "a/b%2fc", "a/b%5cc", "a//b", "a b", "a#frag", "a/%zz", "a/%2", "a\x00b", "a/%00", "é/x", "a/b/"}
	for _, u := range good {
		if err := ValidRelativeURL(u); err != nil {
			t.Errorf("good %q rejected: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := ValidRelativeURL(u); err == nil {
			t.Errorf("bad %q accepted", u)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"1.0.0", "1.0.0", 0}, {"1.0", "1.0.0", 0}, {"1.2.10", "1.2.9", 1}, {"1.9", "1.10", -1}, {"2", "1.99.99", 1}}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	for _, v := range []string{"", "1.", "01.2", "1.2.3.4.5", "v1", "1.-2", "1..2", "1.2.3-beta"} {
		if ValidVersion(v) == nil {
			t.Errorf("version %q accepted", v)
		}
	}
}

func TestKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes only")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	pub, err := GenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKey(path); err == nil {
		t.Fatal("keygen overwrote an existing key")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", st.Mode().Perm())
	}
	k, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k.Public().(ed25519.PublicKey)) != pub {
		t.Fatal("public key mismatch")
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644, 0o666, 0o620} {
		os.Chmod(path, mode)
		if _, err := LoadKey(path); err == nil {
			t.Errorf("mode %o accepted", mode)
		}
	}
	os.Chmod(path, 0o400)
	if _, err := LoadKey(path); err != nil {
		t.Errorf("mode 0400 rejected: %v", err)
	}
	os.Chmod(path, 0o600)
	os.WriteFile(path, []byte("not hex\n"), 0o600)
	if _, err := LoadKey(path); err == nil {
		t.Error("garbage key accepted")
	}
	link := filepath.Join(dir, "dir")
	os.Mkdir(link, 0o700)
	if _, err := LoadKey(link); err == nil {
		t.Error("directory accepted as key")
	}
}
