package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func do(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var o, e bytes.Buffer
	code := run(args, &o, &e)
	return strings.TrimSpace(o.String()), e.String(), code
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	art := filepath.Join(dir, "app.bin")
	man := filepath.Join(dir, "windows.json")
	os.WriteFile(art, []byte("installer bytes"), 0o644)

	pub, _, code := do(t, "keygen", "-out", key)
	if code != 0 || len(pub) != 64 {
		t.Fatalf("keygen: %q %d", pub, code)
	}
	if _, _, code := do(t, "keygen", "-out", key); code == 0 {
		t.Fatal("keygen overwrote")
	}
	if p2, _, _ := do(t, "pub", "-key", key); p2 != pub {
		t.Fatal("pub differs")
	}
	base := []string{"-manifest", man, "-key", key, "-file", art, "-url", "files/app.bin", "-platform", "windows"}
	if _, e, c := do(t, append([]string{"manifest", "add", "-version", "1.0.0", "-build", "1", "-notes", "first"}, base...)...); c != 0 {
		t.Fatal(e)
	}
	if _, _, c := do(t, append([]string{"manifest", "add", "-version", "0.5.0", "-build", "0"}, base...)...); c == 0 {
		t.Fatal("older release accepted")
	}
	if _, e, c := do(t, "verify", "-pub", pub, "-manifest", man, "-file", art, "-platform", "windows"); c != 0 {
		t.Fatalf("verify: %s", e)
	}
	// Wrong key and wrong context both fail.
	other := filepath.Join(dir, "other")
	opub, _, _ := do(t, "keygen", "-out", other)
	if _, _, c := do(t, "verify", "-pub", opub, "-manifest", man); c == 0 {
		t.Fatal("wrong key verified")
	}
	if _, _, c := do(t, "verify", "-pub", pub, "-manifest", man, "-context", "other-app-v1"); c == 0 {
		t.Fatal("wrong context verified")
	}
	// A rotation set containing the right key verifies.
	if _, _, c := do(t, "verify", "-pub", opub+","+pub, "-manifest", man); c != 0 {
		t.Fatal("rotation set failed")
	}
	// Modified artifact is detected.
	os.WriteFile(art, []byte("tampered"), 0o644)
	if _, _, c := do(t, "verify", "-pub", pub, "-manifest", man, "-file", art); c == 0 {
		t.Fatal("tampered artifact matched")
	}
	if out, _, _ := do(t, "manifest", "list", "-manifest", man); !strings.Contains(out, "1.0.0") {
		t.Fatalf("list: %q", out)
	}
	if _, _, c := do(t, "manifest", "rm", "-manifest", man, "-platform", "windows", "-version", "1.0.0"); c != 0 {
		t.Fatal("rm failed")
	}
	if _, _, c := do(t, "manifest", "rm", "-manifest", man, "-platform", "windows", "-version", "1.0.0"); c == 0 {
		t.Fatal("rm of absent release succeeded")
	}
}

func TestContextFromEnvAndAbsoluteURL(t *testing.T) {
	dir := t.TempDir()
	key, art, man := filepath.Join(dir, "k"), filepath.Join(dir, "a"), filepath.Join(dir, "m.json")
	os.WriteFile(art, []byte("x"), 0o644)
	pub, _, _ := do(t, "keygen", "-out", key)
	t.Setenv("UPDSIGN_CONTEXT", "myapp-update-v1")
	args := []string{"manifest", "add", "-manifest", man, "-key", key, "-file", art, "-url", "a", "-version", "1.0.0", "-build", "1", "-platform", "linux"}
	if _, e, c := do(t, args...); c != 0 {
		t.Fatal(e)
	}
	t.Setenv("UPDSIGN_CONTEXT", "")
	if _, _, c := do(t, "verify", "-pub", pub, "-manifest", man); c == 0 {
		t.Fatal("default context verified a custom-context signature")
	}
	t.Setenv("UPDSIGN_CONTEXT", "myapp-update-v1")
	if _, _, c := do(t, "verify", "-pub", pub, "-manifest", man); c != 0 {
		t.Fatal("env context not honoured")
	}
	bad := append([]string{}, args...)
	bad[len(bad)-7] = "https://evil.example/a"
	os.Remove(man)
	if _, _, c := do(t, bad...); c == 0 {
		t.Fatal("absolute url accepted")
	}
}

func TestRefusesLooseKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	key, art := filepath.Join(dir, "k"), filepath.Join(dir, "a")
	os.WriteFile(art, []byte("x"), 0o644)
	do(t, "keygen", "-out", key)
	os.Chmod(key, 0o640)
	_, e, c := do(t, "sign", "-key", key, "-file", art, "-version", "1.0.0", "-platform", "linux", "-sig-only")
	if c == 0 || !strings.Contains(e, "refusing") {
		t.Fatalf("loose key accepted: %q", e)
	}
}

func TestUsage(t *testing.T) {
	if _, _, c := do(t); c != 2 {
		t.Fatal("no args must exit 2")
	}
	if _, _, c := do(t, "bogus"); c != 2 {
		t.Fatal("unknown must exit 2")
	}
}
