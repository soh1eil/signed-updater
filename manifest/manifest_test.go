package manifest

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/soh1eil/signed-updater/signing"
)

func key() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(make([]byte, 32)) }

func entry(t *testing.T, version string, build int64, platform string) Entry {
	t.Helper()
	e := Entry{Version: version, Build: build, Platform: platform, URL: "dl/" + version + ".bin",
		SHA256: strings.Repeat("0a", 32), Size: 10, Notes: "n"}
	sig, err := signing.Sign(key(), signing.DefaultContext, e.Claims())
	if err != nil {
		t.Fatal(err)
	}
	e.Sig = sig
	return e
}

func TestAddRemoveNewest(t *testing.T) {
	m := &Manifest{}
	if err := m.Add(entry(t, "1.0.0", 1, "linux"), false); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(entry(t, "1.1.0", 2, "linux"), false); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(entry(t, "1.1.0", 2, "linux"), false); err == nil {
		t.Error("duplicate accepted")
	}
	if err := m.Add(entry(t, "0.9.0", 0, "linux"), false); err == nil {
		t.Error("rollback accepted without -allow-older")
	}
	if err := m.Add(entry(t, "0.9.0", 0, "linux"), true); err != nil {
		t.Errorf("allow-older refused: %v", err)
	}
	if err := m.Add(entry(t, "1.0.0", 1, "windows"), false); err != nil {
		t.Fatal(err)
	}
	if e, _ := m.Newest("linux"); e.Version != "1.1.0" {
		t.Errorf("newest = %s", e.Version)
	}
	if n := m.Remove("linux", "1.1.0", -1); n != 1 {
		t.Errorf("removed %d", n)
	}
	if e, _ := m.Newest("linux"); e.Version != "1.0.0" {
		t.Errorf("newest after rm = %s", e.Version)
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	m := &Manifest{}
	m.Add(entry(t, "1.0.0", 1, "linux"), false)
	m.Add(entry(t, "2.0.0", 2, "linux"), false)
	out, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Releases) != 2 || p.Releases[0].Version != "2.0.0" {
		t.Fatalf("unexpected order: %+v", p.Releases)
	}
}

func TestParseRejects(t *testing.T) {
	good := entry(t, "1.0.0", 1, "linux")
	enc := func(m Manifest) string { b, _ := json.Marshal(m); return string(b) }
	withURL := func(u string) string { e := good; e.URL = u; return enc(Manifest{Schema: 1, Releases: []Entry{e}}) }
	cases := map[string]string{
		"empty":          ``,
		"not json":       `nope`,
		"wrong schema":   enc(Manifest{Schema: 2}),
		"absolute url":   withURL("https://evil.example/x"),
		"traversal":      withURL("../x"),
		"trailing":       enc(Manifest{Schema: 1}) + `{}`,
		"float build":    `{"schema":1,"releases":[{"version":"1.0.0","build":1.5}]}`,
		"duplicate":      enc(Manifest{Schema: 1, Releases: []Entry{good, good}}),
		"null releases?": `{"schema":1,"releases":"x"}`,
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(enc(Manifest{Schema: 1, Releases: []Entry{good}}))); err != nil {
		t.Errorf("good manifest rejected: %v", err)
	}
	if _, err := Parse(make([]byte, MaxBytes+1)); err == nil {
		t.Error("oversize accepted")
	}
}

func TestSaveLoad(t *testing.T) {
	path := t.TempDir() + "/m.json"
	m, err := Load(path)
	if err != nil || len(m.Releases) != 0 {
		t.Fatalf("load missing: %v %v", m, err)
	}
	m.Add(entry(t, "1.0.0", 1, "linux"), false)
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}
	m2, err := Load(path)
	if err != nil || len(m2.Releases) != 1 {
		t.Fatalf("reload: %v %v", m2, err)
	}
}

func FuzzParse(f *testing.F) {
	k := key()
	e := Entry{Version: "1.0.0", Build: 1, Platform: "linux", URL: "a/b.bin", SHA256: strings.Repeat("0a", 32), Size: 5}
	e.Sig, _ = signing.Sign(k, signing.DefaultContext, e.Claims())
	seed, _ := json.Marshal(Manifest{Schema: 1, Releases: []Entry{e}})
	f.Add(seed)
	f.Add([]byte(`{"schema":1,"releases":[]}`))
	f.Add([]byte(`{"schema":1,"releases":[{"url":"../../etc/passwd"}]}`))
	f.Add([]byte(`{"schema":1}{"schema":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Parse(data)
		if err != nil {
			return
		}
		// Invariant: everything Parse accepts satisfies the grammar, relative
		// URL rule included, and survives a marshal/parse round trip.
		for _, e := range m.Releases {
			if err := e.Validate(); err != nil {
				t.Fatalf("accepted invalid entry: %v", err)
			}
			if err := signing.ValidRelativeURL(e.URL); err != nil {
				t.Fatalf("accepted bad url %q", e.URL)
			}
		}
		out, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(out); err != nil {
			t.Fatalf("round trip failed: %v", err)
		}
	})
}
