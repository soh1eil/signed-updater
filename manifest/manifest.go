// Package manifest defines the update manifest and its strict parser.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/soh1eil/signed-updater/signing"
)

const (
	// SchemaVersion is the only manifest schema understood.
	SchemaVersion = 1
	// MaxBytes bounds the size of a manifest the parser will read.
	MaxBytes = 1 << 20
	// MaxReleases bounds the number of entries.
	MaxReleases = 1000
)

// Entry is one published release for one platform.
type Entry struct {
	Version  string `json:"version"`
	Build    int64  `json:"build"`
	Platform string `json:"platform"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Sig      string `json:"sig"`
	Notes    string `json:"notes"`
}

// Claims returns the signed subset of the entry.
func (e Entry) Claims() signing.Claims {
	return signing.Claims{Version: e.Version, Build: e.Build, Platform: e.Platform,
		SHA256: e.SHA256, Size: e.Size, Notes: e.Notes}
}

// Validate checks field grammar (not the signature).
func (e Entry) Validate() error {
	if err := e.Claims().Validate(); err != nil {
		return err
	}
	if err := signing.ValidRelativeURL(e.URL); err != nil {
		return err
	}
	return signing.ValidSig(e.Sig)
}

// VerifySignature checks the entry's signature under any of keys.
func (e Entry) VerifySignature(keys []ed25519.PublicKey, context string) error {
	return signing.Verify(keys, context, e.Claims(), e.Sig)
}

// Manifest is the published document.
type Manifest struct {
	Schema   int     `json:"schema"`
	Releases []Entry `json:"releases"`
}

// Parse decodes and validates a manifest. It rejects oversized input, trailing
// data, an unknown schema, and any entry that fails Validate.
func Parse(data []byte) (*Manifest, error) {
	if len(data) > MaxBytes {
		return nil, errors.New("manifest too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest: trailing data")
	}
	if _, err := dec.Token(); err == nil {
		return nil, errors.New("manifest: trailing data")
	}
	if m.Schema != SchemaVersion {
		return nil, fmt.Errorf("manifest: unsupported schema %d", m.Schema)
	}
	if len(m.Releases) > MaxReleases {
		return nil, errors.New("manifest: too many releases")
	}
	seen := map[string]bool{}
	for i, e := range m.Releases {
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("manifest: release %d: %w", i, err)
		}
		k := fmt.Sprintf("%s|%d|%s", e.Platform, e.Build, e.Version)
		if seen[k] {
			return nil, fmt.Errorf("manifest: release %d duplicates %s", i, k)
		}
		seen[k] = true
	}
	return &m, nil
}

// Marshal renders the manifest as indented JSON, releases sorted by platform
// then newest first, so diffs stay stable.
func (m *Manifest) Marshal() ([]byte, error) {
	m.Schema = SchemaVersion
	sort.SliceStable(m.Releases, func(i, j int) bool {
		a, b := m.Releases[i], m.Releases[j]
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		if c := signing.CompareVersions(a.Version, b.Version); c != 0 {
			return c > 0
		}
		return a.Build > b.Build
	})
	if m.Releases == nil {
		m.Releases = []Entry{}
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Newest returns the highest (version, build) entry for platform.
func (m *Manifest) Newest(platform string) (Entry, bool) {
	var best Entry
	found := false
	for _, e := range m.Releases {
		if e.Platform != platform {
			continue
		}
		if !found || Newer(e, best) {
			best, found = e, true
		}
	}
	return best, found
}

// Newer reports whether a is a later release than b.
func Newer(a, b Entry) bool {
	if c := signing.CompareVersions(a.Version, b.Version); c != 0 {
		return c > 0
	}
	return a.Build > b.Build
}

// Load reads a manifest file; a missing file yields an empty manifest.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Manifest{Schema: SchemaVersion, Releases: []Entry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Save writes the manifest atomically (temp file in the same directory, then
// rename) so a reader never sees a half-written document.
func (m *Manifest) Save(path string) error {
	out, err := m.Marshal()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".manifest-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Add appends e. It refuses an exact duplicate, and refuses to publish a
// release older than the newest existing one for the platform unless
// allowOlder is set (a rollback is rarely intended).
func (m *Manifest) Add(e Entry, allowOlder bool) error {
	if err := e.Validate(); err != nil {
		return err
	}
	for _, x := range m.Releases {
		if x.Platform == e.Platform && x.Version == e.Version && x.Build == e.Build {
			return fmt.Errorf("release %s build %d for %s already exists", e.Version, e.Build, e.Platform)
		}
	}
	if best, ok := m.Newest(e.Platform); ok && !allowOlder && !Newer(e, best) {
		return fmt.Errorf("%s build %d is not newer than published %s build %d (use -allow-older to override)",
			e.Version, e.Build, best.Version, best.Build)
	}
	m.Releases = append(m.Releases, e)
	return nil
}

// Remove deletes entries matching platform and version (and build, when
// build >= 0). It returns how many were removed.
func (m *Manifest) Remove(platform, version string, build int64) int {
	kept := m.Releases[:0]
	n := 0
	for _, e := range m.Releases {
		if e.Platform == platform && e.Version == version && (build < 0 || e.Build == build) {
			n++
			continue
		}
		kept = append(kept, e)
	}
	m.Releases = kept
	return n
}
