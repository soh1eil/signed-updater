package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// DefaultContext is the domain-separation string used when none is configured.
// Every deployment should choose its own (for example "myapp-update-v1") so a
// signature made for one product can never be replayed against another.
const DefaultContext = "signed-updater-v1"

// Claims are the manifest fields a signature authenticates.
type Claims struct {
	Version  string
	Build    int64
	Platform string
	SHA256   string
	Size     int64
	Notes    string
}

// Validate checks every field against the manifest grammar.
func (c Claims) Validate() error {
	if err := ValidVersion(c.Version); err != nil {
		return err
	}
	if c.Build < 0 || c.Build > MaxBuild {
		return fmt.Errorf("invalid build %d", c.Build)
	}
	if err := ValidPlatform(c.Platform); err != nil {
		return err
	}
	if err := ValidSHA256(c.SHA256); err != nil {
		return err
	}
	if c.Size < 1 || c.Size > MaxSize {
		return fmt.Errorf("invalid size %d", c.Size)
	}
	return ValidNotes(c.Notes)
}

// Message returns the exact bytes that are signed:
//
//	<context>\n
//	version=<version>\n
//	build=<build>\n
//	platform=<platform>\n
//	sha256=<hex>\n
//	size=<bytes>\n
//	notes_sha256=<hex of the UTF-8 notes>\n
//
// All fields are validated first, so none can contain a newline and the
// encoding is unambiguous.
func Message(context string, c Claims) ([]byte, error) {
	if err := ValidContext(context); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	notes := sha256.Sum256([]byte(c.Notes))
	var b strings.Builder
	b.WriteString(context + "\n")
	b.WriteString("version=" + c.Version + "\n")
	b.WriteString("build=" + strconv.FormatInt(c.Build, 10) + "\n")
	b.WriteString("platform=" + c.Platform + "\n")
	b.WriteString("sha256=" + c.SHA256 + "\n")
	b.WriteString("size=" + strconv.FormatInt(c.Size, 10) + "\n")
	b.WriteString("notes_sha256=" + hex.EncodeToString(notes[:]) + "\n")
	return []byte(b.String()), nil
}

// Sign returns the lowercase hex Ed25519 signature of the claims.
func Sign(key ed25519.PrivateKey, context string, c Claims) (string, error) {
	m, err := Message(context, c)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(key, m)), nil
}

// ErrBadSignature is returned when a signature does not verify.
var ErrBadSignature = errors.New("signature invalid")

// Verify checks sigHex over the claims under any one of the given public keys.
// Supplying several keys supports key rotation.
func Verify(keys []ed25519.PublicKey, context string, c Claims, sigHex string) error {
	if err := ValidSig(sigHex); err != nil {
		return err
	}
	m, err := Message(context, c)
	if err != nil {
		return err
	}
	sig, _ := hex.DecodeString(sigHex)
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, m, sig) {
			return nil
		}
	}
	return ErrBadSignature
}

// ParsePublicKey decodes a 64-character hex Ed25519 public key.
func ParsePublicKey(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("public key must be 64 hex characters (32 bytes)")
	}
	return ed25519.PublicKey(b), nil
}

// GenerateKey creates a new key file (mode 0600, never overwriting) holding the
// hex-encoded 32-byte seed, and returns the hex public key.
func GenerateKey(path string) (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create key file: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(seed) + "\n"); err != nil {
		f.Close()
		os.Remove(path)
		return "", fmt.Errorf("write key file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), nil
}

// LoadKey reads a key file after checking its permissions: group- or
// world-accessible files are refused (see checkKeyPerm).
func LoadKey(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	if err := checkKeyPerm(path, st.Mode()); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("key file must hold a 32-byte hex seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
