// Command updsign signs and verifies auto-update manifests.
//
//	updsign keygen  -out KEYFILE
//	updsign pub     -key KEYFILE
//	updsign sign    -key KEYFILE -file ARTIFACT -version V -build N -platform P [-notes T | -notes-file F] [-sig-only]
//	updsign verify  -pub HEX[,HEX...] (-manifest FILE | -entry FILE) [-file ARTIFACT -platform P]
//	updsign manifest add -manifest FILE -key KEYFILE -file ARTIFACT -url REL -version V -build N -platform P
//	updsign manifest rm  -manifest FILE -platform P -version V [-build N]
//	updsign manifest list -manifest FILE
//
// The signing context (domain separation) is set with -context or the
// UPDSIGN_CONTEXT environment variable and defaults to "signed-updater-v1".
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/soh1eil/signed-updater/manifest"
	"github.com/soh1eil/signed-updater/signing"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage: updsign <command> [flags]

commands:
  keygen    create a new signing key file (mode 0600) and print the public key
  pub       print the public key of a key file
  sign      sign an artifact and print the manifest entry (or only the signature)
  verify    verify a manifest or entry, optionally against the artifact file
  manifest  add | rm | list releases in a manifest file

Run "updsign <command> -h" for flags.
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = cmdKeygen(args[1:], stdout)
	case "pub":
		err = cmdPub(args[1:], stdout)
	case "sign":
		err = cmdSign(args[1:], stdout)
	case "verify":
		err = cmdVerify(args[1:], stdout)
	case "manifest":
		err = cmdManifest(args[1:], stdout)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "updsign: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "updsign:", err)
		return 1
	}
	return 0
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func contextFlag(fs *flag.FlagSet) *string {
	def := os.Getenv("UPDSIGN_CONTEXT")
	if def == "" {
		def = signing.DefaultContext
	}
	return fs.String("context", def, "signing context (domain separation); env UPDSIGN_CONTEXT")
}

func cmdKeygen(args []string, out io.Writer) error {
	fs := newFlags("keygen")
	path := fs.String("out", "", "key file to create (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("keygen: -out is required")
	}
	pub, err := signing.GenerateKey(*path)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, pub)
	return nil
}

func cmdPub(args []string, out io.Writer) error {
	fs := newFlags("pub")
	path := fs.String("key", "", "key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	k, err := signing.LoadKey(*path)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	return nil
}

type entryFlags struct {
	file, version, platform, url, notes, notesFile string
	build                                          int64
}

func (f *entryFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&f.file, "file", "", "artifact file to hash")
	fs.StringVar(&f.version, "version", "", "release version, e.g. 1.2.3")
	fs.Int64Var(&f.build, "build", 0, "build number")
	fs.StringVar(&f.platform, "platform", "", "platform label, e.g. windows, linux, macos")
	fs.StringVar(&f.url, "url", "", "artifact URL, relative to the manifest")
	fs.StringVar(&f.notes, "notes", "", "release notes")
	fs.StringVar(&f.notesFile, "notes-file", "", "read release notes from a file")
}

func (f *entryFlags) claims() (signing.Claims, error) {
	if f.file == "" {
		return signing.Claims{}, errors.New("-file is required")
	}
	notes := f.notes
	if f.notesFile != "" {
		b, err := os.ReadFile(f.notesFile)
		if err != nil {
			return signing.Claims{}, err
		}
		notes = string(b)
	}
	sum, size, err := hashFile(f.file)
	if err != nil {
		return signing.Claims{}, err
	}
	c := signing.Claims{Version: f.version, Build: f.build, Platform: f.platform, SHA256: sum, Size: size, Notes: notes}
	return c, c.Validate()
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func cmdSign(args []string, out io.Writer) error {
	fs := newFlags("sign")
	key := fs.String("key", "", "key file")
	ctx := contextFlag(fs)
	sigOnly := fs.Bool("sig-only", false, "print only the hex signature")
	var ef entryFlags
	ef.bind(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	k, err := signing.LoadKey(*key)
	if err != nil {
		return err
	}
	c, err := ef.claims()
	if err != nil {
		return err
	}
	sig, err := signing.Sign(k, *ctx, c)
	if err != nil {
		return err
	}
	if *sigOnly {
		fmt.Fprintln(out, sig)
		return nil
	}
	e := manifest.Entry{Version: c.Version, Build: c.Build, Platform: c.Platform, URL: ef.url,
		SHA256: c.SHA256, Size: c.Size, Sig: sig, Notes: c.Notes}
	b, _ := json.MarshalIndent(e, "", "  ")
	fmt.Fprintln(out, string(b))
	return nil
}

func parseKeys(s string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, h := range strings.Split(s, ",") {
		k, err := signing.ParsePublicKey(h)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func cmdVerify(args []string, out io.Writer) error {
	fs := newFlags("verify")
	pub := fs.String("pub", "", "public key(s), hex, comma separated")
	mpath := fs.String("manifest", "", "manifest file")
	epath := fs.String("entry", "", "single entry JSON file")
	file := fs.String("file", "", "artifact file; must match the entry digest and size")
	platform := fs.String("platform", "", "with -file: which platform's newest entry the file belongs to")
	ctx := contextFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := parseKeys(*pub)
	if err != nil {
		return err
	}
	var entries []manifest.Entry
	switch {
	case *mpath != "" && *epath == "":
		data, err := os.ReadFile(*mpath)
		if err != nil {
			return err
		}
		m, err := manifest.Parse(data)
		if err != nil {
			return err
		}
		entries = m.Releases
	case *epath != "" && *mpath == "":
		data, err := os.ReadFile(*epath)
		if err != nil {
			return err
		}
		var e manifest.Entry
		if err := json.Unmarshal(data, &e); err != nil {
			return err
		}
		if err := e.Validate(); err != nil {
			return err
		}
		entries = []manifest.Entry{e}
	default:
		return errors.New("verify: give exactly one of -manifest or -entry")
	}
	bad := 0
	for _, e := range entries {
		if err := e.VerifySignature(keys, *ctx); err != nil {
			fmt.Fprintf(out, "FAIL  %s %s build %d: %v\n", e.Platform, e.Version, e.Build, err)
			bad++
			continue
		}
		fmt.Fprintf(out, "ok    %s %s build %d\n", e.Platform, e.Version, e.Build)
	}
	if *file != "" {
		sum, size, err := hashFile(*file)
		if err != nil {
			return err
		}
		matched := false
		for _, e := range entries {
			if (*platform == "" || e.Platform == *platform) && e.SHA256 == sum && e.Size == size {
				matched = true
				fmt.Fprintf(out, "ok    %s matches %s %s build %d\n", *file, e.Platform, e.Version, e.Build)
			}
		}
		if !matched {
			fmt.Fprintf(out, "FAIL  %s matches no entry (sha256 %s)\n", *file, sum)
			bad++
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d check(s) failed", bad)
	}
	return nil
}

func cmdManifest(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("manifest: want add, rm or list")
	}
	sub, rest := args[0], args[1:]
	fs := newFlags("manifest " + sub)
	mpath := fs.String("manifest", "", "manifest file")
	switch sub {
	case "add":
		key := fs.String("key", "", "key file")
		ctx := contextFlag(fs)
		older := fs.Bool("allow-older", false, "allow publishing a release older than the newest one")
		var ef entryFlags
		ef.bind(fs)
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *mpath == "" {
			return errors.New("-manifest is required")
		}
		k, err := signing.LoadKey(*key)
		if err != nil {
			return err
		}
		c, err := ef.claims()
		if err != nil {
			return err
		}
		sig, err := signing.Sign(k, *ctx, c)
		if err != nil {
			return err
		}
		e := manifest.Entry{Version: c.Version, Build: c.Build, Platform: c.Platform, URL: ef.url,
			SHA256: c.SHA256, Size: c.Size, Sig: sig, Notes: c.Notes}
		m, err := manifest.Load(*mpath)
		if err != nil {
			return err
		}
		if err := m.Add(e, *older); err != nil {
			return err
		}
		if err := m.Save(*mpath); err != nil {
			return err
		}
		fmt.Fprintf(out, "added %s %s build %d\n", e.Platform, e.Version, e.Build)
	case "rm":
		platform := fs.String("platform", "", "platform")
		version := fs.String("version", "", "version")
		build := fs.Int64("build", -1, "build (default: all builds of the version)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		m, err := manifest.Load(*mpath)
		if err != nil {
			return err
		}
		n := m.Remove(*platform, *version, *build)
		if n == 0 {
			return errors.New("no matching release")
		}
		if err := m.Save(*mpath); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed %d release(s)\n", n)
	case "list":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		m, err := manifest.Load(*mpath)
		if err != nil {
			return err
		}
		for _, e := range m.Releases {
			fmt.Fprintf(out, "%-12s %-12s build %-6d %s\n", e.Platform, e.Version, e.Build, e.URL)
		}
	default:
		return fmt.Errorf("manifest: unknown subcommand %q", sub)
	}
	return nil
}
