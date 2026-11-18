# signed-updater

Secure self-update for **Flutter / Dart desktop apps** on Windows, Linux and
macOS. The update server is treated as untrusted: every release is described by
an **Ed25519-signed** manifest entry and the client verifies it against a
**public key compiled into the app**.

[فارسی](README.fa.md)

- `updsign` (Go): generate keys, sign artifacts, maintain the manifest, verify.
- `signed_updater` (Dart): fetch, verify, download, re-hash, install.
- Both sides share one signed-message format, proven by fixtures made by the Go
  tool and verified by the Dart tests.

## Why not just "sha256 in the manifest"?

If the manifest and the installer sit on the same server, an attacker who owns
that server changes both. A signature made offline with a key the server never
sees closes that hole. And signing *only* the digest still allows relabelling an
old artifact as a new version, so this project signs the whole tuple:

```
<context>\n
version=<version>\n
build=<build>\n
platform=<platform>\n
sha256=<hex>\n
size=<bytes>\n
notes_sha256=<hex of UTF-8 notes>\n
```

`<context>` is a domain-separation string you choose per product
(`myapp-update-v1`), so a signature from one app is meaningless to another.

## Quick start

### 1. Publisher (Go 1.23+)

```sh
go install github.com/soh1eil/signed-updater/cmd/updsign@latest

updsign keygen -out release.key         # prints the public key (64 hex chars); file mode 0600
export UPDSIGN_CONTEXT=myapp-update-v1  # or pass -context

updsign manifest add \
  -manifest updates/windows.json -key release.key \
  -file dist/MyApp-1.4.0-setup.exe -url files/MyApp-1.4.0-setup.exe \
  -version 1.4.0 -build 42 -platform windows -notes "Bug fixes"

updsign verify -pub <PUBKEY> -manifest updates/windows.json -file dist/MyApp-1.4.0-setup.exe
```

`updsign` refuses to read a key file that is readable by group or others, never
overwrites an existing key, and writes manifests atomically. `manifest add`
also refuses to publish a release that is not newer than the current newest one
for that platform unless `-allow-older` is given.

Commands: `keygen`, `pub`, `sign` (prints an entry, or `-sig-only`),
`verify`, `manifest add | rm | list`.

Manifest (`schema` 1):

```json
{
  "schema": 1,
  "releases": [
    {
      "version": "1.4.0",
      "build": 42,
      "platform": "windows",
      "url": "files/MyApp-1.4.0-setup.exe",
      "sha256": "…64 hex…",
      "size": 48123904,
      "sig": "…128 hex…",
      "notes": "Bug fixes"
    }
  ]
}
```

`url` must be a plain **relative** path (no scheme, no `//host`, no `..`).
It resolves against the manifest URL, so the artifact can never leave the
origin that served the manifest. Upload `files/` and the manifest as static
files; nothing server-side is required.

### 2. App (Dart / Flutter desktop)

```yaml
dependencies:
  signed_updater:
    git:
      url: https://github.com/soh1eil/signed-updater
      path: dart/signed_updater
```

```dart
final updater = SignedUpdater(
  config: UpdaterConfig(
    manifestUrl: Uri.parse('https://example.com/updates/windows.json'),
    publicKeys: ['<PUBKEY>'],          // compiled in, never fetched
    context: 'myapp-update-v1',        // must equal updsign's context
    platform: 'windows',
    currentVersion: '1.3.0',
    currentBuild: 41,
  ),
  stateStore: FileStateStore('$appSupportDir/update-state.json'), // rollback memory
  installer: WindowsInstaller(arguments: ['/VERYSILENT', '/NORESTART']),
);

try {
  final r = await updater.check();
  if (r is UpdateAvailable) {
    final verified = await updater.download(r.release, Directory('$cacheDir/updates'),
        onProgress: (got, total) => setProgress(got / total));
    await updater.install(verified);   // then exit the app so files are not locked
  }
} on UpdateException catch (e) {
  log('update refused: ${e.failure.name}');
}
```

What the client enforces:

| Check | Where |
|---|---|
| Pinned key(s) only; manifest URL must be `https` | `UpdaterConfig` |
| Strict manifest grammar, 1 MiB cap, no duplicates | `Manifest.parse` |
| Signature must verify before anything is downloaded | `check`, `download` |
| Relative URL only, same-origin redirects only (max 3) | `isValidRelativeUrl`, `_open` |
| Size cap while streaming, incremental SHA-256 | `download` |
| Re-hash from disk after writing and before install | `VerifiedUpdate.recheck` |
| Newer than running app; not older than the high-water mark | `check` |

### Installers

`Installer` is a one-method interface. Included: `WindowsInstaller` (runs an
`.exe` with your silent flags), `LinuxInstaller` (atomically replaces an
AppImage and keeps `.old`), `MacOsInstaller` (hands a `.dmg`/`.pkg` to `open`),
and `CommandInstaller` (any program; the file path is an argv entry, never
shell-interpolated). Implement `Installer` for MSIX, deb/rpm helpers, or
bundle-swapping logic of your own.

## Security documents

- [Threat model](docs/threat-model.md): what is and is not protected (server
  compromise, MITM, rollback, freeze, key loss).
- [Key rotation](docs/key-rotation.md): ship the new key in a release signed by
  the old one; standby keys.

## Development

```sh
go vet ./... && go test -race ./...
go test ./manifest -run xxx -fuzz FuzzParse -fuzztime 30s
go test ./manifest -run Interop -update       # regenerate testdata/interop.json

cd dart/signed_updater && dart pub get && dart analyze && dart test
```

`testdata/interop.json` is produced by the Go code with a published **test** key
and is consumed by the Dart tests; CI fails if it drifts.

## Limits and non-goals

No delta updates, no staged rollouts, no in-band revocation, no manifest expiry
(v1), no pre-release version syntax. Windows key-file permission checks are not
performed (use an ACL). See the threat model.

## License

MIT, see [LICENSE](LICENSE).
