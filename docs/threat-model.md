# Threat model

This document says what `signed_updater` + `updsign` defend against, and,
just as important, what they do not.

## Assets and roles

- **Signing key**: Ed25519 private key held by the publisher (ideally offline
  or on a dedicated release machine). Its public half is compiled into the app.
- **Update server**: serves `manifest.json` and artifacts. Treated as
  *untrusted storage*.
- **Client**: the installed app, holding the pinned public key(s).

## What is protected

| Threat | Outcome |
|---|---|
| Compromised update server or web root swaps an installer and its `sha256` | Refused. The signature covers the digest, size, version, build, platform and notes, and the attacker has no key. |
| MITM on the network path (even with a rogue TLS certificate) | Refused for the same reason: authenticity comes from the signature, not from TLS. TLS remains mandatory (`https` only) for privacy and to deny trivial downgrades. |
| Tampered artifact bytes (truncated, padded, bit-flipped) | Refused: size is capped while streaming, the digest is computed incrementally, and the file is re-hashed from disk after writing and again right before install. |
| Relabelling an old signed artifact as a new version | Refused. `version` and `build` are inside the signed message. |
| Serving a Windows build as a Linux update | Refused. `platform` is signed. |
| Rewriting release notes to carry phishing text | Refused. The digest of the notes is signed. |
| Signature reuse across products | Refused when each product uses its own signing context (`-context` / `UpdaterConfig.context`). |
| Rollback to an older, vulnerable but validly signed release | Refused: the offered release must be newer than the running app, and a persisted high-water mark rejects a manifest whose best release is older than one already authenticated. |
| Path tricks in the manifest (`../`, absolute URLs, `//host`, `\\`, encoded dots, schemes) | The manifest is rejected. Artifact URLs are plain relative paths resolved against the manifest URL; redirects are followed only within the same origin (max 3). |
| Trust-on-first-use downgrade (key delivered by the server on first contact) | Not possible: the key is compiled in. There is no code path that reads a key from the network. |
| Oversized or malformed manifests | Size-capped (1 MiB), strictly typed, fuzzed in Go. |
| World-readable signing key on the release machine | `updsign` refuses key files that are group- or world-accessible (POSIX). |

## What is NOT protected

- **Compromise of the signing key.** Whoever holds it can ship anything. Keep
  it offline or in an HSM/KMS, use a dedicated machine, and have a rotation
  plan ([key-rotation.md](key-rotation.md)). There is no in-band revocation: if
  the key leaks, clients pinned to it can only be fixed by a build you
  distribute some other way.
- **Key loss.** If the private key is lost and no second pinned key was
  shipped, installed clients can never accept another update. Back the key up
  (encrypted, two locations). Shipping a *standby* public key in advance is the
  cheap insurance.
- **Freeze / withhold attacks.** An attacker who controls the server can serve
  an old (valid) manifest or drop entries, so clients silently stay on an old
  version. The high-water mark stops going *backwards*; nothing stops *not going
  forwards*. The manifest has no expiry/timestamp in v1. Monitor your own
  update endpoint from outside.
- **A compromised build machine or supply chain.** If the attacker can get
  malicious code into the artifact *before* you sign it, the signature is valid.
  Reproducible builds and review are out of scope.
- **A compromised client.** Malware already running as the user can modify the
  app, the pinned key or the downloaded file (a small TOCTOU window remains
  between the final re-hash and the installer reading the file). Installers
  should run from a directory only the user can write.
- **Confidentiality.** Nothing is encrypted; artifacts and notes are public.
- **Installer trust.** The package verifies bytes; it does not sandbox the
  installer it launches, nor validate code-signing (Authenticode, notarisation).
  Use both: this package for authenticity of the update channel, OS code
  signing for platform trust.
- **Metadata privacy.** The server sees which clients check for updates.
- **Unsigned manifest fields.** Only `version`, `build`, `platform`, `sha256`,
  `size` and `notes` are authenticated. `url` is intentionally not signed (so
  you can move files); a wrong URL can only produce a digest mismatch, i.e. a
  denial of update, never code execution. Unknown extra fields are ignored and
  must not be relied upon.
- **Pre-release semantics.** Versions are purely numeric (`1.2.3`, up to four
  components); there are no `-beta` suffixes. Use separate manifests/platform
  labels for channels (for example `windows-beta`).

## Design choices worth knowing

- **Per-entry signatures** (not one signature over the whole manifest) mean a
  manifest may carry releases signed by different keys. Clients skip entries
  they cannot verify and only fail when *no* entry for their platform verifies.
  This is what lets the key-rotation procedure work for stragglers.
- **Domain separation** is a plain first line of the signed message. It is not a
  secret.
- **Ed25519** signatures are deterministic, which is why the cross-language
  fixtures in `testdata/interop.json` are byte-stable.
