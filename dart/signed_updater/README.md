# signed_updater

Secure self-update for desktop apps (Windows, Linux, macOS) with Ed25519-signed
manifests. Companion to the `updsign` Go tool. See the
[repository README](../../README.md) and the
[threat model](../../docs/threat-model.md).

```dart
final updater = SignedUpdater(
  config: UpdaterConfig(
    manifestUrl: Uri.parse('https://example.com/updates/windows.json'),
    publicKeys: ['<64 hex chars from updsign keygen>'],
    context: 'myapp-update-v1',
    platform: 'windows',
    currentVersion: '1.0.0',
    currentBuild: 1,
  ),
  stateStore: FileStateStore('update-state.json'),
  installer: WindowsInstaller(arguments: ['/VERYSILENT']),
);
final r = await updater.check();
if (r is UpdateAvailable) {
  final verified = await updater.download(r.release, Directory('updates'));
  await updater.install(verified);
}
```
