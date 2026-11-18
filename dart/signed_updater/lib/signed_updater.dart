/// Secure self-update for desktop apps using Ed25519-signed manifests.
///
/// Start with [SignedUpdater]. See the README for the threat model.
library;

export 'src/errors.dart';
export 'src/installers/installer.dart';
export 'src/installers/command_installer.dart';
export 'src/installers/linux_installer.dart';
export 'src/installers/macos_installer.dart';
export 'src/installers/windows_installer.dart';
export 'src/message.dart' show buildSignedMessage, defaultSigningContext;
export 'src/release.dart';
export 'src/state_store.dart';
export 'src/updater.dart';
export 'src/validate.dart';
