import '../updater.dart';
import 'command_installer.dart';
import 'installer.dart';

/// Opens a verified `.dmg`, `.pkg` or `.app` bundle archive with `open`, so the
/// system installer or Finder takes over. Unattended replacement of a running
/// bundle is app-specific; supply your own [Installer] for that.
class MacOsInstaller implements Installer {
  /// Creates the installer.
  MacOsInstaller({ProcessLauncher? launcher})
      : _inner =
            CommandInstaller(executable: '/usr/bin/open', launcher: launcher);

  final CommandInstaller _inner;

  @override
  Future<void> install(VerifiedUpdate update) => _inner.install(update);
}
