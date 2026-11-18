import '../updater.dart';
import 'command_installer.dart';
import 'installer.dart';

/// Runs a verified `.exe` installer (Inno Setup, NSIS, WiX bootstrapper ...).
///
/// Pass the silent-install switches your installer technology understands,
/// for example `['/VERYSILENT', '/NORESTART']` for Inno Setup. The caller is
/// responsible for exiting the app afterwards so files are not locked.
class WindowsInstaller implements Installer {
  /// Creates the installer.
  WindowsInstaller(
      {List<String> arguments = const [], ProcessLauncher? launcher})
      : _inner = CommandInstaller(arguments: arguments, launcher: launcher);

  final CommandInstaller _inner;

  @override
  Future<void> install(VerifiedUpdate update) => _inner.install(update);
}
