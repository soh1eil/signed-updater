import 'dart:io';

import '../errors.dart';
import '../updater.dart';
import 'installer.dart';

/// Runs the verified file as a detached command, with optional arguments.
///
/// The file path is passed as an argument vector entry, never through a shell.
class CommandInstaller implements Installer {
  /// [arguments] are placed before the file path unless [fileFirst] is true.
  CommandInstaller({
    this.arguments = const [],
    this.fileFirst = false,
    ProcessLauncher? launcher,
    this.executable,
  }) : _launcher = launcher ?? _detached;

  /// Arguments passed to the process.
  final List<String> arguments;

  /// Put the file path before [arguments].
  final bool fileFirst;

  /// When set, this program is run with the file as an argument; otherwise the
  /// verified file itself is executed.
  final String? executable;

  final ProcessLauncher _launcher;

  static Future<void> _detached(String exe, List<String> args) async {
    await Process.start(exe, args, mode: ProcessStartMode.detached);
  }

  @override
  Future<void> install(VerifiedUpdate update) async {
    await update.recheck();
    final file = update.file.path;
    try {
      if (executable != null) {
        await _launcher(executable!,
            fileFirst ? [file, ...arguments] : [...arguments, file]);
      } else {
        await _launcher(file, arguments);
      }
    } on Object catch (e) {
      throw UpdateException(
          UpdateFailure.installFailed, 'could not start installer: $e');
    }
  }
}
