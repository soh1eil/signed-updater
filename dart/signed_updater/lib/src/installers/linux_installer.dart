import 'dart:io';

import '../errors.dart';
import '../updater.dart';
import 'installer.dart';

/// Replaces a single-file executable (typically an AppImage) in place.
///
/// The verified file is copied next to [targetPath], marked executable, and
/// renamed over the target, which is atomic on one filesystem. The previous
/// file is kept as `<target>.old` for manual recovery.
class LinuxInstaller implements Installer {
  /// [targetPath] is the file to replace, for example `$APPIMAGE`.
  LinuxInstaller(this.targetPath);

  /// File that will be replaced.
  final String targetPath;

  @override
  Future<void> install(VerifiedUpdate update) async {
    await update.recheck();
    final staged = File('$targetPath.new');
    try {
      await update.file.copy(staged.path);
      final r = await Process.run('chmod', ['755', staged.path]);
      if (r.exitCode != 0) throw StateError('chmod failed: ${r.stderr}');
      final target = File(targetPath);
      final old = File('$targetPath.old');
      final hadTarget = await target.exists();
      if (hadTarget) await target.rename(old.path);
      try {
        await staged.rename(targetPath);
      } on Object {
        if (hadTarget) await old.rename(targetPath);
        rethrow;
      }
    } on Object catch (e) {
      if (await staged.exists()) await staged.delete();
      throw UpdateException(
          UpdateFailure.installFailed, 'could not replace $targetPath: $e');
    }
  }
}
