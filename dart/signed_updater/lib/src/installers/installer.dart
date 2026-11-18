import '../updater.dart';

/// Applies a verified update. Implement this for a platform or packaging
/// format that the bundled installers do not cover.
abstract interface class Installer {
  /// Starts installation of [update]. Implementations MUST call
  /// [VerifiedUpdate.recheck] immediately before touching the file.
  Future<void> install(VerifiedUpdate update);
}

/// Starts an external process; replaceable in tests.
typedef ProcessLauncher = Future<void> Function(
    String executable, List<String> arguments);
