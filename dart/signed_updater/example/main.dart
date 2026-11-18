// ignore_for_file: avoid_print
import 'dart:io';

import 'package:signed_updater/signed_updater.dart';

/// Minimal desktop flow: check, download, install.
Future<void> main() async {
  final updater = SignedUpdater(
    config: UpdaterConfig(
      manifestUrl: Uri.parse('https://example.com/updates/linux.json'),
      // Output of `updsign keygen`, compiled into the app. Never fetched.
      publicKeys: [
        '0000000000000000000000000000000000000000000000000000000000000000'
      ],
      context: 'myapp-update-v1', // must equal updsign's -context
      platform: 'linux',
      currentVersion: '1.0.0',
      currentBuild: 1,
    ),
    stateStore:
        FileStateStore('${Directory.systemTemp.path}/myapp-update-state.json'),
    installer: LinuxInstaller('/opt/myapp/MyApp.AppImage'),
  );
  try {
    final result = await updater.check();
    if (result is UpdateAvailable) {
      final dir = Directory('${Directory.systemTemp.path}/myapp-updates');
      final verified = await updater.download(result.release, dir);
      await updater.install(verified);
    }
  } on UpdateException catch (e) {
    print('update refused: $e');
  } finally {
    updater.close();
  }
}
