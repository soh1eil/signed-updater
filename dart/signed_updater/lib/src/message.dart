import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'release.dart';

/// Signing context used when none is configured. Choose your own per app.
const String defaultSigningContext = 'signed-updater-v1';

/// Builds the canonical bytes the publisher signed for [r].
///
/// Layout (every line ends with `\n`):
/// `<context>`, `version=`, `build=`, `platform=`, `sha256=`, `size=`,
/// `notes_sha256=` (hex SHA-256 of the UTF-8 notes). Field grammar is checked
/// at parse time, so no field can contain a newline.
Future<List<int>> buildSignedMessage(String context, Release r) async {
  final notes = await Sha256().hash(utf8.encode(r.notes));
  final notesHex =
      notes.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  final text = '$context\n'
      'version=${r.version}\n'
      'build=${r.build}\n'
      'platform=${r.platform}\n'
      'sha256=${r.sha256}\n'
      'size=${r.size}\n'
      'notes_sha256=$notesHex\n';
  return utf8.encode(text);
}
