import 'dart:convert';
import 'dart:io';

/// Highest authenticated release ever seen, persisted for rollback protection.
class HighWaterMark {
  /// Creates a mark.
  const HighWaterMark(this.version, this.build);

  /// Version string.
  final String version;

  /// Build number.
  final int build;
}

/// Persists the [HighWaterMark] between runs.
abstract interface class StateStore {
  /// Returns the stored mark, or null when none exists or it is unreadable.
  Future<HighWaterMark?> read();

  /// Stores [mark].
  Future<void> write(HighWaterMark mark);
}

/// Non-persistent store, for tests or when the host app keeps its own state.
class MemoryStateStore implements StateStore {
  HighWaterMark? _mark;

  @override
  Future<HighWaterMark?> read() async => _mark;

  @override
  Future<void> write(HighWaterMark mark) async => _mark = mark;
}

/// Stores the mark as a small JSON file, replaced atomically.
class FileStateStore implements StateStore {
  /// Uses [path] for the state file; its directory must exist.
  FileStateStore(this.path);

  /// Location of the JSON file.
  final String path;

  @override
  Future<HighWaterMark?> read() async {
    try {
      final j = jsonDecode(await File(path).readAsString());
      if (j is Map<String, Object?> &&
          j['version'] is String &&
          j['build'] is int) {
        return HighWaterMark(j['version']! as String, j['build']! as int);
      }
    } on Object {
      // Missing or corrupt state means "no history", not a crash.
    }
    return null;
  }

  @override
  Future<void> write(HighWaterMark mark) async {
    final tmp = File('$path.tmp');
    await tmp.writeAsString(
        jsonEncode({'version': mark.version, 'build': mark.build}),
        flush: true);
    await tmp.rename(path);
  }
}
