import 'dart:convert';

import 'errors.dart';
import 'validate.dart';

/// One published release for one platform.
class Release {
  /// Creates a release; use [Manifest.parse] for untrusted input.
  const Release({
    required this.version,
    required this.build,
    required this.platform,
    required this.url,
    required this.sha256,
    required this.size,
    required this.sig,
    required this.notes,
  });

  /// Dotted numeric version, for example `1.2.3`.
  final String version;

  /// Monotonic build number.
  final int build;

  /// Platform label such as `windows`, `linux`, `macos`.
  final String platform;

  /// Artifact path, relative to the manifest URL.
  final String url;

  /// Lowercase hex SHA-256 of the artifact.
  final String sha256;

  /// Artifact size in bytes.
  final int size;

  /// Lowercase hex Ed25519 signature over the canonical message.
  final String sig;

  /// Release notes (authenticated by the signature).
  final String notes;

  /// True when this is a later release than [other].
  bool isNewerThan(Release other) =>
      compareRelease(version, build, other.version, other.build) > 0;

  /// Rebuilds the release with a different digest, used for re-verification.
  Release withSha256(String digest) => Release(
        version: version,
        build: build,
        platform: platform,
        url: url,
        sha256: digest,
        size: size,
        sig: sig,
        notes: notes,
      );
}

/// Orders (version, build) pairs; returns -1, 0 or 1.
int compareRelease(String va, int ba, String vb, int bb) {
  final c = compareVersions(va, vb);
  if (c != 0) return c;
  return ba.compareTo(bb);
}

/// A parsed, structurally validated manifest. Signatures are NOT checked yet.
class Manifest {
  /// Creates a manifest from already validated releases.
  const Manifest(this.releases);

  /// Largest accepted manifest in bytes.
  static const int maxBytes = 1 << 20;

  /// Largest accepted number of releases.
  static const int maxReleases = 1000;

  /// All releases for all platforms.
  final List<Release> releases;

  /// Parses and validates [bytes]. Mirrors the Go parser: strict types, no
  /// trailing data, schema 1 only, duplicate entries rejected.
  factory Manifest.parse(List<int> bytes) {
    if (bytes.length > maxBytes) _bad('manifest too large');
    final Object? doc;
    try {
      doc = jsonDecode(utf8.decode(bytes));
    } on FormatException catch (e) {
      throw UpdateException(
          UpdateFailure.badManifest, 'not JSON: ${e.message}');
    }
    if (doc is! Map<String, Object?>) _bad('manifest is not an object');
    if (doc['schema'] != 1) _bad('unsupported schema');
    final list = doc['releases'];
    if (list is! List<Object?>) _bad('releases is not a list');
    if (list.length > maxReleases) _bad('too many releases');
    final out = <Release>[];
    final seen = <String>{};
    for (var i = 0; i < list.length; i++) {
      final r = _entry(list[i], i);
      if (!seen.add('${r.platform}|${r.build}|${r.version}')) {
        _bad('release $i is a duplicate');
      }
      out.add(r);
    }
    return Manifest(List.unmodifiable(out));
  }

  static Release _entry(Object? raw, int i) {
    if (raw is! Map<String, Object?>) _bad('release $i is not an object');
    String str(String k) {
      final v = raw[k];
      if (v is! String) _bad('release $i: $k must be a string');
      return v;
    }

    int num_(String k) {
      final v = raw[k];
      if (v is! int) _bad('release $i: $k must be an integer');
      return v;
    }

    final r = Release(
      version: str('version'),
      build: num_('build'),
      platform: str('platform'),
      url: str('url'),
      sha256: str('sha256'),
      size: num_('size'),
      sig: str('sig'),
      notes: raw.containsKey('notes') ? str('notes') : '',
    );
    if (!isValidVersion(r.version)) _bad('release $i: invalid version');
    if (r.build < 0 || r.build > maxBuild) _bad('release $i: invalid build');
    if (!isValidPlatform(r.platform)) _bad('release $i: invalid platform');
    if (!isValidSha256(r.sha256)) _bad('release $i: invalid sha256');
    if (r.size < 1 || r.size > maxArtifactSize)
      _bad('release $i: invalid size');
    if (!isValidSig(r.sig)) _bad('release $i: invalid sig');
    if (utf8.encode(r.notes).length > maxNotesBytes)
      _bad('release $i: notes too long');
    if (!isValidRelativeUrl(r.url))
      _bad('release $i: url must be a plain relative path');
    return r;
  }

  static Never _bad(String m) =>
      throw UpdateException(UpdateFailure.badManifest, m);
}
