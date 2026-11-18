import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:http/http.dart' as http;
import 'package:path/path.dart' as p;

import 'errors.dart';
import 'installers/installer.dart';
import 'message.dart';
import 'release.dart';
import 'state_store.dart';
import 'validate.dart';

/// Configuration for a [SignedUpdater].
class UpdaterConfig {
  /// Creates a configuration. [publicKeys] are the pinned Ed25519 keys as
  /// 64-character hex strings; during key rotation list the old and the new.
  UpdaterConfig({
    required this.manifestUrl,
    required this.publicKeys,
    required this.platform,
    required this.currentVersion,
    required this.currentBuild,
    this.context = defaultSigningContext,
    this.allowInsecureHttp = false,
    this.requestTimeout = const Duration(seconds: 30),
  }) {
    if (publicKeys.isEmpty)
      throw ArgumentError('at least one pinned public key is required');
    for (final k in publicKeys) {
      if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(k)) {
        throw ArgumentError('public key must be 64 hex characters');
      }
    }
    if (!isValidContext(context))
      throw ArgumentError('invalid signing context');
    if (!isValidPlatform(platform)) throw ArgumentError('invalid platform');
    if (!isValidVersion(currentVersion))
      throw ArgumentError('invalid currentVersion');
    final scheme = manifestUrl.scheme;
    if (scheme != 'https' && !(allowInsecureHttp && scheme == 'http')) {
      throw ArgumentError('manifestUrl must be https');
    }
  }

  /// Where the manifest is served; artifact URLs resolve against it.
  final Uri manifestUrl;

  /// Pinned public keys (hex). Never fetched from the network.
  final List<String> publicKeys;

  /// Signing context; must equal the publisher's `-context`.
  final String context;

  /// Platform label to look for in the manifest.
  final String platform;

  /// Version of the running app.
  final String currentVersion;

  /// Build number of the running app.
  final int currentBuild;

  /// Allows `http://` (tests and local development only).
  final bool allowInsecureHttp;

  /// Per-request timeout.
  final Duration requestTimeout;
}

/// Result of [SignedUpdater.check].
sealed class UpdateCheck {
  const UpdateCheck();
}

/// Nothing newer than the running app is published.
class UpToDate extends UpdateCheck {
  /// Creates the result.
  const UpToDate();
}

/// An authenticated newer release is available.
class UpdateAvailable extends UpdateCheck {
  /// Creates the result.
  const UpdateAvailable(this.release);

  /// The signature-verified release.
  final Release release;
}

/// A downloaded file whose size, digest and signature were all verified.
class VerifiedUpdate {
  /// Creates the handle; only [SignedUpdater.download] should.
  VerifiedUpdate._(this.release, this.file, this._verify);

  /// The authenticated release metadata.
  final Release release;

  /// The verified artifact on disk.
  final File file;

  final Future<void> Function(File) _verify;

  /// Re-hashes the file from disk and re-checks the signature. Installers call
  /// this immediately before use, shrinking the window in which another local
  /// process could swap the file after the download check.
  Future<void> recheck() => _verify(file);
}

/// Checks for, downloads and installs signed updates.
class SignedUpdater {
  /// Creates an updater. Supply [client] to customise networking.
  SignedUpdater({
    required this.config,
    http.Client? client,
    StateStore? stateStore,
    this.installer,
  })  : _client = client ?? http.Client(),
        _state = stateStore ?? MemoryStateStore();

  /// Configuration.
  final UpdaterConfig config;

  /// Applies verified updates; may be null if the app installs by itself.
  final Installer? installer;

  final http.Client _client;
  final StateStore _state;

  List<SimplePublicKey>? _keys;

  List<SimplePublicKey> get _pinned => _keys ??= config.publicKeys
      .map((h) => SimplePublicKey(_hex(h), type: KeyPairType.ed25519))
      .toList();

  /// Fetches the manifest and returns the newest authenticated release for
  /// this platform if it is newer than the running app.
  ///
  /// Throws [UpdateException] with [UpdateFailure.badSignature] when entries
  /// exist but none verifies, and [UpdateFailure.rollback] when the best
  /// authenticated release is older than one already seen.
  Future<UpdateCheck> check() async {
    final bytes = await _get(config.manifestUrl, Manifest.maxBytes);
    final manifest = Manifest.parse(bytes);
    final mine =
        manifest.releases.where((r) => r.platform == config.platform).toList();
    final good = <Release>[];
    for (final r in mine) {
      if (await _verifySignature(r)) good.add(r);
    }
    if (mine.isNotEmpty && good.isEmpty) {
      throw UpdateException(UpdateFailure.badSignature,
          'no release for ${config.platform} carries a valid signature');
    }
    if (good.isEmpty) return const UpToDate();
    var best = good.first;
    for (final r in good.skip(1)) {
      if (r.isNewerThan(best)) best = r;
    }
    final mark = await _state.read();
    if (mark != null &&
        compareRelease(best.version, best.build, mark.version, mark.build) <
            0) {
      throw UpdateException(UpdateFailure.rollback,
          'manifest offers ${best.version}+${best.build}, older than already seen ${mark.version}+${mark.build}');
    }
    if (mark == null ||
        compareRelease(best.version, best.build, mark.version, mark.build) >
            0) {
      await _state.write(HighWaterMark(best.version, best.build));
    }
    if (compareRelease(best.version, best.build, config.currentVersion,
            config.currentBuild) <=
        0) {
      return const UpToDate();
    }
    return UpdateAvailable(best);
  }

  /// Downloads [release] into [directory], verifying as it streams and again
  /// from disk afterwards. The returned file exists only if everything matched.
  Future<VerifiedUpdate> download(
    Release release,
    Directory directory, {
    void Function(int received, int total)? onProgress,
  }) async {
    if (release.platform != config.platform ||
        compareRelease(release.version, release.build, config.currentVersion,
                config.currentBuild) <=
            0) {
      throw UpdateException(UpdateFailure.rollback,
          'refusing to download a non-newer or foreign release');
    }
    // Never trust a Release object blindly: it may have been built by app code.
    if (!await _verifySignature(release) || !isValidRelativeUrl(release.url)) {
      throw UpdateException(
          UpdateFailure.badSignature, 'release does not verify');
    }
    final url = _resolve(release.url);
    await directory.create(recursive: true);
    final stamp = Random.secure().nextInt(1 << 32).toRadixString(16);
    final part = File(p.join(directory.path, '.update-$stamp.part'));
    final sink = part.openWrite();
    final hash = Sha256().newHashSink();
    var received = 0;
    try {
      final response = await _open(url);
      if (response.contentLength != null &&
          response.contentLength != release.size) {
        throw UpdateException(UpdateFailure.integrity,
            'Content-Length ${response.contentLength} differs from signed size ${release.size}');
      }
      await for (final chunk
          in response.stream.timeout(config.requestTimeout)) {
        received += chunk.length;
        if (received > release.size) {
          throw UpdateException(
              UpdateFailure.integrity, 'download exceeds the signed size');
        }
        hash.add(chunk);
        sink.add(chunk);
        onProgress?.call(received, release.size);
      }
      await sink.flush();
      await sink.close();
      hash.close();
      if (received != release.size) {
        throw UpdateException(UpdateFailure.integrity,
            'download is shorter than the signed size');
      }
      final digest = _toHex((await hash.hash()).bytes);
      if (digest != release.sha256) {
        throw UpdateException(UpdateFailure.integrity, 'sha256 mismatch');
      }
      final ext = _safeExtension(release.url);
      final finalFile = File(p.join(directory.path,
          'update-${release.platform}-${release.version}-${release.build}$ext'));
      if (await finalFile.exists()) await finalFile.delete();
      await part.rename(finalFile.path);
      final verified =
          VerifiedUpdate._(release, finalFile, (f) => _recheck(release, f));
      await verified.recheck();
      return verified;
    } on UpdateException {
      await _discard(sink, part);
      rethrow;
    } on Object catch (e) {
      await _discard(sink, part);
      throw UpdateException(UpdateFailure.network, 'download failed: $e');
    }
  }

  /// Installs a verified update with the configured [installer].
  Future<void> install(VerifiedUpdate update) {
    final i = installer;
    if (i == null) {
      throw UpdateException(
          UpdateFailure.installFailed, 'no installer configured');
    }
    return i.install(update);
  }

  /// Releases the HTTP client.
  void close() => _client.close();

  Future<void> _discard(IOSink sink, File part) async {
    try {
      await sink.close();
    } on Object {
      // Already closed or failed; the file is removed below regardless.
    }
    if (await part.exists()) await part.delete();
  }

  Future<void> _recheck(Release r, File f) async {
    final sink = Sha256().newHashSink();
    await for (final chunk in f.openRead()) {
      sink.add(chunk);
    }
    sink.close();
    final digest = _toHex((await sink.hash()).bytes);
    if (await f.length() != r.size || digest != r.sha256) {
      throw UpdateException(
          UpdateFailure.integrity, 'file changed after download');
    }
    // Verify again with the digest we just computed, not the one in memory.
    if (!await _verifySignature(r.withSha256(digest))) {
      throw UpdateException(UpdateFailure.badSignature,
          'signature does not cover the file on disk');
    }
  }

  Future<bool> _verifySignature(Release r) async {
    final message = await buildSignedMessage(config.context, r);
    final sig = _hex(r.sig);
    for (final key in _pinned) {
      final ok = await Ed25519()
          .verify(message, signature: Signature(sig, publicKey: key));
      if (ok) return true;
    }
    return false;
  }

  Uri _resolve(String relative) {
    final base = config.manifestUrl;
    final u = base.resolve(relative);
    if (u.scheme != base.scheme ||
        u.host != base.host ||
        u.port != base.port ||
        u.hasFragment) {
      throw UpdateException(
          UpdateFailure.badUrl, 'artifact URL leaves the manifest origin');
    }
    return u;
  }

  Future<Uint8List> _get(Uri url, int limit) async {
    final response = await _open(url);
    final out = BytesBuilder(copy: false);
    await for (final chunk in response.stream.timeout(config.requestTimeout)) {
      out.add(chunk);
      if (out.length > limit) {
        throw UpdateException(UpdateFailure.badManifest, 'manifest too large');
      }
    }
    return out.takeBytes();
  }

  /// GET with manual redirects: only same-origin hops, at most three.
  Future<http.StreamedResponse> _open(Uri start) async {
    var url = start;
    for (var hop = 0; hop <= 3; hop++) {
      final req = http.Request('GET', url)..followRedirects = false;
      final http.StreamedResponse res;
      try {
        res = await _client.send(req).timeout(config.requestTimeout);
      } on UpdateException {
        rethrow;
      } on Object catch (e) {
        throw UpdateException(UpdateFailure.network, 'request failed: $e');
      }
      if (res.isRedirect) {
        final loc = res.headers['location'];
        await res.stream.drain<void>();
        if (loc == null)
          throw UpdateException(
              UpdateFailure.network, 'redirect without Location');
        final next = url.resolve(loc);
        if (next.scheme != config.manifestUrl.scheme ||
            next.host != config.manifestUrl.host ||
            next.port != config.manifestUrl.port) {
          throw UpdateException(
              UpdateFailure.badUrl, 'redirect leaves the manifest origin');
        }
        url = next;
        continue;
      }
      if (res.statusCode != 200) {
        await res.stream.drain<void>();
        throw UpdateException(UpdateFailure.network, 'HTTP ${res.statusCode}');
      }
      return res;
    }
    throw UpdateException(UpdateFailure.network, 'too many redirects');
  }

  static String _safeExtension(String url) {
    final q = url.indexOf('?');
    final path = q >= 0 ? url.substring(0, q) : url;
    final base = path.split('/').last;
    final m = RegExp(r'(\.tar)?(\.[a-zA-Z0-9]{1,12})$').firstMatch(base);
    return m == null ? '' : m.group(0)!.toLowerCase();
  }

  static Uint8List _hex(String h) {
    final out = Uint8List(h.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(h.substring(2 * i, 2 * i + 2), radix: 16);
    }
    return out;
  }

  static String _toHex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}
