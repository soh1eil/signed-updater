import 'dart:convert';

import 'package:signed_updater/signed_updater.dart';
import 'package:test/test.dart';

import 'support.dart';

/// Cross-implementation checks: every value here was produced by the Go
/// `updsign` code, and Dart must accept or reject it identically.
void main() {
  final fx = Fixtures.load();

  test('canonical message matches the Go bytes exactly', () async {
    for (final m in fx.messages) {
      final entry = Manifest.parse(utf8.encode(jsonEncode({
        'schema': 1,
        'releases': [m['entry']]
      }))).releases.single;
      final bytes = await buildSignedMessage(fx.context, entry);
      expect(utf8.decode(bytes), m['message'], reason: m['name']! as String);
    }
  });

  group('Go-made signatures verify in Dart', () {
    for (final platform in ['windows', 'linux']) {
      test(platform, () async {
        final server = await TestServer.start();
        addTearDown(server.close);
        server.serve('/m.json', utf8.encode(jsonEncode(fx.manifest)));
        final u = SignedUpdater(
          config: UpdaterConfig(
            manifestUrl: server.url('/m.json'),
            publicKeys: [fx.publicKey],
            context: fx.context,
            platform: platform,
            currentVersion: '0.1.0',
            currentBuild: 1,
            allowInsecureHttp: true,
          ),
        );
        final r = await u.check();
        expect(r, isA<UpdateAvailable>());
        expect((r as UpdateAvailable).release.version, '1.1.0');
      });
    }
  });

  test('unicode and multi-line notes are authenticated', () async {
    final win = fx.messages[1]['entry']! as Map<String, Object?>;
    expect(win['notes'], contains('\n'));
    final tampered = fx.manifest;
    final rel =
        (tampered['releases']! as List<Object?>)[1]! as Map<String, Object?>;
    rel['notes'] = '${rel['notes']} ';
    final server = await TestServer.start();
    addTearDown(server.close);
    server.serve('/m.json', utf8.encode(jsonEncode(tampered)));
    final u =
        _updater(server, fx, platform: 'windows', version: '1.0.0', build: 10);
    // The 1.1.0 entry no longer verifies; the untouched 1.0.0 is not newer.
    expect(await u.check(), isA<UpToDate>());
  });

  test('wrong pinned key and wrong context are rejected', () async {
    final server = await TestServer.start();
    addTearDown(server.close);
    server.serve('/m.json', utf8.encode(jsonEncode(fx.manifest)));
    final wrongKey = _updater(server, fx, key: fx.otherKey);
    await expectLater(
        wrongKey.check(), throwsA(_failure(UpdateFailure.badSignature)));
    final wrongCtx = _updater(server, fx, context: 'another-app-v1');
    await expectLater(
        wrongCtx.check(), throwsA(_failure(UpdateFailure.badSignature)));
    final rotation = SignedUpdater(
      config: UpdaterConfig(
        manifestUrl: server.url('/m.json'),
        publicKeys: [fx.otherKey, fx.publicKey],
        context: fx.context,
        platform: 'linux',
        currentVersion: '1.0.0',
        currentBuild: 1,
        allowInsecureHttp: true,
      ),
    );
    expect(await rotation.check(), isA<UpdateAvailable>());
  });

  test('relative URL grammar agrees with Go', () {
    for (final c in fx.urls) {
      expect(isValidRelativeUrl(c['url']! as String), c['valid'],
          reason: c['url']! as String);
    }
  });

  test('version ordering agrees with Go', () {
    for (final c in fx.versions) {
      expect(compareVersions(c['A']! as String, c['B']! as String), c['Want'],
          reason: '${c['A']} vs ${c['B']}');
    }
  });
}

SignedUpdater _updater(TestServer s, Fixtures fx,
    {String? key,
    String? context,
    String platform = 'linux',
    String version = '1.0.0',
    int build = 1}) {
  return SignedUpdater(
    config: UpdaterConfig(
      manifestUrl: s.url('/m.json'),
      publicKeys: [key ?? fx.publicKey],
      context: context ?? fx.context,
      platform: platform,
      currentVersion: version,
      currentBuild: build,
      allowInsecureHttp: true,
    ),
  );
}

Matcher _failure(UpdateFailure f) =>
    isA<UpdateException>().having((e) => e.failure, 'failure', f);
