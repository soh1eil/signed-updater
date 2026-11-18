import 'dart:convert';
import 'dart:io';

import 'package:signed_updater/signed_updater.dart';
import 'package:test/test.dart';

import 'support.dart';

class _Rec implements Installer {
  VerifiedUpdate? got;
  @override
  Future<void> install(VerifiedUpdate update) async {
    await update.recheck();
    got = update;
  }
}

void main() {
  final fx = Fixtures.load();
  late TestServer server;
  late Directory tmp;
  final win110 = fx.artifacts['win-1.1.0.bin']!;

  setUp(() async {
    server = await TestServer.start();
    tmp = await Directory.systemTemp.createTemp('su-test');
    server.serve('/app/m.json', utf8.encode(jsonEncode(fx.manifest)));
    server.serve('/app/files/win-1.1.0.bin', win110);
    server.serve('/app/files/win-1.0.0.bin', fx.artifacts['win-1.0.0.bin']!);
  });
  tearDown(() async {
    await server.close();
    await tmp.delete(recursive: true);
  });

  SignedUpdater make({
    String version = '1.0.0',
    int build = 10,
    StateStore? state,
    Installer? installer,
    String path = '/app/m.json',
  }) =>
      SignedUpdater(
        config: UpdaterConfig(
          manifestUrl: server.url(path),
          publicKeys: [fx.publicKey],
          context: fx.context,
          platform: 'windows',
          currentVersion: version,
          currentBuild: build,
          allowInsecureHttp: true,
        ),
        stateStore: state,
        installer: installer,
      );

  Future<Release> available(SignedUpdater u) async =>
      ((await u.check()) as UpdateAvailable).release;

  test('happy path: check, download, install', () async {
    final rec = _Rec();
    final u = make(installer: rec);
    final r = await available(u);
    var lastProgress = 0;
    final v = await u.download(r, tmp, onProgress: (a, t) => lastProgress = a);
    expect(lastProgress, win110.length);
    expect(await v.file.readAsBytes(), win110);
    expect(v.file.path, endsWith('.bin'));
    await u.install(v);
    expect(rec.got, same(v));
    // Only the verified file remains in the download directory.
    expect(tmp.listSync().map((e) => e.path.split('/').last).toList(),
        ['update-windows-1.1.0-11.bin']);
  });

  test('current version is up to date; older build is not offered', () async {
    expect(await make(version: '1.1.0', build: 11).check(), isA<UpToDate>());
    expect(await make(version: '2.0.0', build: 1).check(), isA<UpToDate>());
  });

  test('same version, higher build is an update', () async {
    expect(await make(version: '1.1.0', build: 10).check(),
        isA<UpdateAvailable>());
  });

  test('tampered artifact is refused and nothing is left on disk', () async {
    server.serve('/app/files/win-1.1.0.bin', [...win110]..[0] ^= 1);
    final u = make();
    final r = await available(u);
    await expectLater(
        u.download(r, tmp), throwsA(_failure(UpdateFailure.integrity)));
    expect(tmp.listSync(), isEmpty);
  });

  test('oversized and truncated downloads are refused', () async {
    final u = make();
    final r = await available(u);
    server.serve('/app/files/win-1.1.0.bin', [...win110, 0]);
    await expectLater(
        u.download(r, tmp), throwsA(_failure(UpdateFailure.integrity)));
    server.serve(
        '/app/files/win-1.1.0.bin', win110.sublist(0, win110.length - 1));
    await expectLater(
        u.download(r, tmp), throwsA(_failure(UpdateFailure.integrity)));
    expect(tmp.listSync(), isEmpty);
  });

  test('download error status', () async {
    server.serve('/app/files/win-1.1.0.bin', [], status: 500);
    final u = make();
    await expectLater(u.download(await available(u), tmp),
        throwsA(_failure(UpdateFailure.network)));
  });

  test('rollback: a manifest older than one already seen is refused', () async {
    final state = MemoryStateStore();
    await make(state: state).check(); // sees 1.1.0+11
    final old = fx.manifest;
    (old['releases']! as List<Object?>).removeAt(1); // publisher drops 1.1.0
    server.serve('/app/m.json', utf8.encode(jsonEncode(old)));
    await expectLater(
        make(state: state).check(), throwsA(_failure(UpdateFailure.rollback)));
    // Without history, the same manifest is simply "nothing newer" for 1.0.0+10.
    expect(await make().check(), isA<UpToDate>());
  });

  test('file state store persists the mark', () async {
    final s = FileStateStore('${tmp.path}/state.json');
    expect(await s.read(), isNull);
    await s.write(const HighWaterMark('1.2.3', 4));
    final m = (await FileStateStore('${tmp.path}/state.json').read())!;
    expect([m.version, m.build], ['1.2.3', 4]);
    File('${tmp.path}/state.json').writeAsStringSync('{garbage');
    expect(await s.read(), isNull);
  });

  test('absolute or traversing artifact URLs make the manifest invalid',
      () async {
    for (final bad in [
      'https://evil.example/x.exe',
      '/etc/passwd',
      '../x',
      'a/%2e%2e/b',
      r'a\b'
    ]) {
      final m = fx.manifest;
      ((m['releases']! as List<Object?>)[1]! as Map<String, Object?>)['url'] =
          bad;
      server.serve('/app/m.json', utf8.encode(jsonEncode(m)));
      await expectLater(
          make().check(), throwsA(_failure(UpdateFailure.badManifest)),
          reason: bad);
    }
  });

  test('changing any signed field breaks the signature', () async {
    final edits = <String, Object?>{
      'version': '9.9.9',
      'build': 99,
      'size': 5,
      'sha256': 'f' * 64,
      'notes': 'phish',
    };
    for (final e in edits.entries) {
      final m = fx.manifest;
      final rels = m['releases']! as List<Object?>;
      ((rels[1]! as Map<String, Object?>))[e.key] = e.value;
      rels.removeAt(0);
      rels.removeLast(); // keep only the edited windows entry
      server.serve('/app/m.json', utf8.encode(jsonEncode(m)));
      await expectLater(
          make().check(), throwsA(_failure(UpdateFailure.badSignature)),
          reason: e.key);
    }
  });

  test('platform label is signed: windows entry cannot be served as linux',
      () async {
    final m = fx.manifest;
    final rels = m['releases']! as List<Object?>;
    (rels[1]! as Map<String, Object?>)['platform'] = 'linux';
    rels.removeAt(2);
    rels.removeAt(0);
    server.serve('/app/m.json', utf8.encode(jsonEncode(m)));
    final u = SignedUpdater(
      config: UpdaterConfig(
        manifestUrl: server.url('/app/m.json'),
        publicKeys: [fx.publicKey],
        context: fx.context,
        platform: 'linux',
        currentVersion: '0.1.0',
        currentBuild: 1,
        allowInsecureHttp: true,
      ),
    );
    await expectLater(u.check(), throwsA(_failure(UpdateFailure.badSignature)));
  });

  test('redirects: same origin followed, cross origin refused', () async {
    server.routes['/app/files/win-1.1.0.bin'] = (req) {
      req.response.statusCode = 302;
      req.response.headers.set('location', '/app/files/win-1.0.0.bin');
      req.response.close();
    };
    final u = make();
    // Redirected to a different (validly signed) artifact: digest mismatch.
    await expectLater(u.download(await available(u), tmp),
        throwsA(_failure(UpdateFailure.integrity)));
    server.routes['/app/files/win-1.1.0.bin'] = (req) {
      req.response.statusCode = 302;
      req.response.headers
          .set('location', 'http://localhost:${server.url('/').port}/x');
      req.response.close();
    };
    await expectLater(u.download(await available(u), tmp),
        throwsA(_failure(UpdateFailure.badUrl)));
  });

  test('a release that was not authenticated is not downloaded', () async {
    final u = make();
    final r = await available(u);
    final forged = Release(
        version: '9.0.0',
        build: 99,
        platform: r.platform,
        url: r.url,
        sha256: r.sha256,
        size: r.size,
        sig: r.sig,
        notes: r.notes);
    await expectLater(
        u.download(forged, tmp), throwsA(_failure(UpdateFailure.badSignature)));
  });

  test('recheck detects a file swapped after download', () async {
    final u = make();
    final v = await u.download(await available(u), tmp);
    await v.recheck();
    await v.file.writeAsBytes([...win110]..[0] ^= 1);
    await expectLater(v.recheck(), throwsA(_failure(UpdateFailure.integrity)));
    final rec = _Rec();
    await expectLater(
        make(installer: rec).install(v), throwsA(isA<UpdateException>()));
  });

  test('manifest size cap and bad JSON', () async {
    server.serve('/app/big.json', List.filled(Manifest.maxBytes + 10, 0x20));
    await expectLater(make(path: '/app/big.json').check(),
        throwsA(_failure(UpdateFailure.badManifest)));
    server.serve('/app/bad.json', utf8.encode('{"schema":1,"releases":['));
    await expectLater(make(path: '/app/bad.json').check(),
        throwsA(_failure(UpdateFailure.badManifest)));
    server.serve('/app/s2.json', utf8.encode('{"schema":2,"releases":[]}'));
    await expectLater(make(path: '/app/s2.json').check(),
        throwsA(_failure(UpdateFailure.badManifest)));
    await expectLater(make(path: '/app/missing.json').check(),
        throwsA(_failure(UpdateFailure.network)));
  });

  test('config refuses plain http and bad keys', () {
    expect(
        () => UpdaterConfig(
            manifestUrl: Uri.parse('http://example.com/m.json'),
            publicKeys: [fx.publicKey],
            platform: 'linux',
            currentVersion: '1.0.0',
            currentBuild: 1),
        throwsArgumentError);
    expect(
        () => UpdaterConfig(
            manifestUrl: Uri.parse('https://example.com/m.json'),
            publicKeys: const ['abcd'],
            platform: 'linux',
            currentVersion: '1.0.0',
            currentBuild: 1),
        throwsArgumentError);
    expect(
        () => UpdaterConfig(
            manifestUrl: Uri.parse('https://example.com/m.json'),
            publicKeys: const [],
            platform: 'linux',
            currentVersion: '1.0.0',
            currentBuild: 1),
        throwsArgumentError);
  });

  group('installers', () {
    test(
        'command installer passes the file as an argument, not through a shell',
        () async {
      final u = make();
      final v = await u.download(await available(u), tmp);
      final calls = <List<String>>[];
      await CommandInstaller(
        executable: 'tool',
        arguments: ['--x'],
        launcher: (e, a) async => calls.add([e, ...a]),
      ).install(v);
      expect(calls.single, ['tool', '--x', v.file.path]);
      await WindowsInstaller(
          arguments: ['/S'],
          launcher: (e, a) async => calls.add([e, ...a])).install(v);
      expect(calls.last, [v.file.path, '/S']);
      await MacOsInstaller(launcher: (e, a) async => calls.add([e, ...a]))
          .install(v);
      expect(calls.last, ['/usr/bin/open', v.file.path]);
    });

    test('launcher failure becomes installFailed', () async {
      final u = make();
      final v = await u.download(await available(u), tmp);
      await expectLater(
          WindowsInstaller(launcher: (e, a) async => throw StateError('boom'))
              .install(v),
          throwsA(_failure(UpdateFailure.installFailed)));
    });

    test('linux installer replaces the target atomically and keeps .old',
        () async {
      final u = make();
      final v = await u.download(await available(u), tmp);
      final target = File('${tmp.path}/app.AppImage')..writeAsStringSync('old');
      await LinuxInstaller(target.path).install(v);
      expect(await target.readAsBytes(), win110);
      expect(File('${target.path}.old').readAsStringSync(), 'old');
      expect(File('${target.path}.new').existsSync(), isFalse);
    }, skip: Platform.isWindows);
  });
}

Matcher _failure(UpdateFailure f) =>
    isA<UpdateException>().having((e) => e.failure, 'failure', f);
