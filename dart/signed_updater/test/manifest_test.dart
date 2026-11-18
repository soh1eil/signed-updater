import 'dart:convert';

import 'package:signed_updater/signed_updater.dart';
import 'package:test/test.dart';

String _rel(Map<String, Object?> over) => jsonEncode({
      'schema': 1,
      'releases': [
        {
          'version': '1.0.0',
          'build': 1,
          'platform': 'linux',
          'url': 'a/b.bin',
          'sha256': '0' * 64,
          'size': 5,
          'sig': 'a' * 128,
          'notes': '',
          ...over,
        }
      ],
    });

void main() {
  test('accepts a well-formed manifest', () {
    expect(Manifest.parse(utf8.encode(_rel({}))).releases, hasLength(1));
  });

  test('rejects wrong types and grammar violations', () {
    final cases = <String, Map<String, Object?>>{
      'float build': {'build': 1.5},
      'string build': {'build': '1'},
      'negative build': {'build': -1},
      'version leading zero': {'version': '01.0'},
      'prerelease': {'version': '1.0.0-beta'},
      'upper platform': {'platform': 'Linux'},
      'short sha': {'sha256': 'ab'},
      'upper sha': {'sha256': 'A' * 64},
      'zero size': {'size': 0},
      'short sig': {'sig': 'a' * 64},
      'notes number': {'notes': 3},
      'absolute url': {'url': 'https://x/y'},
    };
    cases.forEach((name, over) {
      expect(() => Manifest.parse(utf8.encode(_rel(over))),
          throwsA(isA<UpdateException>()),
          reason: name);
    });
  });

  test('rejects structural problems', () {
    for (final s in [
      '',
      'null',
      '[]',
      '{}',
      '{"schema":1}',
      '{"schema":"1","releases":[]}',
      '\u0000'
    ]) {
      expect(
          () => Manifest.parse(utf8.encode(s)), throwsA(isA<UpdateException>()),
          reason: s);
    }
    expect(() => Manifest.parse([0xff, 0xfe]), throwsA(isA<UpdateException>()));
    final dup = jsonDecode(_rel({})) as Map<String, Object?>;
    final list = dup['releases']! as List<Object?>;
    list.add(list.first);
    expect(() => Manifest.parse(utf8.encode(jsonEncode(dup))),
        throwsA(isA<UpdateException>()));
  });

  test('context validation', () {
    expect(isValidContext('app-update-v1'), isTrue);
    expect(isValidContext(''), isFalse);
    expect(isValidContext('a\nb'), isFalse);
    expect(isValidContext('x' * 65), isFalse);
  });
}
