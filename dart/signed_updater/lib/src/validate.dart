/// Field grammar shared byte-for-byte with the Go `signing` package.
library;

final RegExp _versionRe =
    RegExp(r'^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,3}$');
final RegExp _platformRe = RegExp(r'^[a-z0-9][a-z0-9_-]{0,31}$');
final RegExp _sha256Re = RegExp(r'^[0-9a-f]{64}$');
final RegExp _sigRe = RegExp(r'^[0-9a-f]{128}$');

/// Largest accepted notes size in UTF-8 bytes.
const int maxNotesBytes = 16 * 1024;

/// Largest accepted artifact size (1 TiB).
const int maxArtifactSize = 1 << 40;

/// Largest accepted build number.
const int maxBuild = 0x7fffffff;

/// True for 1-4 numeric components without leading zeros.
bool isValidVersion(String v) => _versionRe.hasMatch(v);

/// True for a lowercase platform label.
bool isValidPlatform(String p) => _platformRe.hasMatch(p);

/// True for 64 lowercase hex characters.
bool isValidSha256(String s) => _sha256Re.hasMatch(s);

/// True for 128 lowercase hex characters.
bool isValidSig(String s) => _sigRe.hasMatch(s);

/// True for 1-64 printable ASCII characters.
bool isValidContext(String c) {
  if (c.isEmpty || c.length > 64) return false;
  return c.codeUnits.every((u) => u >= 0x20 && u <= 0x7e);
}

/// Compares two valid versions numerically; missing components are zero.
int compareVersions(String a, String b) {
  final pa = a.split('.').map(int.parse).toList();
  final pb = b.split('.').map(int.parse).toList();
  final n = pa.length > pb.length ? pa.length : pb.length;
  for (var i = 0; i < n; i++) {
    final x = i < pa.length ? pa[i] : 0;
    final y = i < pb.length ? pb[i] : 0;
    if (x != y) return x < y ? -1 : 1;
  }
  return 0;
}

/// True when [u] is a plain relative path that cannot leave the origin.
///
/// Rejects schemes, authorities, backslashes, control characters, whitespace,
/// fragments, leading slashes, empty segments, `.`/`..` (also percent-encoded)
/// and encoded separators. Mirrors Go's `ValidRelativeURL` exactly.
bool isValidRelativeUrl(String u) {
  if (u.isEmpty || u.length > 512 || u.startsWith('/')) return false;
  for (final c in u.codeUnits) {
    if (c <= 0x20 || c >= 0x7f || c == 0x5c || c == 0x23) return false;
  }
  final q = u.indexOf('?');
  final path = q >= 0 ? u.substring(0, q) : u;
  if (path.contains(':') || path.isEmpty) return false;
  for (final seg in path.split('/')) {
    if (seg.isEmpty) return false;
    final dec = _percentDecode(seg);
    if (dec == null) return false;
    if (dec == '.' || dec == '..' || dec.contains('/') || dec.contains(r'\')) {
      return false;
    }
    if (dec.codeUnits.any((c) => c < 0x20 || c == 0x7f)) return false;
  }
  return true;
}

String? _percentDecode(String s) {
  if (!s.contains('%')) return s;
  final out = StringBuffer();
  for (var i = 0; i < s.length; i++) {
    if (s[i] != '%') {
      out.write(s[i]);
      continue;
    }
    if (i + 2 >= s.length) return null;
    final hex = s.substring(i + 1, i + 3);
    if (!RegExp(r'^[0-9a-fA-F]{2}$').hasMatch(hex)) return null;
    out.writeCharCode(int.parse(hex, radix: 16));
    i += 2;
  }
  return out.toString();
}
