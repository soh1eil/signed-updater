import 'dart:convert';
import 'dart:io';

/// Fixtures produced by the Go tool (`go test ./manifest -run Interop -update`).
class Fixtures {
  Fixtures._(this.json);

  final Map<String, Object?> json;

  static Fixtures load() {
    final f = File('../../testdata/interop.json');
    return Fixtures._(jsonDecode(f.readAsStringSync()) as Map<String, Object?>);
  }

  String get context => json['context']! as String;
  String get publicKey => json['public_key']! as String;
  String get otherKey => json['other_public_key']! as String;

  Map<String, Object?> get manifest =>
      jsonDecode(jsonEncode(json['manifest'])) as Map<String, Object?>;

  List<Map<String, Object?>> get messages =>
      (json['messages']! as List<Object?>).cast<Map<String, Object?>>();

  List<Map<String, Object?>> get urls =>
      (json['urls']! as List<Object?>).cast<Map<String, Object?>>();

  List<Map<String, Object?>> get versions =>
      (json['versions']! as List<Object?>).cast<Map<String, Object?>>();

  /// Artifact bytes by name.
  Map<String, List<int>> get artifacts => {
        for (final a in (json['artifacts']! as List<Object?>)
            .cast<Map<String, Object?>>())
          a['name']! as String: base64Decode(a['base64']! as String),
      };
}

/// A loopback HTTP server serving fixed paths, with request counting.
class TestServer {
  TestServer._(this._server);

  final HttpServer _server;

  /// path -> handler
  final Map<String, void Function(HttpRequest)> routes = {};

  static Future<TestServer> start() async {
    final s = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final t = TestServer._(s);
    s.listen((req) {
      final h = t.routes[req.uri.path];
      if (h == null) {
        req.response.statusCode = 404;
        req.response.close();
      } else {
        h(req);
      }
    });
    return t;
  }

  Uri url(String path) => Uri.parse('http://127.0.0.1:${_server.port}$path');

  void serve(String path, List<int> body,
      {int status = 200, Map<String, String> headers = const {}}) {
    routes[path] = (req) {
      req.response.statusCode = status;
      headers.forEach(req.response.headers.set);
      req.response.add(body);
      req.response.close();
    };
  }

  Future<void> close() => _server.close(force: true);
}
