/// Why an update step was refused.
enum UpdateFailure {
  /// Network, HTTP status or redirect problem.
  network,

  /// The manifest is malformed, oversized or violates the grammar.
  badManifest,

  /// No entry carried a signature that verifies under a pinned key.
  badSignature,

  /// The offered release is older than one already seen or installed.
  rollback,

  /// The downloaded bytes do not match the signed size or digest.
  integrity,

  /// The manifest URL or an artifact URL breaks the origin rules.
  badUrl,

  /// The installer could not start.
  installFailed,
}

/// Thrown for every refusal. The [message] never contains secrets.
class UpdateException implements Exception {
  /// Creates an exception of the given [failure] kind.
  UpdateException(this.failure, this.message);

  /// Machine-readable reason.
  final UpdateFailure failure;

  /// Human-readable detail for logs.
  final String message;

  @override
  String toString() => 'UpdateException(${failure.name}): $message';
}
