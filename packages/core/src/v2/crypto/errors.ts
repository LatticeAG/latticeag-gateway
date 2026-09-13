/**
 * Shared error type for the Gateway v2 crypto/canonical-evidence primitives.
 *
 * `code` is a stable machine-readable tag so the RPC layer can map failures
 * onto the closed spec error codes (e.g. SIGNATURE_INVALID, OBJECT_LIMIT)
 * without parsing message text.
 */
export class CryptoError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "CryptoError";
    this.code = code;
  }
}
