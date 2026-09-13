/**
 * Storage-layer error codes. These names are part of the durable contract:
 * transport/RPC layers map them onto registry error codes verbatim.
 */
export type StoreErrorCode =
  | "READ_ONLY"
  | "CORRUPT"
  | "OBJECT_LIMIT"
  | "BAD_RECORD"
  | "BAD_CURSOR"
  | "BAD_DIGEST"
  | "BAD_LANE"
  | "INVALID_TRANSITION"
  | "MUTATION_UNKNOWN"
  | "IDENTITY_MISMATCH"
  | "CHAIN_MISMATCH"
  | "NOT_FOUND";

export class StoreError extends Error {
  readonly code: StoreErrorCode;
  readonly details?: unknown;

  constructor(code: StoreErrorCode, message: string, details?: unknown) {
    super(message);
    this.name = "StoreError";
    this.code = code;
    this.details = details;
  }
}

export function storeError(
  code: StoreErrorCode,
  message: string,
  details?: unknown,
): StoreError {
  return new StoreError(code, message, details);
}
