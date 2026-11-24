/** A definite integrity failure, as opposed to an unavailable object store. */
export class ImageIntegrityError extends Error {}

/**
 * A verify stopped because its worker is shutting down (the job's abort
 * signal). Never a verdict: nothing was written, and the job goes back to the
 * queue for the next consumer.
 */
export class VerifyCancelledError extends Error {
  constructor() {
    super("Verify cancelled on shutdown.");
    this.name = "VerifyCancelledError";
  }
}

export function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new VerifyCancelledError();
}

/** Unknown failures must retry without condemning the object or its keys. */
export function isTerminalImageVerificationError(error: unknown): boolean {
  if (error instanceof ImageIntegrityError) return true;
  if (typeof error !== "object" || error === null) return false;
  // Bucket/endpoint configuration failures can also be HTTP 404. Only a
  // missing object is evidence against this upload.
  if (
    ("name" in error && error.name === "NoSuchKey") ||
    ("Code" in error && error.Code === "NoSuchKey")
  )
    return true;
  // Node/OpenSSL's AES-GCM authentication and malformed nonce/tag failures.
  return (
    ("message" in error && error.message === "Unsupported state or unable to authenticate data") ||
    ("code" in error &&
      (error.code === "ERR_CRYPTO_INVALID_AUTH_TAG" || error.code === "ERR_CRYPTO_INVALID_IV"))
  );
}
