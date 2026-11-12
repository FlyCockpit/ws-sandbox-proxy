import { expect, it } from "vitest";
import { decryptImageStream, encryptRecord, unwrapDataKey, wrapDataKey } from "./s3";
import { ImageIntegrityError, isTerminalImageVerificationError } from "./verification-errors";

it.each([
  new ImageIntegrityError("length mismatch"),
  { name: "NoSuchKey" },
  { Code: "NoSuchKey", $metadata: { httpStatusCode: 404 } },
  { code: "ERR_CRYPTO_INVALID_IV" },
  { code: "ERR_CRYPTO_INVALID_AUTH_TAG" },
])("classifies definite missing or invalid data as terminal (%j)", (error) => {
  expect(isTerminalImageVerificationError(error)).toBe(true);
});

it.each([
  new Error("unknown failure"),
  { code: "ECONNRESET" },
  { name: "TimeoutError" },
  { $metadata: { httpStatusCode: 404 } },
  { name: "NoSuchBucket", $metadata: { httpStatusCode: 404 } },
  { Code: "NoSuchBucket", $metadata: { httpStatusCode: 404 } },
  { name: "InvalidObjectState", $metadata: { httpStatusCode: 400 } },
  { $metadata: { httpStatusCode: 403 } },
  { $metadata: { httpStatusCode: 500 } },
  null,
])("retries unavailable or unknown failures (%j)", (error) => {
  expect(isTerminalImageVerificationError(error)).toBe(false);
});

it("recognizes real GCM authentication failures on wrapped keys", () => {
  const master = Buffer.alloc(32, 1);
  const wrapped = wrapDataKey(master, Buffer.alloc(32, 2), "artifact", "owner");
  let failure: unknown;
  try {
    unwrapDataKey(Buffer.alloc(32, 3), wrapped, "artifact", "owner");
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(Error);
  expect(isTerminalImageVerificationError(failure)).toBe(true);
});

it.each(["tamper", "truncate", "trailing"])("recognizes encrypted stream %s", async (mode) => {
  const key = Buffer.alloc(32, 1);
  let sealed = encryptRecord(key, 0, true, Buffer.from("image"));
  if (mode === "tamper") sealed[0] = (sealed[0] ?? 0) ^ 1;
  if (mode === "truncate") sealed = sealed.subarray(1);
  if (mode === "trailing") sealed = Buffer.concat([sealed, Buffer.alloc(1)]);
  let failure: unknown;
  try {
    for await (const _chunk of decryptImageStream(
      key,
      5,
      (async function* () {
        yield sealed;
      })(),
    )) {
      // Consume the stream to force authentication and length checks.
    }
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(Error);
  expect(isTerminalImageVerificationError(failure)).toBe(true);
});
