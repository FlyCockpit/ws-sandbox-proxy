import { describe, expect, it } from "vitest";
import {
  encryptedImageLength,
  IMAGE_ENCRYPTION_RECORD_BYTES,
  IMAGE_ENCRYPTION_TAG_BYTES,
  IMAGE_SIZE_MAX,
  imageUploadPartBytes,
  S3_PARTS_MAX,
} from "./image-wire";

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
const SEALED = IMAGE_ENCRYPTION_RECORD_BYTES + IMAGE_ENCRYPTION_TAG_BYTES;

describe("imageUploadPartBytes", () => {
  it.each([
    ["one byte", 1, 16],
    ["a small image", 300 * MiB, 16],
    ["156 GiB", 156 * GiB, 16],
    ["just past 16 records per part", 10_000 * 16 * MiB + 1, 17],
    ["1 TiB (IMAGE_SIZE_MAX)", IMAGE_SIZE_MAX, 105],
  ])(
    "%s: whole records, at most 10 000 parts, at least 5 MiB but the last",
    (_, plain, records) => {
      for (const encrypted of [false, true]) {
        const part = imageUploadPartBytes(plain, encrypted);
        const record = encrypted ? SEALED : IMAGE_ENCRYPTION_RECORD_BYTES;
        expect(part).toBe(records * record);
        // Record-aligned: a part is whole (sealed) records.
        expect(part % record).toBe(0);
        expect(part).toBeGreaterThanOrEqual(5 * MiB);
        const stored = encrypted ? encryptedImageLength(plain) : plain;
        const parts = Math.max(1, Math.ceil(stored / part));
        expect(parts).toBeLessThanOrEqual(S3_PARTS_MAX);
        // Every part but the last is a full part; the last holds the rest.
        const last = stored - (parts - 1) * part;
        expect(last).toBeGreaterThan(0);
        expect(last).toBeLessThanOrEqual(part);
      }
    },
  );

  it("is 16 MiB plain and 16 sealed records encrypted for ordinary images", () => {
    expect(imageUploadPartBytes(10 * GiB, false)).toBe(16 * MiB);
    expect(imageUploadPartBytes(10 * GiB, true)).toBe(16 * (MiB + 16));
  });
});
