import {
  encryptedImageLength,
  IMAGE_ENCRYPTION_RECORD_BYTES,
  IMAGE_ENCRYPTION_TAG_BYTES,
  IMAGE_SIZE_MAX,
} from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/queue", () => ({}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeImageGrantBudget: async () => {} }));

const { diskPartSize } = await import("./disk-handlers");

describe("disk part size (offload plan §6)", () => {
  const sealed = IMAGE_ENCRYPTION_RECORD_BYTES + IMAGE_ENCRYPTION_TAG_BYTES;
  it.each([1, 64 * IMAGE_ENCRYPTION_RECORD_BYTES, 2 ** 37, IMAGE_SIZE_MAX])(
    "whole sealed records, at least 64, and at most 10000 S3 parts (%d bytes)",
    (plain) => {
      const part = diskPartSize(plain);
      expect(part % sealed).toBe(0);
      expect(part / sealed).toBeGreaterThanOrEqual(64);
      expect(Math.ceil(encryptedImageLength(plain) / part)).toBeLessThanOrEqual(10_000);
      expect(Number.isSafeInteger(part) && part < 2 ** 31).toBe(true);
    },
  );
});
