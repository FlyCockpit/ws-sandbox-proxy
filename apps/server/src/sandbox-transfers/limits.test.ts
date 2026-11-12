import {
  TRANSFER_CHUNK_BYTES,
  TRANSFER_DEFAULT_DISK_BYTES,
  TRANSFER_MAX_BYTES,
  transferCreateSchema,
} from "@wssp/sandbox-contracts";
import { expect, it } from "vitest";
import { checkChunk, checkReservation } from "./limits.js";

const limits = {
  maxBytes: TRANSFER_MAX_BYTES,
  diskBytes: TRANSFER_DEFAULT_DISK_BYTES,
  ownerActive: 4,
  globalActive: 16,
  idleMs: 900_000,
  absoluteMs: 3_600_000,
};
it("uses exact integer cap and quota arithmetic including safe-integer boundaries", () => {
  expect(() => checkReservation(1024 ** 3, limits, 9n * 1024n ** 3n, 15, 3)).not.toThrow();
  expect(() => checkReservation(1024 ** 3 + 1, limits, 0n, 0, 0)).toThrow();
  expect(() => checkReservation(1, limits, BigInt(limits.diskBytes), 0, 0)).toThrow();
  expect(() => checkReservation(Number.MAX_SAFE_INTEGER + 1, limits, 0n, 0, 0)).toThrow();
  expect(() =>
    checkReservation(
      Number.MAX_SAFE_INTEGER,
      { ...limits, maxBytes: Number.MAX_SAFE_INTEGER, diskBytes: Number.MAX_SAFE_INTEGER },
      1n,
      0,
      0,
    ),
  ).toThrow();
  for (const [active, owned] of [
    [16, 0],
    [0, 4],
  ])
    expect(() => checkReservation(0, limits, 0n, active!, owned!)).toThrow();
});
it("requires exact fixed chunks and declared lengths with bounded guest-only paths", () => {
  const size = TRANSFER_CHUNK_BYTES;
  expect(() => checkChunk(size + 3, 0, size)).not.toThrow();
  expect(() => checkChunk(size + 3, size, 3)).not.toThrow();
  for (const [offset, length] of [
    [0, size - 1],
    [size, 4],
    [1, size],
    [size * 2, 1],
    [0, 0],
    [-size, size],
  ])
    expect(() => checkChunk(size + 3, offset!, length!)).toThrow();
  const valid = {
    sandboxId: "sandbox",
    direction: "UPLOAD",
    guestPath: "/home/user/a..b/guest-file",
    totalBytes: 0,
    idempotencyKey: "key",
  };
  expect(transferCreateSchema.safeParse(valid).success).toBe(true);
  for (const bad of [
    { totalBytes: undefined },
    { totalBytes: -1 },
    { guestPath: "x\0y" },
    { guestPath: `/${"x".repeat(4096)}` },
    // E-27: the host refuses these, so they never reserve a transfer.
    { guestPath: "../guest-file" },
    { guestPath: "guest-file" },
    { guestPath: "/home/user/../user/f" },
    { guestPath: "/home/user/.." },
    // E-28: the guest file helper's rules (crates/sandbox-runtime/src/incus/file-helper.py).
    { guestPath: "/home/user/./dot.txt" },
    { guestPath: "/." },
    { guestPath: "/" },
    { guestPath: "//" },
    { guestPath: "/a\nb" },
    { guestPath: "/a\ud800b" },
    // 4096 UTF-8 bytes is the host's bound, not 4096 UTF-16 units.
    { guestPath: `/${"é".repeat(2048)}` },
  ])
    expect(transferCreateSchema.safeParse({ ...valid, ...bad }).success).toBe(false);
});
