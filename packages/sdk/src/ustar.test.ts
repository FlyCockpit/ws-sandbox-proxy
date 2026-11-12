import { describe, expect, it } from "vitest";
import {
  assertContainedLinkTarget,
  USTAR_BLOCK,
  UstarPathError,
  ustarHeader,
  ustarPadding,
  ustarPathSegments,
} from "./ustar";

const decoder = new TextDecoder();
const field = (header: Uint8Array, offset: number, length: number) =>
  decoder.decode(header.subarray(offset, offset + length)).replace(/\0.*$/s, "");

describe("ustar path safety (security)", () => {
  it.each([
    "",
    "/etc/passwd",
    "../x",
    "a/../../x",
    "a/./b",
    "a//b",
    "a/",
    ".",
    "..",
    "a\nb",
    "a\0b",
    "tab\there",
  ])("refuses entry name %j", (path) => {
    expect(() => ustarPathSegments(path)).toThrow(UstarPathError);
    expect(() => ustarHeader({ type: "file", path, mode: 0o644, size: 0 })).toThrow(UstarPathError);
  });

  it.each([
    ["link", "/etc/passwd"],
    ["link", "../outside"],
    ["dir/link", "../../outside"],
    ["dir/link", "sub/../../../x"],
    ["link", ""],
    ["link", "a\nb"],
  ])("refuses symlink %s → %j", (path, target) => {
    expect(() => assertContainedLinkTarget(path, target)).toThrow(UstarPathError);
    expect(() => ustarHeader({ type: "symlink", path, target })).toThrow(UstarPathError);
  });

  it.each([
    ["link", "file"],
    ["dir/link", "../file"],
    ["dir/sub/link", "../../dir/./x"],
  ])("accepts contained symlink %s → %s", (path, target) => {
    expect(() => ustarHeader({ type: "symlink", path, target })).not.toThrow();
  });

  it("refuses names that cannot be split into ustar prefix/name and oversize files", () => {
    expect(() =>
      ustarHeader({ type: "file", path: "x".repeat(101), mode: 0o644, size: 0 }),
    ).toThrow(UstarPathError);
    expect(() =>
      ustarHeader({ type: "file", path: `${"d".repeat(156)}/f`, mode: 0o644, size: 0 }),
    ).toThrow(UstarPathError);
    expect(() =>
      ustarHeader({ type: "file", path: "big", mode: 0o644, size: 0o77777777777 + 1 }),
    ).toThrow(UstarPathError);
  });

  it("drops setuid/setgid/sticky bits and writes zero owners and mtime", () => {
    const header = ustarHeader({ type: "file", path: "bin/tool", mode: 0o104755, size: 5 });
    expect(field(header, 100, 8)).toBe("0000755");
    expect(field(header, 108, 8)).toBe("0000000");
    expect(field(header, 116, 8)).toBe("0000000");
    expect(field(header, 136, 12)).toBe("00000000000");
    expect(field(header, 124, 12)).toBe("00000000005");
  });
});

describe("ustar header layout", () => {
  it("writes a valid checksum, magic and type flags", () => {
    for (const [entry, flag] of [
      [{ type: "file", path: "a", mode: 0o644, size: 1 }, "0"],
      [{ type: "directory", path: "d", mode: 0o755 }, "5"],
      [{ type: "symlink", path: "l", target: "a" }, "2"],
    ] as const) {
      const header = ustarHeader(entry);
      expect(header).toHaveLength(USTAR_BLOCK);
      expect(String.fromCharCode(header[156]!)).toBe(flag);
      expect(field(header, 257, 6)).toBe("ustar");
      const stored = Number.parseInt(field(header, 148, 8).trim(), 8);
      const copy = header.slice();
      copy.fill(0x20, 148, 156);
      expect(copy.reduce((sum, byte) => sum + byte, 0)).toBe(stored);
    }
  });

  it("splits long names into prefix and name", () => {
    const path = `${"p".repeat(120)}/name.txt`;
    const header = ustarHeader({ type: "file", path, mode: 0o644, size: 0 });
    expect(field(header, 0, 100)).toBe("name.txt");
    expect(field(header, 345, 155)).toBe("p".repeat(120));
  });

  it("pads data to whole blocks", () => {
    expect(ustarPadding(0)).toHaveLength(0);
    expect(ustarPadding(1)).toHaveLength(511);
    expect(ustarPadding(512)).toHaveLength(0);
  });
});
