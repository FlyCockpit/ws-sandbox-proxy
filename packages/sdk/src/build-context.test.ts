import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { packContext } from "./build-context";

/** Simulate a platform without `/proc/self/fd` (the pathname fallback). */
const platform = vi.hoisted(() => ({ noProc: false }));
vi.mock("node:fs/promises", async (actual) => {
  const real = await actual<typeof import("node:fs/promises")>();
  return {
    ...real,
    stat: (path: string, ...rest: never[]) =>
      platform.noProc && String(path).startsWith("/proc/self/fd/")
        ? Promise.reject(Object.assign(new Error("ENOENT"), { code: "ENOENT" }))
        : real.stat(path, ...rest),
  };
});

import { WsspError } from "./errors";

const roots: string[] = [];
function context(): string {
  const dir = mkdtempSync(join(tmpdir(), "wssp-ctx-test-"));
  roots.push(dir);
  return dir;
}
afterEach(() => {
  platform.noProc = false;
  for (const dir of roots.splice(0)) rmSync(dir, { recursive: true, force: true });
});

type Read = { name: string; type: string; mode: number; size: number; link: string; data: string };
/** Test-only ustar reader (round-trip proof; never shipped). */
function readTar(bytes: Uint8Array): Read[] {
  const decoder = new TextDecoder();
  const text = (offset: number, length: number) =>
    decoder.decode(bytes.subarray(offset, offset + length)).replace(/\0.*$/s, "");
  const out: Read[] = [];
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    if (bytes.subarray(offset, offset + 512).every((byte) => byte === 0)) break;
    const prefix = text(offset + 345, 155);
    const name = text(offset, 100);
    const size = Number.parseInt(text(offset + 124, 12), 8);
    const data = decoder.decode(bytes.subarray(offset + 512, offset + 512 + size));
    out.push({
      name: prefix ? `${prefix}/${name}` : name,
      type: String.fromCharCode(bytes[offset + 156]!),
      mode: Number.parseInt(text(offset + 100, 8), 8),
      size,
      link: text(offset + 157, 100),
      data,
    });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

describe("packContext path safety (security)", () => {
  it("refuses a symlink that escapes the context", async () => {
    const dir = context();
    symlinkSync("../../etc/passwd", join(dir, "escape"));
    await expect(packContext(dir)).rejects.toThrow(WsspError);
    const absolute = context();
    symlinkSync("/etc/passwd", join(absolute, "abs"));
    await expect(packContext(absolute)).rejects.toThrow(/inside the context/);
  });

  it("refuses FIFOs and other special files", async () => {
    const dir = context();
    execFileSync("mkfifo", [join(dir, "pipe")]);
    await expect(packContext(dir)).rejects.toThrow(/not a file, directory or symlink/);
  });

  it("refuses a context root that is a symlink", async () => {
    const real = context();
    const parent = context();
    symlinkSync(real, join(parent, "link"));
    await expect(packContext(join(parent, "link"))).rejects.toThrow(/must be a directory/);
  });

  it("refuses file names with control characters", async () => {
    const dir = context();
    writeFileSync(join(dir, "bad\nname"), "x");
    await expect(packContext(dir)).rejects.toThrow(/control characters/);
  });

  it("enforces maxBytes and leaves no temp file behind", async () => {
    const dir = context();
    writeFileSync(join(dir, "big"), "x".repeat(4096));
    const temp = context();
    await expect(packContext(dir, { maxBytes: 2048, tempDir: temp })).rejects.toThrow(/larger/);
    expect(execFileSync("ls", ["-A", temp]).toString()).toBe("");
  });
});

describe("packContext concurrent swaps (security)", () => {
  /** A context `sub/` with a.txt and b.txt, and an outside directory with a
   * secret b.txt that a concurrent writer can swap in through a symlink. */
  function race() {
    const dir = context();
    mkdirSync(join(dir, "sub"));
    writeFileSync(join(dir, "sub", "a.txt"), "a");
    writeFileSync(join(dir, "sub", "b.txt"), "b");
    const outside = context();
    writeFileSync(join(outside, "b.txt"), "SECRET");
    const swap = () => {
      renameSync(join(dir, "sub"), join(dir, "sub.orig"));
      symlinkSync(outside, join(dir, "sub"));
    };
    return { dir, swap };
  }

  it("a directory swapped for a symlink after its check is never traversed", async () => {
    const { dir, swap } = race();
    const packing = packContext(dir, {
      filter: (path, kind) => {
        if (path === "sub" && kind === "directory") swap();
        return true;
      },
    });
    await expect(packing).rejects.toMatchObject({ kind: "invalid_request" });
  });

  it("without /proc anchoring, packing is refused by default (typed), before any entry is read", async () => {
    platform.noProc = true;
    const dir = context();
    writeFileSync(join(dir, "f"), "x");
    const temp = context();
    const filter = vi.fn(() => true);
    const packing = packContext(dir, { filter, tempDir: temp });
    await expect(packing).rejects.toMatchObject({
      name: "WsspError",
      kind: "unsupported",
      reason: "unanchored_context",
    });
    await expect(packing).rejects.toThrow(/allowUnanchoredContext/);
    expect(filter).not.toHaveBeenCalled();
    // No temporary tar is left behind.
    expect(execFileSync("ls", ["-A", temp]).toString()).toBe("");
  });

  it("on Linux (anchored) packing needs no opt-in and the opt-in changes nothing", async () => {
    const dir = context();
    mkdirSync(join(dir, "d"));
    writeFileSync(join(dir, "d", "f"), "x");
    const plain = await packContext(dir);
    const optedIn = await packContext(dir, { allowUnanchoredContext: true });
    try {
      expect(plain.entries).toEqual(["d/", "d/f"]);
      expect(optedIn.sha256).toBe(plain.sha256);
    } finally {
      await plain.dispose();
      await optedIn.dispose();
    }
  });

  it("without /proc anchoring and with the opt-in, both swaps are still detected by the identity re-checks", async () => {
    platform.noProc = true;
    for (const at of ["sub", "sub/a.txt"]) {
      const { dir, swap } = race();
      const packing = packContext(dir, {
        allowUnanchoredContext: true,
        filter: (path) => {
          if (path === at) swap();
          return true;
        },
      });
      await expect(packing).rejects.toMatchObject({ kind: "invalid_request" });
    }
    // And an untouched context still packs on that path.
    const dir = context();
    mkdirSync(join(dir, "d"));
    writeFileSync(join(dir, "d", "f"), "x");
    const packed = await packContext(dir, { allowUnanchoredContext: true });
    expect(packed.entries).toEqual(["d/", "d/f"]);
    await packed.dispose();
  });

  it("an ancestor swapped mid-directory never redirects the remaining entries", async () => {
    const { dir, swap } = race();
    const packing = packContext(dir, {
      filter: (path) => {
        if (path === "sub/a.txt") swap();
        return true;
      },
    });
    await expect(packing).rejects.toMatchObject({ kind: "invalid_request" });
  });
});

describe("packContext round trip", () => {
  it("archives sorted entries deterministically with a matching sha256", async () => {
    const dir = context();
    mkdirSync(join(dir, "app/src"), { recursive: true });
    writeFileSync(join(dir, "package.json"), '{"name":"x"}');
    writeFileSync(join(dir, "app/src/index.js"), "console.log(1)\n");
    writeFileSync(join(dir, "app/run.sh"), "#!/bin/sh\n");
    chmodSync(join(dir, "app/run.sh"), 0o755);
    symlinkSync("src/index.js", join(dir, "app/main.js"));
    mkdirSync(join(dir, ".git"));
    writeFileSync(join(dir, ".git/HEAD"), "ref");

    const first = await packContext(dir, { filter: (path) => path !== ".git" });
    const second = await packContext(dir, { filter: (path) => path !== ".git" });
    try {
      expect(first.sha256).toBe(second.sha256);
      const bytes = new Uint8Array(readFileSync(first.path));
      expect(bytes.length).toBe(first.bytes);
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(first.sha256);
      expect(first.entries).toEqual([
        "app/",
        "app/main.js",
        "app/run.sh",
        "app/src/",
        "app/src/index.js",
        "package.json",
      ]);
      const read = readTar(bytes);
      expect(read.map((entry) => [entry.name, entry.type])).toEqual([
        ["app/", "5"],
        ["app/main.js", "2"],
        ["app/run.sh", "0"],
        ["app/src/", "5"],
        ["app/src/index.js", "0"],
        ["package.json", "0"],
      ]);
      expect(read[1]!.link).toBe("src/index.js");
      expect(read[2]!.mode).toBe(0o755);
      expect(read[4]!.data).toBe("console.log(1)\n");
    } finally {
      await first.dispose();
      await second.dispose();
    }
  });
});
