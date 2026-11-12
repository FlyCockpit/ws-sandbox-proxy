import { createHash, randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { Sha256 } from "./sha256";

const node = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");

describe("incremental SHA-256", () => {
  it("matches the FIPS 180-4 vectors", () => {
    const text = (value: string) => new TextEncoder().encode(value);
    expect(new Sha256().hex()).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    expect(new Sha256().update(text("abc")).hex()).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(
      new Sha256().update(text("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).hex(),
    ).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  });

  it("any split of the input gives the same digest as hashing it whole", () => {
    // Every padding boundary (55/56/63/64/119/120 bytes) and multi-block inputs.
    for (const size of [1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 70_001]) {
      const data = new Uint8Array(randomBytes(size));
      for (const split of [1, 7, 64, 333, size]) {
        const hash = new Sha256();
        for (let at = 0; at < size; at += split) hash.update(data.subarray(at, at + split));
        expect(hash.hex(), `${size}/${split}`).toBe(node(data));
      }
    }
  });

  it("refuses to be reused after the digest is taken", () => {
    const hash = new Sha256();
    hash.hex();
    expect(() => hash.update(new Uint8Array(1))).toThrow();
    expect(() => hash.hex()).toThrow();
  });
});
