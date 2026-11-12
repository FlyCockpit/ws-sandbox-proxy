import { describe, expect, it } from "vitest";
import { dataRootKey } from "../../crypto/data-key";
import { CredentialVaultError, type CredentialVaultErrorCode } from "./errors";
import { deriveVaultKeys } from "./keys";
import {
  createReturnKeyPair,
  rewrapReturnPrivateKey,
  unwrapReturnPrivateKey,
  verifyReturnKeyPair,
  type WrappedReturnKey,
  wrapReturnPrivateKey,
} from "./return-key";
import {
  computePolicyDigest,
  decryptValue,
  encryptValue,
  rewrapDek,
  type SealedValue,
  unwrapDek,
  type ValueContext,
} from "./value";

// Dummy test-only roots; never real keys. CURRENT matches crypto/data-key.test.ts.
const CURRENT_HEX = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const PREVIOUS_HEX = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
const current = deriveVaultKeys({ current: dataRootKey(CURRENT_HEX), previous: null });
const rotated = deriveVaultKeys({
  current: dataRootKey(PREVIOUS_HEX),
  previous: dataRootKey(CURRENT_HEX),
});

const DEFINITION_DIGEST = "ab".repeat(32);
const POLICY = computePolicyDigest(DEFINITION_DIGEST, "GUEST");
const CTX: ValueContext = {
  userId: "usr_1",
  credentialId: "crd_1",
  instanceId: "cin_1",
  storageSeq: 3,
  kind: "UPLOAD",
  policyDigest: POLICY,
};
const PLAINTEXT = Buffer.from('{"token":"test-only"}');

function code(fn: () => unknown): CredentialVaultErrorCode | "no-error" | "other" {
  try {
    fn();
    return "no-error";
  } catch (error) {
    return error instanceof CredentialVaultError ? error.code : "other";
  }
}

describe("policy digest", () => {
  it("is SHA-256 of the exact canonical JSON (independent known answer)", () => {
    // python: sha256(b'{"definitionDigest":"abab…","delivery":"GUEST"}')
    expect(POLICY).toBe("7d3f4153cd06937f36b5c93972757c5c5b3612dd5d3c8d37358a3236f2bedc06");
    expect(computePolicyDigest(DEFINITION_DIGEST, "PROXY")).not.toBe(POLICY);
  });

  it("refuses non-canonical inputs", () => {
    expect(code(() => computePolicyDigest("AB".repeat(32), "GUEST"))).toBe("malformed");
    expect(code(() => computePolicyDigest(DEFINITION_DIGEST, "guest" as "GUEST"))).toBe(
      "malformed",
    );
  });
});

describe("stored values (per-value DEK, salted single-use wraps)", () => {
  it("opens an independently produced known-answer row", () => {
    // Computed with Python `cryptography` from the spec: DEK 0x11×32, nonce
    // 0x22×12, wrapSalt 0x33×32, wrapNonce 0x44×12 under CURRENT_HEX.
    const row: SealedValue = {
      ciphertext: Buffer.from(
        "6cd57326abaaf17ddf1daa593bd2c4ba71ffb4c017105f03ab9bdb26b498e5d5d1a1158494",
        "hex",
      ),
      nonce: Buffer.alloc(12, 0x22),
      wrappedDek: Buffer.from(
        "953595d897a4b3d1db7522ab11afbf45210a7c3ed98ce4671e289647ea3c1620ba661f9ba77611e12327c38d4cabe585",
        "hex",
      ),
      wrapSalt: Buffer.alloc(32, 0x33),
      wrapNonce: Buffer.alloc(12, 0x44),
      rootKid: "6685009530c3e0f4",
      policyDigest: POLICY,
      sizeBytes: PLAINTEXT.byteLength,
    };
    expect(decryptValue(row, CTX, current.dek.all).equals(PLAINTEXT)).toBe(true);
    expect(unwrapDek(row, CTX, current.dek.all).equals(Buffer.alloc(32, 0x11))).toBe(true);
  });

  it("round-trips with fresh DEK, nonce and salt every time", () => {
    const a = encryptValue(PLAINTEXT, CTX, current.dek.current);
    const b = encryptValue(PLAINTEXT, CTX, current.dek.current);
    expect(a.wrappedDek).toHaveLength(48);
    expect(a.wrapSalt).toHaveLength(32);
    expect(a.wrapNonce).toHaveLength(12);
    expect(a.ciphertext).toHaveLength(PLAINTEXT.byteLength + 16);
    expect(a.rootKid).toBe(current.dek.current.rootKeyId);
    expect(a.sizeBytes).toBe(PLAINTEXT.byteLength);
    for (const field of ["ciphertext", "nonce", "wrappedDek", "wrapSalt", "wrapNonce"] as const)
      expect(a[field].equals(b[field])).toBe(false);
    expect(decryptValue(a, CTX, current.dek.all).equals(PLAINTEXT)).toBe(true);
    expect(decryptValue(b, { ...CTX, storageSeq: 3n }, current.dek.all).equals(PLAINTEXT)).toBe(
      true,
    );
  });

  it("fails closed when any context field moves (value and wrapped-DEK transplant)", () => {
    const sealed = encryptValue(PLAINTEXT, CTX, current.dek.current);
    const moved: Partial<ValueContext>[] = [
      { userId: "usr_2" },
      { credentialId: "crd_2" },
      { instanceId: "cin_2" },
      { storageSeq: 4 },
      { kind: "CAPTURE" },
    ];
    for (const change of moved)
      expect(code(() => decryptValue(sealed, { ...CTX, ...change }, current.dek.all))).toBe(
        "authentication_failed",
      );
    // A different delivery or definition changes the recomputed digest: the row's
    // stored digest no longer matches, and forging the column fails the AAD.
    const proxy = computePolicyDigest(DEFINITION_DIGEST, "PROXY");
    expect(code(() => decryptValue(sealed, { ...CTX, policyDigest: proxy }, current.dek.all))).toBe(
      "context_mismatch",
    );
    expect(
      code(() =>
        decryptValue(
          { ...sealed, policyDigest: proxy },
          { ...CTX, policyDigest: proxy },
          current.dek.all,
        ),
      ),
    ).toBe("authentication_failed");
    // Wrapped DEK from another value, ciphertext kept.
    const other = encryptValue(PLAINTEXT, { ...CTX, instanceId: "cin_2" }, current.dek.current);
    expect(
      code(() =>
        decryptValue(
          {
            ...sealed,
            wrappedDek: other.wrappedDek,
            wrapSalt: other.wrapSalt,
            wrapNonce: other.wrapNonce,
          },
          CTX,
          current.dek.all,
        ),
      ),
    ).toBe("authentication_failed");
    // A row claiming another root kid that IS configured still fails the DEK AAD.
    expect(
      code(() =>
        decryptValue({ ...sealed, rootKid: rotated.dek.current.rootKeyId }, CTX, rotated.dek.all),
      ),
    ).toBe("authentication_failed");
  });

  it("refuses an unknown root kid, tampering, truncation and bad lengths", () => {
    const sealed = encryptValue(PLAINTEXT, CTX, current.dek.current);
    expect(
      code(() => decryptValue({ ...sealed, rootKid: "0000000000000000" }, CTX, current.dek.all)),
    ).toBe("key_unavailable");
    const flip = (buf: Buffer, at: number) => {
      const copy = Buffer.from(buf);
      copy[at] = copy[at]! ^ 1;
      return copy;
    };
    expect(
      code(() =>
        decryptValue({ ...sealed, ciphertext: flip(sealed.ciphertext, 0) }, CTX, current.dek.all),
      ),
    ).toBe("authentication_failed");
    expect(
      code(() =>
        decryptValue({ ...sealed, wrapSalt: flip(sealed.wrapSalt, 31) }, CTX, current.dek.all),
      ),
    ).toBe("authentication_failed");
    expect(
      code(() => decryptValue({ ...sealed, nonce: flip(sealed.nonce, 0) }, CTX, current.dek.all)),
    ).toBe("authentication_failed");
    expect(
      code(() =>
        decryptValue(
          { ...sealed, ciphertext: sealed.ciphertext.subarray(0, 15) },
          CTX,
          current.dek.all,
        ),
      ),
    ).toBe("authentication_failed");
    expect(
      code(() =>
        decryptValue(
          { ...sealed, ciphertext: sealed.ciphertext.subarray(1) },
          CTX,
          current.dek.all,
        ),
      ),
    ).toBe("authentication_failed");
    expect(
      code(() =>
        decryptValue(
          { ...sealed, wrappedDek: sealed.wrappedDek.subarray(0, 47) },
          CTX,
          current.dek.all,
        ),
      ),
    ).toBe("malformed");
    expect(code(() => decryptValue({ ...sealed, sizeBytes: 1 }, CTX, current.dek.all))).toBe(
      "context_mismatch",
    );
    expect(code(() => decryptValue(sealed, { ...CTX, storageSeq: 0 }, current.dek.all))).toBe(
      "malformed",
    );
    expect(code(() => decryptValue(sealed, { ...CTX, storageSeq: 1.5 }, current.dek.all))).toBe(
      "malformed",
    );
    expect(code(() => decryptValue(sealed, { ...CTX, userId: "" }, current.dek.all))).toBe(
      "malformed",
    );
    expect(code(() => decryptValue(sealed, { ...CTX, userId: "\ud800" }, current.dek.all))).toBe(
      "malformed",
    );
  });

  it("rewraps under a new root with a new salt and nonce, value untouched", () => {
    const sealed = encryptValue(PLAINTEXT, CTX, current.dek.current);
    const next = rewrapDek(sealed, CTX, rotated.dek.all, rotated.dek.current);
    expect(next.rootKid).toBe(rotated.dek.current.rootKeyId);
    expect(next.wrapSalt.equals(sealed.wrapSalt)).toBe(false);
    expect(next.wrapNonce.equals(sealed.wrapNonce)).toBe(false);
    const moved = { ...sealed, ...next };
    expect(decryptValue(moved, CTX, rotated.dek.all).equals(PLAINTEXT)).toBe(true);
    // After the previous root is removed, the old row is unopenable.
    expect(code(() => decryptValue(sealed, CTX, [rotated.dek.current]))).toBe("key_unavailable");
  });

  it("separates purposes: a DEK wrap never opens under the return-key sub-key", () => {
    const sealed = encryptValue(PLAINTEXT, CTX, current.dek.current);
    const wrongPurpose = current.returnKey.all as unknown as typeof current.dek.all;
    expect(code(() => decryptValue(sealed, CTX, wrongPurpose))).toBe("authentication_failed");
  });
});

describe("return keys", () => {
  it("unwraps an independently produced known-answer row and verifies the binding", () => {
    // Python `cryptography`: private 0x55×32, rwrapSalt 0x66×32, nonce 0x77×12.
    const row: WrappedReturnKey = {
      kidR: "1128de8a3d96a514",
      publicKey: Buffer.from(
        "38ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67",
        "hex",
      ),
      wrappedPrivate: Buffer.from(
        "f4817521580b8194df186a3238e19289d98dd3853b906dc361cf831ae3ea8c023f90b46a49532bbf943717ae3e06ae79",
        "hex",
      ),
      rwrapSalt: Buffer.alloc(32, 0x66),
      wrapNonce: Buffer.alloc(12, 0x77),
      rootKid: "6685009530c3e0f4",
    };
    expect(
      unwrapReturnPrivateKey(row, current.returnKey.all).privateKey.equals(Buffer.alloc(32, 0x55)),
    ).toBe(true);
  });

  it("creates, wraps with fresh salt per wrap and rewrap, and unwraps", () => {
    const pair = createReturnKeyPair();
    verifyReturnKeyPair(pair);
    expect(pair.kidR).toMatch(/^[0-9a-f]{16}$/);
    const a = wrapReturnPrivateKey(pair, current.returnKey.current);
    const b = wrapReturnPrivateKey(pair, current.returnKey.current);
    expect(a.rwrapSalt.equals(b.rwrapSalt)).toBe(false);
    expect(a.wrapNonce.equals(b.wrapNonce)).toBe(false);
    expect(a.wrappedPrivate).toHaveLength(48);
    const back = unwrapReturnPrivateKey(a, current.returnKey.all);
    expect(back.privateKey.equals(pair.privateKey)).toBe(true);
    const re = rewrapReturnPrivateKey(a, rotated.returnKey.all, rotated.returnKey.current);
    expect(re.rootKid).toBe(rotated.returnKey.current.rootKeyId);
    expect(re.rwrapSalt.equals(a.rwrapSalt)).toBe(false);
    expect(
      unwrapReturnPrivateKey(re, rotated.returnKey.all).privateKey.equals(pair.privateKey),
    ).toBe(true);
  });

  it("refuses a substituted public key or kidR, even with a matching re-wrap", () => {
    const pair = createReturnKeyPair();
    const other = createReturnKeyPair();
    const row = wrapReturnPrivateKey(pair, current.returnKey.current);
    // Column swap: AAD binds publicKey and kidR.
    expect(
      code(() =>
        unwrapReturnPrivateKey({ ...row, publicKey: other.publicKey }, current.returnKey.all),
      ),
    ).toBe("authentication_failed");
    expect(
      code(() => unwrapReturnPrivateKey({ ...row, kidR: other.kidR }, current.returnKey.all)),
    ).toBe("authentication_failed");
    // A writer who could wrap would still need the private key to match.
    expect(
      code(() => verifyReturnKeyPair({ ...pair, publicKey: other.publicKey, kidR: other.kidR })),
    ).toBe("return_key_mismatch");
    expect(code(() => verifyReturnKeyPair({ ...pair, kidR: other.kidR }))).toBe(
      "return_key_mismatch",
    );
    expect(
      code(() => wrapReturnPrivateKey({ ...pair, kidR: other.kidR }, current.returnKey.current)),
    ).toBe("return_key_mismatch");
    expect(
      code(() =>
        unwrapReturnPrivateKey({ ...row, rootKid: "0000000000000000" }, current.returnKey.all),
      ),
    ).toBe("key_unavailable");
    expect(
      code(() =>
        unwrapReturnPrivateKey(
          { ...row, wrappedPrivate: row.wrappedPrivate.subarray(1) },
          current.returnKey.all,
        ),
      ),
    ).toBe("malformed");
    expect(code(() => unwrapReturnPrivateKey(row, current.dek.all as never))).toBe(
      "authentication_failed",
    );
  });
});
