import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { fromBase64UrlStrict, returnKeyId } from "./codec";
import { buildEnvelope, type EnvelopeHeader, openEnvelope, parseEnvelope } from "./envelope";
import { CredentialVaultError, type CredentialVaultErrorCode } from "./errors";
import vectors from "./fixtures/seal-v1.json" with { type: "json" };
import { createReturnKeyPair, type ReturnKeyPair } from "./return-key";
import {
  encodeReturnAad,
  openSealed,
  RETURN_AAD_FIELDS,
  type ReturnAad,
  SEAL_OVERHEAD,
  sealToReturnKey,
} from "./sealed-box";
import { x25519PublicKey } from "./x25519";

// Shared with apps/cli/src/sandbox_relay/credentials/seal.rs (include_str!).
// Every key in the vector file is a fixed TEST value.
const recipient: ReturnKeyPair = {
  kidR: vectors.recipient.kidR,
  publicKey: fromBase64UrlStrict(vectors.recipient.publicKey, 32),
  privateKey: Buffer.from(vectors.recipient.privateKey, "hex"),
};

function code(fn: () => unknown): CredentialVaultErrorCode | "no-error" | "other" {
  try {
    fn();
    return "no-error";
  } catch (error) {
    return error instanceof CredentialVaultError ? error.code : "other";
  }
}

const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

function headerFor(seal: Buffer, aad: ReturnAad, key = recipient): EnvelopeHeader {
  return {
    kidR: key.kidR,
    recipientPubSha256: sha(key.publicKey),
    aad,
    sealedLen: seal.byteLength,
    sealedSha256: sha(seal),
    createdAt: 1,
  };
}

describe("cross-language seal vectors", () => {
  it("binds the recipient key id", () => {
    expect(x25519PublicKey(recipient.privateKey).equals(recipient.publicKey)).toBe(true);
    expect(returnKeyId(recipient.publicKey)).toBe(recipient.kidR);
  });

  for (const vector of vectors.cases) {
    it(`${vector.name}: reproduces the seal and envelope byte for byte and opens them`, () => {
      const aad = vector.aad as ReturnAad;
      const plaintext = Buffer.from(vector.plaintext, "hex");
      expect(encodeReturnAad(recipient.kidR, aad).toString("hex")).toBe(vector.aadEncoded);
      const seal = sealToReturnKey(plaintext, recipient.publicKey, aad, {
        ephemeralPrivateKey: Buffer.from(vector.ephemeralPrivateKey, "hex"),
        nonce: Buffer.from(vector.nonce, "hex"),
      });
      expect(seal.toString("hex")).toBe(vector.seal);
      expect(seal.byteLength).toBe(plaintext.byteLength + SEAL_OVERHEAD);
      expect(openSealed(Buffer.from(vector.seal, "hex"), recipient, aad).equals(plaintext)).toBe(
        true,
      );
      const envelope = Buffer.from(vector.envelope, "hex");
      expect(
        buildEnvelope({ ...headerFor(seal, aad), createdAt: vector.createdAt }, seal).equals(
          envelope,
        ),
      ).toBe(true);
      const parsed = parseEnvelope(envelope);
      expect(parsed.headerJson.toString("utf8")).toBe(vector.headerJson);
      expect(parsed.envelopeDigest.toString("hex")).toBe(vector.envelopeDigest);
      expect(parsed.envelopeDigest.toString("hex")).toBe(sha(envelope));
      expect(openEnvelope(parsed, aad, recipient).equals(plaintext)).toBe(true);
    });
  }

  it("refuses every invalid public key encoding", () => {
    for (const bad of vectors.invalidPublicKeys) {
      const decoded = (() => {
        try {
          return fromBase64UrlStrict(bad.publicKey, 32);
        } catch {
          return null;
        }
      })();
      if (decoded === null) continue; // refused at decode
      expect(
        code(() => sealToReturnKey(Buffer.alloc(1), decoded, vectors.cases[0]!.aad as ReturnAad)),
        bad.name,
      ).toBe("invalid_key");
    }
    // Every entry is refused somewhere; padding/alphabet/trailing bits at decode.
    for (const name of [
      "31-bytes",
      "33-bytes",
      "padded-base64url",
      "standard-base64-alphabet",
      "non-canonical-trailing-bits",
    ]) {
      const entry = vectors.invalidPublicKeys.find((k) => k.name === name)!;
      expect(
        code(() => fromBase64UrlStrict(entry.publicKey, 32)),
        name,
      ).toBe("invalid_key");
    }
  });

  it("refuses low-order points (all-zero DH) both sealing and opening", () => {
    const base = Buffer.from(vectors.cases[0]!.seal, "hex");
    for (const low of vectors.lowOrderPublicKeys) {
      const key = fromBase64UrlStrict(low.publicKey, 32);
      expect(
        code(() => sealToReturnKey(Buffer.alloc(1), key, vectors.cases[0]!.aad as ReturnAad)),
        low.name,
      ).toBe("invalid_key");
      const forged = Buffer.concat([key, base.subarray(32)]);
      expect(
        code(() => openSealed(forged, recipient, vectors.cases[0]!.aad as ReturnAad)),
        low.name,
      ).toBe("invalid_key");
    }
  });
});

describe("sealed box negatives", () => {
  const aad = vectors.cases[1]!.aad as ReturnAad;
  const seal = Buffer.from(vectors.cases[1]!.seal, "hex");

  it("fails when any AAD field is changed", () => {
    for (const field of RETURN_AAD_FIELDS) {
      const changed: ReturnAad = {
        ...aad,
        [field]: field === "captureSeq" ? "8" : field === "residueId" ? "crs_x" : `${aad[field]}x`,
      };
      expect(
        code(() => openSealed(seal, recipient, changed)),
        field,
      ).toBe("authentication_failed");
    }
    // An empty residue and a named one are distinct contexts.
    const withResidue = vectors.cases[2]!;
    expect(
      code(() =>
        openSealed(Buffer.from(withResidue.seal, "hex"), recipient, {
          ...(withResidue.aad as ReturnAad),
          residueId: "",
        }),
      ),
    ).toBe("authentication_failed");
  });

  it("fails for another recipient, a wrong kidR, truncation and tampering", () => {
    const other = createReturnKeyPair();
    expect(code(() => openSealed(seal, other, aad))).toBe("authentication_failed");
    expect(code(() => openSealed(seal, { ...recipient, kidR: other.kidR }, aad))).toBe(
      "return_key_mismatch",
    );
    expect(code(() => openSealed(seal.subarray(0, SEAL_OVERHEAD - 1), recipient, aad))).toBe(
      "malformed",
    );
    expect(code(() => openSealed(seal.subarray(0, seal.byteLength - 1), recipient, aad))).toBe(
      "authentication_failed",
    );
    for (const at of [0, 33, 44, seal.byteLength - 1]) {
      const copy = Buffer.from(seal);
      copy[at] = copy[at]! ^ 0x40;
      expect(
        code(() => openSealed(copy, recipient, aad)),
        String(at),
      ).not.toBe("no-error");
    }
  });

  it("validates AAD fields strictly", () => {
    for (const captureSeq of ["0", "07", "-1", "1.0", "9223372036854775808", ""])
      expect(
        code(() => encodeReturnAad(recipient.kidR, { ...aad, captureSeq })),
        captureSeq,
      ).toBe("malformed");
    expect(code(() => encodeReturnAad(recipient.kidR, { ...aad, kind: "STOP" }))).toBe("malformed");
    expect(code(() => encodeReturnAad(recipient.kidR, { ...aad, hostId: "" }))).toBe("malformed");
    expect(code(() => encodeReturnAad(recipient.kidR, { ...aad, hostId: "a".repeat(257) }))).toBe(
      "malformed",
    );
    expect(code(() => encodeReturnAad("ABCDEF0123456789", aad))).toBe("invalid_key");
  });

  it("round-trips random seals (fresh ephemeral and nonce each time)", () => {
    const pair = createReturnKeyPair();
    const a = sealToReturnKey(Buffer.from("x"), pair.publicKey, aad);
    const b = sealToReturnKey(Buffer.from("x"), pair.publicKey, aad);
    expect(a.subarray(0, 44).equals(b.subarray(0, 44))).toBe(false);
    expect(openSealed(a, pair, aad).toString()).toBe("x");
  });
});

describe("envelope v1", () => {
  const vector = vectors.cases[1]!;
  const aad = vector.aad as ReturnAad;
  const envelope = Buffer.from(vector.envelope, "hex");
  const seal = Buffer.from(vector.seal, "hex");

  it("refuses bad framing, oversize or non-canonical headers and seal mismatches", () => {
    const mutate = (fn: (b: Buffer) => void) => {
      const copy = Buffer.from(envelope);
      fn(copy);
      return copy;
    };
    expect(
      code(() =>
        parseEnvelope(
          mutate((b) => {
            b[0] = 0x58;
          }),
        ),
      ),
    ).toBe("malformed");
    expect(
      code(() =>
        parseEnvelope(
          mutate((b) => {
            b[4] = 2;
          }),
        ),
      ),
    ).toBe("malformed");
    expect(code(() => parseEnvelope(mutate((b) => b.writeUInt32BE(4097, 5))))).toBe("malformed");
    expect(code(() => parseEnvelope(envelope.subarray(0, envelope.byteLength - 1)))).toBe(
      "malformed",
    );
    expect(code(() => parseEnvelope(Buffer.concat([envelope, Buffer.from([0])])))).toBe(
      "malformed",
    );
    expect(code(() => parseEnvelope(envelope.subarray(0, 8)))).toBe("malformed");
    // Seal byte flipped: sealedSha256 no longer matches.
    expect(
      code(() =>
        parseEnvelope(
          mutate((b) => {
            b[b.byteLength - 1] ^= 1;
          }),
        ),
      ),
    ).toBe("malformed");
    // Same header semantics, different spelling (whitespace, key order, duplicates).
    const json = vector.headerJson;
    for (const spelled of [
      json.replace('{"kidR"', '{ "kidR"'),
      json.replace(/^\{("kidR":"[0-9a-f]+"),("recipientPubSha256":"[0-9a-f]+")/, "{$2,$1"),
      json.replace('{"kidR"', `{"kidR":"${vector.aad.hostId}","kidR"`),
      json.replace('"createdAt":', '"extra":1,"createdAt":'),
      json.replace(`"captureSeq":"${aad.captureSeq}"`, `"captureSeq":${aad.captureSeq}`),
    ]) {
      const header = Buffer.from(spelled, "utf8");
      const length = Buffer.alloc(4);
      length.writeUInt32BE(header.byteLength);
      const framed = Buffer.concat([Buffer.from("WSCO\x01", "latin1"), length, header, seal]);
      expect(
        code(() => parseEnvelope(framed)),
        spelled,
      ).toBe("malformed");
    }
  });

  it("opens only against the server-rebuilt context and the named recipient", () => {
    const parsed = parseEnvelope(envelope);
    for (const field of RETURN_AAD_FIELDS) {
      const expected = { ...aad, [field]: field === "captureSeq" ? "8" : `${aad[field]}x` };
      expect(
        code(() => openEnvelope(parsed, expected, recipient)),
        field,
      ).toBe("context_mismatch");
    }
    expect(code(() => openEnvelope(parsed, aad, createReturnKeyPair()))).toBe("context_mismatch");
    // A header that lies about its AAD still cannot open under the true context.
    const lying = buildEnvelope(headerFor(seal, { ...aad, leaseId: "cls_other" }), seal);
    expect(
      code(() => openEnvelope(parseEnvelope(lying), { ...aad, leaseId: "cls_other" }, recipient)),
    ).toBe("authentication_failed");
    expect(code(() => openEnvelope(parseEnvelope(lying), aad, recipient))).toBe("context_mismatch");
    // A different header over the same seal is a different digest (replay key).
    expect(parseEnvelope(lying).envelopeDigest.equals(parsed.envelopeDigest)).toBe(false);
  });

  it("caps the header at 4 KiB, measured after JSON escaping", () => {
    const max = Object.fromEntries(RETURN_AAD_FIELDS.map((f) => [f, aad[f]])) as ReturnAad;
    for (const f of ["hostOwnerId", "hostId", "sandboxOwnerId", "sandboxId", "leaseId"] as const)
      max[f] = "a".repeat(256);
    expect(() => buildEnvelope(headerFor(seal, max), seal)).not.toThrow();
    const control = "\u0001".repeat(256); // 6 bytes each once escaped
    const escaped = { ...aad, hostId: control, sandboxId: control, leaseId: control };
    expect(code(() => buildEnvelope(headerFor(seal, escaped), seal))).toBe("malformed");
  });
});
