import { createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const { DATA_KEY_PURPOSES, dataRootKey } = await import("../../crypto/data-key");
const {
  DISK_DEK_WRAP_PURPOSE,
  DiskKeyError,
  deriveDiskWrapKeys,
  diskDekAad,
  diskObjectKey,
  generateDiskDek,
  readDiskWrapKeys,
  shredOffloadKeys,
  unwrapDiskDek,
  wrapDiskDek,
} = await import("./keys");

const ROOT_A = dataRootKey("11".repeat(32));
const ROOT_B = dataRootKey("22".repeat(32));
const keysA = deriveDiskWrapKeys({ current: ROOT_A, previous: null });
const keysAB = deriveDiskWrapKeys({ current: ROOT_B, previous: ROOT_A });
const context = {
  userId: "user-1",
  sandboxId: "sbx-1",
  offloadId: "off-1",
  seq: 3,
  sessionId: "ses-1",
};

const saved = {
  key: process.env.DATA_ENCRYPTION_KEY,
  previous: process.env.DATA_ENCRYPTION_KEY_PREVIOUS,
  imageEncryption: process.env.IMAGE_STORE_ENCRYPTION,
};
afterEach(() => {
  for (const [name, value] of [
    ["DATA_ENCRYPTION_KEY", saved.key],
    ["DATA_ENCRYPTION_KEY_PREVIOUS", saved.previous],
    ["IMAGE_STORE_ENCRYPTION", saved.imageEncryption],
  ] as const)
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
});

const errorCode = (work: () => unknown) => {
  try {
    work();
  } catch (error) {
    return error instanceof DiskKeyError ? error.code : "other";
  }
  return "none";
};

describe("disk DEK wrap (offload plan §3)", () => {
  it("registers its own purpose and derives a key distinct from every other purpose", () => {
    expect(DATA_KEY_PURPOSES).toContain(DISK_DEK_WRAP_PURPOSE);
    expect(keysA.current.rootKeyId).toBe(ROOT_A.id);
    expect(keysA.current.purpose).toBe("sandbox-disk-dek-wrap:v1");
    expect(keysA.current.key.equals(keysAB.current.key)).toBe(false);
  });

  it("encodes the AAD as length-prefixed fields in the fixed order (vector)", () => {
    const aad = diskDekAad("0123456789abcdef", context);
    const fields = [
      "wssp:sandbox-disk-dek:v1",
      "0123456789abcdef",
      "user-1",
      "sbx-1",
      "off-1",
      "3",
      "ses-1",
    ];
    const expected = Buffer.concat(
      fields.map((field) => {
        const length = Buffer.alloc(4);
        length.writeUInt32BE(Buffer.byteLength(field));
        return Buffer.concat([length, Buffer.from(field)]);
      }),
    );
    expect(aad.equals(expected)).toBe(true);
    expect(aad.subarray(0, 4).toString("hex")).toBe("00000018");
  });

  it("opens with an independent HKDF + AES-256-GCM derivation (vector over the full AAD)", () => {
    const dek = generateDiskDek();
    const wrap = wrapDiskDek(keysA.current, { ...context, dek });
    expect(wrap.rootKid).toBe(ROOT_A.id);
    expect(wrap.wrapSalt.byteLength).toBe(32);
    expect(wrap.wrapNonce.byteLength).toBe(12);
    expect(wrap.wrappedKey.byteLength).toBe(48);
    const purposeKey = Buffer.from(
      hkdfSync("sha256", ROOT_A.key, "wssp-data-key-v1", "sandbox-disk-dek-wrap:v1", 32),
    );
    const rowKey = Buffer.from(
      hkdfSync("sha256", purposeKey, wrap.wrapSalt, "wssp:sandbox-disk-row:v1", 32),
    );
    const decipher = createDecipheriv("aes-256-gcm", rowKey, wrap.wrapNonce);
    decipher.setAAD(diskDekAad(ROOT_A.id, context));
    decipher.setAuthTag(wrap.wrappedKey.subarray(32));
    const opened = Buffer.concat([
      decipher.update(wrap.wrappedKey.subarray(0, 32)),
      decipher.final(),
    ]);
    expect(opened.equals(dek)).toBe(true);
    expect(unwrapDiskDek(wrap, context, keysA.all).equals(dek)).toBe(true);
  });

  it("never reuses a salt or nonce for the same DEK and context", () => {
    const dek = generateDiskDek();
    const one = wrapDiskDek(keysA.current, { ...context, dek });
    const two = wrapDiskDek(keysA.current, { ...context, dek });
    expect(one.wrapSalt.equals(two.wrapSalt)).toBe(false);
    expect(one.wrapNonce.equals(two.wrapNonce)).toBe(false);
    expect(one.wrappedKey.equals(two.wrappedKey)).toBe(false);
  });

  it.each([
    ["userId", { userId: "user-2" }],
    ["sandboxId", { sandboxId: "sbx-2" }],
    ["offloadId", { offloadId: "off-2" }],
    ["seq", { seq: 4 }],
    ["sessionId", { sessionId: "ses-2" }],
  ] as const)("refuses a wrap opened against another %s", (_field, change) => {
    const wrap = wrapDiskDek(keysA.current, { ...context, dek: generateDiskDek() });
    expect(errorCode(() => unwrapDiskDek(wrap, { ...context, ...change }, keysA.all))).toBe(
      "authentication_failed",
    );
  });

  it("binds the root kid: a wrap relabelled to another configured root never opens", () => {
    const wrap = wrapDiskDek(keysA.current, { ...context, dek: generateDiskDek() });
    expect(
      errorCode(() => unwrapDiskDek({ ...wrap, rootKid: ROOT_B.id }, context, keysAB.all)),
    ).toBe("authentication_failed");
    expect(unwrapDiskDek(wrap, context, keysAB.all).byteLength).toBe(32);
    expect(errorCode(() => unwrapDiskDek(wrap, context, [keysAB.current]))).toBe("key_unavailable");
  });

  it.each(["wrappedKey", "wrapSalt", "wrapNonce"] as const)("refuses a tampered %s", (column) => {
    const wrap = wrapDiskDek(keysA.current, { ...context, dek: generateDiskDek() });
    const tampered = Buffer.from(wrap[column]);
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    expect(
      errorCode(() => unwrapDiskDek({ ...wrap, [column]: tampered }, context, keysA.all)),
    ).toBe("authentication_failed");
  });

  it("refuses malformed input before any key use", () => {
    expect(errorCode(() => wrapDiskDek(keysA.current, { ...context, dek: Buffer.alloc(16) }))).toBe(
      "malformed",
    );
    expect(errorCode(() => diskDekAad("nope", context))).toBe("malformed");
    expect(errorCode(() => diskDekAad(ROOT_A.id, { ...context, seq: -1 }))).toBe("malformed");
    expect(errorCode(() => diskDekAad(ROOT_A.id, { ...context, sessionId: "" }))).toBe("malformed");
  });

  it("diskObjectKey rebuilds the AAD from the offload row and its completed session", () => {
    const dek = generateDiskDek();
    const wrap = wrapDiskDek(keysA.current, { ...context, dek });
    const row = {
      id: context.offloadId,
      userId: context.userId,
      sandboxId: context.sandboxId,
      seq: context.seq,
      completedSessionId: context.sessionId,
      encryption: "aes256gcm-r1",
      wrappedKey: new Uint8Array(wrap.wrappedKey),
      wrapSalt: new Uint8Array(wrap.wrapSalt),
      wrapNonce: new Uint8Array(wrap.wrapNonce),
      rootKid: wrap.rootKid,
    };
    expect(diskObjectKey(row, keysA.all).equals(dek)).toBe(true);
    expect(errorCode(() => diskObjectKey({ ...row, completedSessionId: "ses-2" }, keysA.all))).toBe(
      "authentication_failed",
    );
    expect(errorCode(() => diskObjectKey({ ...row, completedSessionId: null }, keysA.all))).toBe(
      "not_stored",
    );
    expect(errorCode(() => diskObjectKey({ ...row, wrappedKey: null }, keysA.all))).toBe(
      "not_stored",
    );
  });

  it("works from the environment with IMAGE_STORE_ENCRYPTION=off (disks are always encrypted)", () => {
    process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
    delete process.env.DATA_ENCRYPTION_KEY_PREVIOUS;
    process.env.IMAGE_STORE_ENCRYPTION = "off";
    const keys = readDiskWrapKeys();
    if (!keys) throw new Error("expected disk wrap keys");
    const dek = generateDiskDek();
    const wrap = wrapDiskDek(keys.current, { ...context, dek });
    expect(unwrapDiskDek(wrap, context).equals(dek)).toBe(true);
    delete process.env.DATA_ENCRYPTION_KEY;
    expect(readDiskWrapKeys()).toBeNull();
    expect(errorCode(() => unwrapDiskDek(wrap, context))).toBe("key_unavailable");
  });
});

describe("shredOffloadKeys order (T13; real rows: keys.pg.test.ts)", () => {
  function fakeTx(state: string | null) {
    const statements: string[] = [];
    const record = (parts: TemplateStringsArray) => {
      statements.push(parts.join("?").replace(/\s+/g, " ").trim());
    };
    const tx = {
      $queryRaw: vi.fn(async (parts: TemplateStringsArray) => {
        record(parts);
        if (parts.join("?").includes("FROM sandbox_disk_offload WHERE id"))
          return state ? [{ state }] : [];
        if (parts.join("?").includes("RETURNING id")) return [{ id: "ses-1", transferId: "t-1" }];
        return [];
      }),
      $executeRaw: vi.fn(async (parts: TemplateStringsArray) => {
        record(parts);
        return 1;
      }),
    };
    return { tx, statements };
  }

  it("takes the epoch FOR SHARE, aborts OPEN sessions, then nulls the offload wrap", async () => {
    const { tx, statements } = fakeTx("FAILED");
    await expect(shredOffloadKeys(tx as never, "off-1")).resolves.toEqual({
      abortedSessions: [{ id: "ses-1", transferId: "t-1" }],
    });
    expect(statements[0]).toMatch(/FROM data_key_epoch WHERE id = 1 FOR SHARE$/);
    expect(statements[1]).toMatch(/FROM sandbox_disk_offload WHERE id = \? FOR UPDATE$/);
    expect(statements[2]).toMatch(/^UPDATE sandbox_image_upload_session SET state = 'ABORTED'/);
    expect(statements[2]).toMatch(/"wrappedKey" = NULL/);
    expect(statements[3]).toMatch(/^UPDATE sandbox_image_upload_session SET encryption = NULL/);
    expect(statements[4]).toMatch(/^UPDATE sandbox_disk_offload SET "wrappedKey" = NULL/);
    expect(statements[4]).toMatch(/"shreddedAt" = COALESCE/);
    expect(statements).toHaveLength(5);
  });

  it.each(["STORED", "EVICTING"])(
    "refuses a %s row (its object still needs the key)",
    async (state) => {
      const { tx, statements } = fakeTx(state);
      await expect(shredOffloadKeys(tx as never, "off-1")).rejects.toMatchObject({
        code: "not_terminal",
      });
      expect(statements).toHaveLength(2);
    },
  );

  it("returns null for a missing row and writes nothing", async () => {
    const { tx, statements } = fakeTx(null);
    await expect(shredOffloadKeys(tx as never, "off-1")).resolves.toBeNull();
    expect(statements).toHaveLength(2);
  });
});
