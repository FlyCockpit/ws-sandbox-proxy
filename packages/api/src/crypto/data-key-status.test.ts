import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const { readDataKeyStatus, safeToRemove, DATA_KEY_COLUMNS } = await import("./data-key-status");
const { readDataKeyHeartbeats, startDataKeyHeartbeat, heldKids, DATA_KEY_HEARTBEAT_PREFIX } =
  await import("./data-key-heartbeat");
const { writeKeyForEpoch, DataKeyStaleWriter, promoteDataKey } = await import("./data-key-epoch");

const A = "aaaaaaaaaaaaaaaa";
const B = "bbbbbbbbbbbbbbbb";
const root = (id: string) => ({ id, key: Buffer.alloc(32, 1) });

describe("write fence helpers (unit; locking: data-key-epoch.pg.test.ts)", () => {
  it("picks the key the epoch names, whatever the env current is, and refuses a missing one", () => {
    const keys = [{ rootKeyId: A }, { rootKeyId: B }];
    expect(writeKeyForEpoch(keys, { currentKid: B })).toBe(keys[1]);
    expect(() => writeKeyForEpoch([{ rootKeyId: A }], { currentKid: B })).toThrow(
      DataKeyStaleWriter,
    );
  });

  it("promote refuses a malformed or unheld kid before any database IO", async () => {
    const ring = { current: root(A), previous: null };
    await expect(promoteDataKey(ring, "nope")).resolves.toEqual({
      ok: false,
      reason: "kid_malformed",
    });
    await expect(promoteDataKey(ring, B)).resolves.toEqual({ ok: false, reason: "key_not_held" });
  });
});

describe("status", () => {
  it("safe_to_remove needs a switched epoch and zero rows in every registered column", () => {
    expect(safeToRemove(null, [], A)).toBe(false);
    expect(safeToRemove({ currentKid: A }, [], A)).toBe(false);
    expect(safeToRemove({ currentKid: B }, [{ kid: A, rows: 1 }], A)).toBe(false);
    expect(
      safeToRemove(
        { currentKid: B },
        [
          { kid: A, rows: 0 },
          { kid: B, rows: 9 },
        ],
        A,
      ),
    ).toBe(true);
  });

  it("registers every encrypted column, including the webhook overlap secret and live return keys", () => {
    expect(DATA_KEY_COLUMNS.map((column) => column.source)).toEqual([
      "webhook_endpoint.secretKeyId",
      "webhook_endpoint.previousSecretKeyId",
      "credential_secret_version.rootKid",
      "credential_return_key.rootKid",
      "sandbox_disk_offload.rootKid",
      "sandbox_image_upload_session.keyId",
    ]);
  });

  it("sums counts per kid across tables and marks the switched-away kid removable once empty", async () => {
    const counts = [[{ kid: A, rows: 1 }], [], [{ kid: B, rows: 4 }], [{ kid: B, rows: 1 }]];
    let call = 0;
    const client = {
      $queryRaw: vi.fn(async (query: TemplateStringsArray) => {
        if (query.join("?").includes("data_key_epoch"))
          return [
            {
              currentKid: B,
              previousKid: A,
              epoch: 2n,
              switchedAt: new Date("2026-11-03T00:00:00Z"),
            },
          ];
        return counts[call++] ?? [];
      }),
    };
    const status = await readDataKeyStatus({
      ring: { current: root(B), previous: root(A) },
      client: client as never,
    });
    expect(status.epoch).toEqual({
      currentKid: B,
      previousKid: A,
      epoch: "2",
      switchedAt: "2026-11-03T00:00:00.000Z",
    });
    expect(status.kids).toEqual([
      { kid: A, rows: 1, current: false, safeToRemove: false },
      { kid: B, rows: 5, current: true, safeToRemove: false },
    ]);
    expect(status.held).toEqual([B, A]);
    expect(status.heartbeats).toBeNull();
  });
});

describe("advisory heartbeats", () => {
  it("publish kids only with a TTL and read back a bounded, validated set", async () => {
    const store = new Map<string, string>();
    const redis = {
      set: vi.fn(async (key: string, value: string) => void store.set(key, value)),
      scan: vi.fn(
        async () =>
          ["0", [...store.keys(), `${DATA_KEY_HEARTBEAT_PREFIX}junk`]] as [string, string[]],
      ),
      mget: vi.fn(async (keys: string[]) =>
        keys.map((key) => (key.endsWith("junk") ? "{not json" : (store.get(key) ?? null))),
      ),
    };
    const controller = new AbortController();
    startDataKeyHeartbeat({
      redis,
      role: "worker",
      readRing: () => ({ current: root(A), previous: root(B) }),
      signal: controller.signal,
    });
    controller.abort();
    expect(redis.set).toHaveBeenCalledWith(
      expect.stringMatching(/^wssp:data-key:heartbeat:worker:/),
      expect.any(String),
      "EX",
      120,
    );
    const written = String(redis.set.mock.calls[0]?.[1]);
    expect(written).not.toContain(Buffer.alloc(32, 1).toString("hex"));
    const beats = await readDataKeyHeartbeats(redis);
    expect(beats).toEqual([{ role: "worker", keysHeld: [A, B], at: expect.any(String) }]);
    expect(heldKids(null)).toEqual([]);
  });

  it("a throwing ring or Redis never escapes the heartbeat", () => {
    const controller = new AbortController();
    expect(() =>
      startDataKeyHeartbeat({
        redis: {
          set: () => {
            throw new Error("down");
          },
          scan: vi.fn(),
          mget: vi.fn(),
        } as never,
        role: "server",
        readRing: () => {
          throw new Error("invalid");
        },
        signal: controller.signal,
      }),
    ).not.toThrow();
    controller.abort();
  });
});
