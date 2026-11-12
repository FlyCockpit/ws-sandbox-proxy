import { beforeEach, describe, expect, it, vi } from "vitest";
import { deviceRow, deviceStore, gate } from "./device-code-test-harness";

vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "test-better-auth-secret" } }));
vi.mock("@wssp/db", async () => ({
  default: await (await import("../test/mock-prisma")).createMockPrisma(),
}));
const { default: prisma } = await import("@wssp/db");
const { mintHostDeviceCredentialFromApprovedDeviceCode: exchange } = await import(
  "./host-device-credential-access"
);
let store: ReturnType<typeof deviceStore>;
function mint(deviceCode = "secret-code-1") {
  return exchange({ deviceCode, hostSlug: "desk-01" });
}
beforeEach(() => {
  store = deviceStore();
  Object.assign(prisma, store.db);
  store.state.deviceCode.set("code-1", deviceRow());
  store.state.user.set("user-1", {
    id: "user-1",
    banned: false,
    banExpires: null,
    emailVerified: true,
    twoFactorEnabled: true,
    role: "admin",
    createdAt: new Date("2020-01-01"),
  });
});

describe("device exchange transaction", () => {
  it("mints and consumes once; replay cannot mint", async () => {
    const result = await mint();
    expect(result.secret).toMatch(/^wssp_device_/);
    expect(store.state.deviceCode.size).toBe(0);
    expect(store.state.hostDeviceCredential.size).toBe(1);
    expect(store.state.sandboxHost.size).toBe(1);
    await expect(mint()).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(JSON.stringify([...store.state.hostDeviceCredential.values()])).not.toContain(
      result.secret,
    );
  });

  it.each([false, true])(
    "concurrent exchanges same code vs different code same slug: different=%s",
    async (different) => {
      if (different)
        store.state.deviceCode.set(
          "code-2",
          deviceRow({ id: "code-2", deviceCode: "secret-code-2" }),
        );
      if (!different) {
        store.state.deviceCode.set(
          "code-1",
          deviceRow({ enrollmentIntent: "replace", replaceHostId: "host-existing" }),
        );
        store.state.sandboxHost.set("host-existing", {
          id: "host-existing",
          userId: "user-1",
          slug: "desk-01",
        });
      }
      const consumed = gate(),
        release = gate(),
        waiting = gate();
      store.hooks.afterConsume = async () => {
        consumed.open();
        await release.promise;
      };
      store.hooks.onWait = () => waiting.open();
      const first = mint();
      await consumed.promise;
      const second = mint(different ? "secret-code-2" : "secret-code-1");
      await waiting.promise;
      release.open();
      const results = await Promise.allSettled([first, second]);
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      expect(store.state.hostDeviceCredential.size).toBe(1);
      expect(store.state.sandboxHost.size).toBe(1);
      expect(store.state.deviceCode.size).toBe(different ? 1 : 0);
      if (different)
        expect(results[1]).toMatchObject({ status: "rejected", reason: { code: "CONFLICT" } });
    },
  );

  it("rolls back after actual consumption and host creation when credential insertion fails", async () => {
    store.hooks.beforeCredential = async () => {
      expect(store.events).toContain("consume");
      throw new Error("credential insert failed");
    };
    await expect(mint()).rejects.toThrow("credential insert failed");
    expect(store.events).toContain("create:sandboxHost");
    expect(store.events).toContain("consume");
    expect(store.events).toContain("rollback");
    expect(store.state.deviceCode.get("code-1")).toEqual(deviceRow());
    expect(store.state.hostDeviceCredential.size).toBe(0);
    expect(store.state.sandboxHost.size).toBe(0);
  });

  it("uses database time after a device lock wait crosses expiry", async () => {
    const locked = gate(),
      release = gate(),
      waiting = gate();
    const holder = store.db.$transaction(async (tx) => {
      const db = tx as {
        $queryRaw: (parts: TemplateStringsArray, ...values: unknown[]) => Promise<unknown>;
      };
      await db.$queryRaw`SELECT id FROM device_code WHERE id = ${"code-1"} FOR UPDATE`;
      locked.open();
      await release.promise;
    });
    await locked.promise;
    store.hooks.onWait = () => waiting.open();
    const result = mint();
    await waiting.promise;
    store.now = new Date("2026-07-01T00:11:00Z");
    release.open();
    await holder;
    await expect(result).rejects.toMatchObject({ data: { deviceFlowError: "expired_token" } });
    expect(store.state.deviceCode.size).toBe(1);
    expect(store.state.hostDeviceCredential.size).toBe(0);
    expect(store.state.sandboxHost.size).toBe(0);
  });

  it("pending then slow_down persists the polling timestamp without minting", async () => {
    store.state.deviceCode.set("code-1", deviceRow({ status: "pending", userId: null }));
    await expect(mint()).rejects.toMatchObject({
      data: { deviceFlowError: "authorization_pending" },
    });
    expect(store.state.deviceCode.get("code-1")?.lastPolledAt).toEqual(store.now);
    await expect(mint()).rejects.toMatchObject({ data: { deviceFlowError: "slow_down" } });
    expect(store.state.hostDeviceCredential.size).toBe(0);
  });

  it("CAS miss classifies slow_down from the locked row lastPolledAt", async () => {
    store.state.deviceCode.set("code-1", deviceRow({ status: "pending", userId: null }));
    const [first, second] = await Promise.allSettled([mint(), mint()]);
    const flowErrors = [first, second].map((result) =>
      result.status === "rejected"
        ? (result.reason as { data?: { deviceFlowError?: string } }).data?.deviceFlowError
        : null,
    );
    expect(flowErrors).toContain("authorization_pending");
    expect(flowErrors).toContain("slow_down");
  });

  it("pending bookkeeping handles a missing row after the read", async () => {
    store.state.deviceCode.set("code-1", deviceRow({ status: "pending", userId: null }));
    store.hooks.beforeLock = async () => {
      store.state.deviceCode.delete("code-1");
    };
    await expect(mint()).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(store.state.hostDeviceCredential.size).toBe(0);
  });

  it.each(["denied", "expired"])("never mints for %s", async (state) => {
    store.state.deviceCode.set(
      "code-1",
      deviceRow(state === "denied" ? { status: "denied" } : { expiresAt: new Date("2026-06-01") }),
    );
    await expect(mint()).rejects.toMatchObject({
      data: { deviceFlowError: state === "denied" ? "access_denied" : "expired_token" },
    });
    expect(store.state.hostDeviceCredential.size).toBe(0);
    expect(store.state.deviceCode.size).toBe(state === "denied" ? 0 : 1);
  });

  it.each(["banned", "twoFactorEnabled", "emailVerified"])(
    "rechecks owner %s inside mint",
    async (field) => {
      const owner = store.state.user.get("user-1");
      if (!owner) throw new Error("fixture");
      owner[field] = field === "banned";
      await expect(mint()).rejects.toMatchObject({ code: "FORBIDDEN" });
      expect(store.state.deviceCode.size).toBe(1);
      expect(store.state.hostDeviceCredential.size).toBe(0);
    },
  );

  it("replaces only the approved identity and revokes previous credentials", async () => {
    store.state.deviceCode.set(
      "code-1",
      deviceRow({ enrollmentIntent: "replace", replaceHostId: "host-old" }),
    );
    store.state.sandboxHost.set("host-old", {
      id: "host-old",
      userId: "user-1",
      slug: "desk-01",
      label: "Keep",
    });
    store.state.hostDeviceCredential.set("prior", {
      id: "prior",
      userId: "user-1",
      sandboxHostId: "host-old",
      revokedAt: null,
    });
    const result = await mint();
    expect(result.hostId).toBe("host-old");
    expect(store.state.hostDeviceCredential.get("prior")?.revokedAt).toEqual(store.now);
    expect(store.state.sandboxHost.get("host-old")?.label).toBe("Keep");
  });

  it.each([false, true])(
    "deleted/recycled replacement target conflicts: recycled=%s",
    async (recycled) => {
      store.state.deviceCode.set(
        "code-1",
        deviceRow({ enrollmentIntent: "replace", replaceHostId: "host-old" }),
      );
      if (recycled)
        store.state.sandboxHost.set("new", { id: "new", userId: "user-1", slug: "desk-01" });
      await expect(mint()).rejects.toMatchObject({ code: "CONFLICT" });
      expect(store.state.deviceCode.size).toBe(1);
      expect(store.state.hostDeviceCredential.size).toBe(0);
    },
  );

  it("does not mislabel a credential unique violation as a slug conflict", async () => {
    const error = Object.assign(new Error("digest collision"), {
      code: "P2002",
      meta: { target: ["secretDigest"] },
    });
    store.hooks.beforeCredential = async () => {
      throw error;
    };
    await expect(mint()).rejects.toBe(error);
    expect(store.state.deviceCode.size).toBe(1);
  });
});

it("pending bookkeeping cannot write across a concurrent approval", async () => {
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending" }));
  store.hooks.beforeLock = async () => {
    store.state.deviceCode.set("code-1", deviceRow({ status: "approved" }));
  };
  await expect(mint()).rejects.toMatchObject({
    data: { deviceFlowError: "authorization_pending" },
  });
  expect(store.state.deviceCode.get("code-1")?.lastPolledAt).toBeNull();
});

function replaceFixture(userId = "user-1", slug = "desk-01") {
  store.state.deviceCode.set(
    "code-1",
    deviceRow({ enrollmentIntent: "replace", replaceHostId: "host-old" }),
  );
  store.state.sandboxHost.set("host-old", { id: "host-old", userId, slug });
}

it.each(["user", "slug"])(
  "foreign replacement %s takes no lock on the foreign row",
  async (field) => {
    replaceFixture(
      field === "user" ? "other-user" : "user-1",
      field === "slug" ? "other-slug" : "desk-01",
    );
    await expect(mint()).rejects.toMatchObject({ code: "CONFLICT" });
    expect(store.events).not.toContain("lock:sandboxHost:host-old");
    expect(store.state.hostDeviceCredential.size).toBe(0);
    expect(store.state.deviceCode.size).toBe(1);
  },
);

it.each(["host", "credential", "revoke", "settings"])(
  "grace crossing during %s wait rolls back mint",
  async (wait) => {
    replaceFixture();
    const owner = store.state.user.get("user-1");
    if (!owner) throw new Error("fixture");
    Object.assign(owner, { twoFactorEnabled: false, createdAt: new Date("2026-06-30T00:00:01Z") });
    const reached = gate(),
      release = gate();
    const advance = async () => {
      reached.open();
      await release.promise;
    };
    let holder: Promise<unknown> | undefined;
    if (wait === "host") {
      const locked = gate();
      holder = store.db.$transaction(async (tx) => {
        const db = tx as {
          $queryRaw: (parts: TemplateStringsArray, ...values: unknown[]) => Promise<unknown>;
        };
        await db.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${"host-old"} FOR UPDATE`;
        locked.open();
        await release.promise;
      });
      await locked.promise;
      store.hooks.onWait = () => reached.open();
    } else if (wait === "credential") store.hooks.beforeCredential = advance;
    else if (wait === "revoke") store.hooks.beforeRevoke = advance;
    else store.hooks.beforeSettings = advance;
    // Keep the application clock inside grace, while the DB clock crosses it.
    vi.spyOn(Date, "now").mockReturnValue(store.now.getTime());
    try {
      const result = mint();
      await reached.promise;
      store.now = new Date("2026-07-01T00:00:02Z");
      release.open();
      await holder;
      await expect(result).rejects.toMatchObject({ code: "FORBIDDEN" });
      expect(store.state.hostDeviceCredential.size).toBe(0);
      expect(store.state.deviceCode.size).toBe(1);
    } finally {
      release.open();
      vi.restoreAllMocks();
    }
  },
);

describe("unit (recording transaction; no real-DB test yet) — enrollment lock order and owner-FK mapping", () => {
  it("replacement locks the owned host before device code without a User UPDATE lock", async () => {
    replaceFixture();
    await mint();
    expect(store.events.indexOf("lock:sandboxHost:host-old")).toBeLessThan(
      store.events.indexOf("lock:deviceCode:code-1"),
    );
    expect(store.events).not.toContain("lock:user:user-1");
  });
  it("creation locks device code before owner-slug insertion without a User UPDATE lock", async () => {
    await mint();
    expect(store.events.indexOf("lock:deviceCode:code-1")).toBeLessThan(
      store.events.indexOf("lock:slug:user-1:desk-01"),
    );
    expect(store.events).not.toContain("lock:user:user-1");
  });

  it.each(["create", "replace"])(
    "C21-ACCTDEL-RACE %s enrollment takes the owner FOR SHARE lock before every insert",
    async (intent) => {
      if (intent === "replace") replaceFixture();
      await mint();
      const share = store.events.indexOf("share:user:user-1");
      expect(share).toBeGreaterThanOrEqual(0);
      expect(share).toBeLessThan(store.events.indexOf("create:hostDeviceCredential"));
      if (intent === "create")
        expect(share).toBeLessThan(store.events.indexOf("create:sandboxHost"));
      else expect(share).toBeLessThan(store.events.indexOf("lock:sandboxHost:host-old"));
    },
  );
  it("C21-ACCTDEL-RACE a tombstoned owner cannot enroll: CONFLICT, nothing created", async () => {
    store.state.user.get("user-1")!.deletionRequestedAt = new Date();
    await expect(mint()).rejects.toMatchObject({
      code: "CONFLICT",
      message: "The account changed during enrollment.",
    });
    expect(store.state.sandboxHost.size).toBe(0);
    expect(store.state.hostDeviceCredential.size).toBe(0);
    expect(store.state.deviceCode.size).toBe(1);
  });
  it("C21-ACCTDEL-RACE an owner-FK P2003 during enrollment maps to CONFLICT", async () => {
    store.hooks.beforeCredential = async () => {
      throw Object.assign(new Error("fk"), { code: "P2003" });
    };
    await expect(mint()).rejects.toMatchObject({ code: "CONFLICT" });
    expect(store.state.hostDeviceCredential.size).toBe(0);
  });
});

it.each(["pending", "approved"])(
  "application clock ahead cannot expire or delete a DB-live %s code",
  async (status) => {
    store.state.deviceCode.set("code-1", deviceRow({ status }));
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-02"));
    try {
      if (status === "pending") {
        await expect(mint()).rejects.toMatchObject({
          data: { deviceFlowError: "authorization_pending" },
        });
        expect(store.state.deviceCode.size).toBe(1);
      } else await expect(mint()).resolves.toMatchObject({ hostId: expect.any(String) });
    } finally {
      vi.useRealTimers();
    }
  },
);

it.each(["denied", "expired"])("CAS miss rereads the typed terminal %s state", async (state) => {
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending" }));
  store.hooks.beforeLock = async () => {
    store.state.deviceCode.set(
      "code-1",
      deviceRow(
        state === "denied"
          ? { status: "denied" }
          : { status: "pending", expiresAt: new Date("2026-06-01") },
      ),
    );
  };
  await expect(mint()).rejects.toMatchObject({
    data: { deviceFlowError: state === "denied" ? "access_denied" : "expired_token" },
  });
  expect(store.state.deviceCode.size).toBe(0);
});

it.each(["P2034", "40P01", "40001"])(
  "mint conflict %s rolls back and remains retryable",
  async (code) => {
    store.hooks.beforeCredential = async () => {
      throw { code };
    };
    await expect(mint()).rejects.toMatchObject({
      code: "SERVICE_UNAVAILABLE",
      data: { deviceFlowError: "authorization_pending" },
    });
    expect(store.state.deviceCode.size).toBe(1);
    expect(store.state.sandboxHost.size).toBe(0);
    expect(store.state.hostDeviceCredential.size).toBe(0);
  },
);

it("expiry crossing the final credential write rolls back consumption", async () => {
  store.hooks.beforeCredential = async () => {
    store.now = new Date("2026-07-01T00:11:00Z");
  };
  await expect(mint()).rejects.toMatchObject({ data: { deviceFlowError: "expired_token" } });
  expect(store.state.deviceCode.size).toBe(1);
  expect(store.state.sandboxHost.size).toBe(0);
  expect(store.state.hostDeviceCredential.size).toBe(0);
});
