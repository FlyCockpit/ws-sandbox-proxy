import { invalidateForceTwoFactorSettingsCache } from "@wssp/api/lib/two-factor-policy";
import { withAuthorityChange, withGlobalAuthorityChange } from "@wssp/db/authority";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SandboxRelaySessionManager } from "./session-manager.js";

// Only Prisma is mocked: the authority registry and revalidateSandboxHostIdentity
// (host-token-access) are the production modules (C21-TESTS).
vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "session-authority-test" } }));
vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep<typeof import("@wssp/db").default>() };
});
const { default: prisma } = await import("@wssp/db");
const db = vi.mocked(prisma, true);

class FakeSocket {
  readyState = 1;
  bufferedAmount = 0;
  closes: { code?: number; reason?: string }[] = [];
  send() {}
  close(code?: number, reason?: string) {
    this.closes.push({ code, reason });
    this.readyState = 3;
  }
}

const identity = {
  hostId: "host-1",
  userId: "user-1",
  tokenId: "token-1",
  credentialKind: "hostToken" as const,
  expiresAt: null,
};

type TokenRow = {
  id: string;
  userId: string;
  sandboxHostId: string;
  lookupPrefix: string;
  secretDigest: string;
  revokedAt: Date | null;
  expiresAt: Date | null;
  SandboxHost: { userId: string; deletionRequestedAt: Date | null };
  User: {
    deletionRequestedAt: Date | null;
    banned: boolean;
    banExpires: Date | null;
    twoFactorEnabled: boolean;
    createdAt: Date;
    role: string;
  };
};

let row: TokenRow;
let settings: { key: string; value: string }[];
let manager: SandboxRelaySessionManager;

/** Committed listeners run in a microtask; revalidation then awaits durable reads. */
async function settle() {
  for (let i = 0; i < 10; i += 1) await new Promise<void>((resolve) => setImmediate(resolve));
}

beforeEach(() => {
  vi.clearAllMocks();
  invalidateForceTwoFactorSettingsCache();
  settings = [];
  row = {
    id: "token-1",
    userId: "user-1",
    sandboxHostId: "host-1",
    lookupPrefix: "prefix",
    secretDigest: "digest",
    revokedAt: null,
    expiresAt: null,
    SandboxHost: { userId: "user-1", deletionRequestedAt: null },
    User: {
      deletionRequestedAt: null,
      banned: false,
      banExpires: null,
      twoFactorEnabled: false,
      createdAt: new Date("2020-01-01T00:00:00Z"),
      role: "user",
    },
  };
  db.hostToken.findUnique.mockImplementation((async () => structuredClone(row)) as never);
  db.appSetting.findMany.mockImplementation((async () => settings) as never);
  manager = new SandboxRelaySessionManager();
});

afterEach(() => {
  manager.dispose();
});

describe("C21 real authority registry + real host revalidation", () => {
  it("an owner-scoped grant-direction change (2FA enable) keeps a valid socket open", async () => {
    const socket = new FakeSocket();
    manager.acceptAuthenticatedSocket({ socket, identity });
    await withAuthorityChange({ ownerId: "user-1" }, async () => {
      row.User.twoFactorEnabled = true;
    });
    await settle();
    // Revalidation really ran against the durable row, and passed.
    expect(db.hostToken.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: "token-1" } }),
    );
    expect(socket.closes).toEqual([]);
    expect(manager.isHostConnected("host-1")).toBe(false); // never registered (no hello)
  });

  it("a token revoke closes the socket with 4003", async () => {
    const socket = new FakeSocket();
    manager.acceptAuthenticatedSocket({ socket, identity });
    await withAuthorityChange({ ownerId: "user-1", credentialId: "token-1" }, async () => {
      row.revokedAt = new Date();
    });
    await settle();
    // 4003 (revoke); the reason is the explicit verdict the daemon stops VMs on.
    expect(socket.closes).toEqual([{ code: 4003, reason: "credential_revoked" }]);
  });

  it("a foreign owner's change does not revalidate or close this owner's socket", async () => {
    const socket = new FakeSocket();
    manager.acceptAuthenticatedSocket({ socket, identity });
    await withAuthorityChange({ ownerId: "user-2" }, async () => undefined);
    await settle();
    expect(db.hostToken.findUnique).not.toHaveBeenCalled();
    expect(socket.closes).toEqual([]);
  });

  it("a global forced-2FA change revalidates every session and keeps a compliant one", async () => {
    row.User.twoFactorEnabled = true;
    const compliant = new FakeSocket();
    manager.acceptAuthenticatedSocket({ socket: compliant, identity });
    await withGlobalAuthorityChange(async () => {
      settings = [{ key: "force2faPublicUsers", value: "true" }];
      invalidateForceTwoFactorSettingsCache();
    });
    await settle();
    expect(db.hostToken.findUnique).toHaveBeenCalledTimes(1);
    expect(compliant.closes).toEqual([]);
  });

  it("a global change revalidates many sessions in bounded parallel batches", async () => {
    row.User.twoFactorEnabled = true;
    const sockets = Array.from({ length: 20 }, (_, index) => {
      const socket = new FakeSocket();
      manager.acceptAuthenticatedSocket({
        socket,
        identity: { ...identity, hostId: `host-${index}`, tokenId: `token-${index}` },
      });
      return socket;
    });
    let inFlight = 0;
    let peak = 0;
    db.hostToken.findUnique.mockImplementation((async ({ where }: { where: { id: string } }) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise<void>((resolve) => setImmediate(resolve));
      inFlight -= 1;
      const index = where.id.slice("token-".length);
      return { ...structuredClone(row), id: where.id, sandboxHostId: `host-${index}` };
    }) as never);
    await withGlobalAuthorityChange(async () => {
      settings = [{ key: "force2faPublicUsers", value: "true" }];
      invalidateForceTwoFactorSettingsCache();
    });
    for (let i = 0; i < 10; i += 1) await settle();
    expect(db.hostToken.findUnique).toHaveBeenCalledTimes(20);
    expect(peak).toBeGreaterThan(1);
    expect(peak).toBeLessThanOrEqual(8);
    for (const socket of sockets) expect(socket.closes).toEqual([]);
  });

  it("a global forced-2FA change closes a non-compliant session with 4003", async () => {
    const nonCompliant = new FakeSocket();
    manager.acceptAuthenticatedSocket({ socket: nonCompliant, identity });
    await withGlobalAuthorityChange(async () => {
      settings = [{ key: "force2faPublicUsers", value: "true" }];
      invalidateForceTwoFactorSettingsCache();
    });
    await settle();
    expect(nonCompliant.closes).toEqual([{ code: 4003, reason: "credential_inactive" }]);
  });

  it("an infrastructure error during revalidation closes 1011, not 4003", async () => {
    const socket = new FakeSocket();
    manager.acceptAuthenticatedSocket({ socket, identity });
    db.hostToken.findUnique.mockRejectedValueOnce(new Error("connection reset"));
    await withAuthorityChange({ ownerId: "user-1" }, async () => undefined);
    await settle();
    expect(socket.closes).toEqual([{ code: 1011, reason: "internal_error" }]);
  });

  it("revalidation overlapped by an in-flight change is stale, not inactive: the socket stays open", async () => {
    const socket = new FakeSocket();
    manager.acceptAuthenticatedSocket({ socket, identity });
    let release!: () => void;
    const inFlight = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started = false;
    db.hostToken.findUnique.mockImplementation((async () => {
      // A second (grant-direction) change starts during the first revalidation and
      // stays open across all of its retry attempts: every ticket is invalidated.
      if (!started) {
        started = true;
        void withAuthorityChange({ ownerId: "user-1" }, () => inFlight);
      }
      return structuredClone(row);
    }) as never);
    await withAuthorityChange({ ownerId: "user-1" }, async () => undefined);
    await settle();
    expect(db.hostToken.findUnique).toHaveBeenCalledTimes(3);
    expect(socket.closes).toEqual([]);
    // The overlapping change commits; its own revalidation decides (active).
    release();
    await settle();
    expect(db.hostToken.findUnique).toHaveBeenCalledTimes(4);
    expect(socket.closes).toEqual([]);
  });
});
