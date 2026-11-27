import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("../../api/src/test/mock-prisma");
  return { default: await createMockPrisma() };
});
const { default: prisma } = await import("@wssp/db");
const { authorityTicket, onAuthorityCommitted } = await import("@wssp/db/authority");
const { onAuthSessionsRevoked } = await import("@wssp/db/session-revocation");
const { passwordChangeRevocationTarget, revokeCredentialsAfterPasswordChange } = await import(
  "./credential-revocation"
);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(prisma.session.findMany).mockResolvedValue([]);
  vi.mocked(prisma.verification.findMany).mockResolvedValue([]);
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("standing credential revocation", () => {
  it("unit: reset deletes all owner sessions and notifies after commit (real-DB: credential-mint-revocation.pg.test.ts)", async () => {
    const notified = vi.fn();
    const off = onAuthSessionsRevoked(notified);
    vi.mocked(prisma.$transaction).mockImplementationOnce(async (work) => {
      const result = await (typeof work === "function" ? work(prisma) : Promise.all(work));
      expect(prisma.session.deleteMany).toHaveBeenCalledWith({
        where: { userId: "owner" },
      });
      expect(notified).not.toHaveBeenCalled();
      return result;
    });
    try {
      await revokeCredentialsAfterPasswordChange("owner", { revokeSessions: true });
      await Promise.resolve();
      expect(notified).toHaveBeenCalledExactlyOnceWith({ userId: "owner" });
    } finally {
      off();
    }
  });

  it.each([true, false])(
    "unit: removes impersonations during reset/sign-out sweep (all sessions=%s)",
    async (revokeSessions) => {
      const notified = vi.fn();
      const off = onAuthSessionsRevoked(notified);
      vi.mocked(prisma.session.findMany).mockResolvedValueOnce([
        { id: "impersonation", userId: "target" },
      ] as never);
      try {
        await revokeCredentialsAfterPasswordChange("owner", { revokeSessions });
        expect(prisma.session.deleteMany).toHaveBeenCalledWith({
          where: { impersonatedBy: "owner" },
        });
        expect(notified).toHaveBeenCalledWith({ userId: "target", sessionId: "impersonation" });
      } finally {
        off();
      }
    },
  );

  it("revokes CLI/API and OAuth credentials with owner-scoped writes in one transaction", async () => {
    await revokeCredentialsAfterPasswordChange("owner");
    expect(prisma.$transaction).toHaveBeenCalledOnce();
    for (const model of [prisma.sdkKey, prisma.mcpGrant]) {
      expect(model.updateMany).toHaveBeenCalledExactlyOnceWith({
        where: { userId: "owner", revokedAt: null },
        data: { revokedAt: expect.any(Date) },
      });
    }
    for (const model of [prisma.oauthAccessToken, prisma.oauthRefreshToken, prisma.oauthConsent]) {
      expect(model.deleteMany).toHaveBeenCalledExactlyOnceWith({ where: { userId: "owner" } });
    }
    // No status filter: both claimed pending codes and approved codes are ended.
    expect(prisma.deviceCode.deleteMany).toHaveBeenCalledExactlyOnceWith({
      where: { userId: "owner", scope: "user-login" },
    });
    expect(prisma.session.deleteMany).toHaveBeenCalledExactlyOnceWith({
      where: { impersonatedBy: "owner" },
    });
  });

  it("leaves machine enrollments and host credentials unchanged", async () => {
    await revokeCredentialsAfterPasswordChange("owner");
    for (const model of [prisma.hostToken, prisma.hostDeviceCredential, prisma.sandboxHost]) {
      expect(model.updateMany).not.toHaveBeenCalled();
      expect(model.update).not.toHaveBeenCalled();
      expect(model.deleteMany).not.toHaveBeenCalled();
      expect(model.delete).not.toHaveBeenCalled();
    }
    expect(prisma.deviceCode.deleteMany).toHaveBeenCalledExactlyOnceWith({
      where: { userId: "owner", scope: "user-login" },
    });
  });

  it("invalidates the owner's existing and in-flight authority tickets and signals live consumers", async () => {
    const before = authorityTicket({ ownerId: "owner", credentialId: "key" });
    const unrelated = authorityTicket({ ownerId: "other-owner" });
    const seen = vi.fn();
    const off = onAuthorityCommitted(seen);
    let inFlight: (() => boolean) | undefined;
    vi.mocked(prisma.$transaction).mockImplementationOnce(async (work) => {
      inFlight = authorityTicket({ ownerId: "owner", credentialId: "key" });
      expect(before()).toBe(false);
      expect(inFlight()).toBe(false);
      return typeof work === "function" ? work(prisma) : Promise.all(work);
    });
    try {
      await revokeCredentialsAfterPasswordChange("owner");
      await Promise.resolve();
      expect(before()).toBe(false);
      expect(inFlight?.()).toBe(false);
      expect(unrelated()).toBe(true);
      expect(seen).toHaveBeenCalledWith({ kind: "scoped", ownerId: "owner" });
    } finally {
      off();
    }
  });

  it("retries a transient transaction failure", async () => {
    vi.mocked(prisma.$transaction).mockRejectedValueOnce(new Error("temporary failure"));
    const pending = revokeCredentialsAfterPasswordChange("owner");
    await vi.runAllTimersAsync();
    await pending;
    expect(prisma.$transaction).toHaveBeenCalledTimes(2);
  });

  it("logs a security failure without query details and rethrows after three failures", async () => {
    const error = new Error("private query parameters");
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(prisma.$transaction)
      .mockRejectedValueOnce(error)
      .mockRejectedValueOnce(error)
      .mockRejectedValueOnce(error);
    const pending = expect(revokeCredentialsAfterPasswordChange("owner")).rejects.toBe(error);
    await Promise.all([pending, vi.runAllTimersAsync()]);
    expect(prisma.$transaction).toHaveBeenCalledTimes(3);
    expect(log).toHaveBeenCalledWith(expect.stringContaining("SECURITY"), {
      userId: "owner",
      errorClass: "Error",
    });
    expect(JSON.stringify(log.mock.calls)).not.toContain(error.message);
  });
});

describe("password change revocation target", () => {
  it.each([
    {
      path: "/reset-password",
      body: { revokeOtherSessions: true },
      returned: { user: { id: "u" } },
    },
    {
      path: "/change-password",
      body: { revokeOtherSessions: false },
      returned: { user: { id: "u" } },
    },
    {
      path: "/change-password",
      body: { revokeOtherSessions: true },
      returned: { status: "BAD_REQUEST" },
    },
    {
      path: "/change-password",
      body: { revokeOtherSessions: true },
      returned: { user: { id: "" } },
    },
  ])("ignores unsuccessful or ineligible requests: %j", (ctx) => {
    expect(passwordChangeRevocationTarget(ctx)).toBeNull();
  });
});
