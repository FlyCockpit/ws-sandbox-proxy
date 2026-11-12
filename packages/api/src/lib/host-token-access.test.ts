import { withAuthorityChange } from "@wssp/db/authority";
import {
  credentialLookupPrefix,
  generateProductCredentialSecret,
  hmacDigestForProductPurpose,
  PRODUCT_CREDENTIAL_PREFIXES,
  PRODUCT_CREDENTIAL_SUFFIX_LENGTH,
} from "@wssp/db/credential-security";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "test-better-auth-secret" },
}));

const verifierCalls = vi.hoisted(() => [] as Array<{ purpose: string; digest: string }>);
vi.mock("@wssp/db/credential-security", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@wssp/db/credential-security")>();
  return {
    ...actual,
    verifyProductCredentialDigest: (
      input: Parameters<typeof actual.verifyProductCredentialDigest>[0],
    ) => {
      verifierCalls.push({ purpose: input.purpose, digest: input.digest });
      return actual.verifyProductCredentialDigest(input);
    },
  };
});

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

const {
  authenticateSandboxHostWebsocketSecret,
  digestHostTokenSecret,
  hostDeviceCredentialListSelect,
  hostTokenListSelect,
  revalidateSandboxHostIdentity,
} = await import("./host-token-access");
const { default: prisma } = await import("@wssp/db");
const { invalidateForceTwoFactorSettingsCache } = await import("./two-factor-policy");

const db = prisma as unknown as {
  hostToken: {
    findUnique: MockInstance;
    update: MockInstance;
  };
  hostDeviceCredential: {
    findUnique: MockInstance;
    update: MockInstance;
  };
  appSetting: { findMany: MockInstance };
};

const established = new Date("2020-01-01T00:00:00.000Z");

beforeEach(() => {
  invalidateForceTwoFactorSettingsCache();
  db.appSetting.findMany.mockResolvedValue([]);
});

function ownerUser(overrides: Record<string, unknown> = {}) {
  return {
    banned: false,
    banExpires: null,
    twoFactorEnabled: true,
    createdAt: established,
    role: "user",
    ...overrides,
  };
}

const now = new Date("2026-01-01T00:00:00.000Z");

describe("hostTokenAccess", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
    db.appSetting.findMany.mockResolvedValue([]);
  });

  it("verifies active wssp_host_ tokens with the host-token HMAC context", async () => {
    const credential = generateProductCredentialSecret("hostToken");
    const lookupPrefix = credentialLookupPrefix(credential);
    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix,
      User: ownerUser(),
      secretDigest: digestHostTokenSecret(credential),
      revokedAt: null,
      expiresAt: null,
    });
    db.hostToken.update.mockResolvedValue({ id: "token-id" });

    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toEqual({
      hostId: "host-id",
      userId: "user-id",
      tokenId: "token-id",
      credentialKind: "hostToken",
      expiresAt: null,
    });
  });

  it("rejects malformed and wrong-purpose secrets before lookup", async () => {
    const valid = generateProductCredentialSecret("hostToken");
    const sharedLookupPrefix = credentialLookupPrefix(valid);

    const malformedHostCases = [
      PRODUCT_CREDENTIAL_PREFIXES.hostToken,
      `${PRODUCT_CREDENTIAL_PREFIXES.hostToken}${"a".repeat(PRODUCT_CREDENTIAL_SUFFIX_LENGTH - 1)}`,
      `${PRODUCT_CREDENTIAL_PREFIXES.hostToken}${"a".repeat(PRODUCT_CREDENTIAL_SUFFIX_LENGTH + 1)}`,
      `${PRODUCT_CREDENTIAL_PREFIXES.hostToken}${"A".repeat(PRODUCT_CREDENTIAL_SUFFIX_LENGTH - 1)}=`,
      `${PRODUCT_CREDENTIAL_PREFIXES.hostToken}${"A".repeat(20)} ${"A".repeat(22)}`,
      `${PRODUCT_CREDENTIAL_PREFIXES.hostToken}${"A".repeat(20)}é${"A".repeat(21)}`,
      `${PRODUCT_CREDENTIAL_PREFIXES.hostToken}${"A".repeat(20)}@${"A".repeat(21)}`,
      sharedLookupPrefix,
    ];

    for (const candidate of malformedHostCases) {
      await expect(authenticateSandboxHostWebsocketSecret(candidate, now)).resolves.toBeNull();
    }

    await expect(authenticateSandboxHostWebsocketSecret("")).resolves.toBeNull();
    await expect(
      authenticateSandboxHostWebsocketSecret(
        `${PRODUCT_CREDENTIAL_PREFIXES.sdkKey}${"A".repeat(PRODUCT_CREDENTIAL_SUFFIX_LENGTH)}`,
      ),
    ).resolves.toBeNull();

    expect(db.hostToken.findUnique).not.toHaveBeenCalled();
    expect(db.hostToken.update).not.toHaveBeenCalled();
    expect(db.hostDeviceCredential.findUnique).not.toHaveBeenCalled();
    expect(db.hostDeviceCredential.update).not.toHaveBeenCalled();
  });

  it("rejects revoked, expired, unknown, and cross-purpose digests", async () => {
    const credential = generateProductCredentialSecret("hostToken");
    const lookupPrefix = credentialLookupPrefix(credential);

    db.hostToken.findUnique.mockResolvedValueOnce(null);
    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toBeNull();

    db.hostToken.findUnique.mockResolvedValueOnce({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix,
      User: ownerUser(),
      secretDigest: hmacDigestForProductPurpose({
        purpose: "deviceCredential",
        value: credential.raw,
      }),
      revokedAt: null,
      expiresAt: null,
    });
    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toBeNull();

    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix,
      User: ownerUser(),
      secretDigest: digestHostTokenSecret(credential),
      revokedAt: now,
      expiresAt: null,
    });
    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toBeNull();

    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix,
      User: ownerUser(),
      secretDigest: digestHostTokenSecret(credential),
      revokedAt: null,
      expiresAt: now,
    });
    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toBeNull();
  });

  it("verifies active wssp_device_ credentials bound to their host", async () => {
    const credential = generateProductCredentialSecret("deviceCredential");
    const lookupPrefix = credentialLookupPrefix(credential);
    db.hostDeviceCredential.findUnique.mockResolvedValue({
      id: "device-cred-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix,
      User: ownerUser(),
      secretDigest: hmacDigestForProductPurpose({
        purpose: "deviceCredential",
        value: credential.raw,
      }),
      revokedAt: null,
    });
    db.hostDeviceCredential.update.mockResolvedValue({ id: "device-cred-id" });

    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toEqual({
      hostId: "host-id",
      userId: "user-id",
      tokenId: "device-cred-id",
      credentialKind: "deviceCredential",
      expiresAt: null,
    });
    expect(db.hostToken.findUnique).not.toHaveBeenCalled();
  });

  it("rejects revoked host device credentials", async () => {
    const credential = generateProductCredentialSecret("deviceCredential");
    db.hostDeviceCredential.findUnique.mockResolvedValue({
      id: "device-cred-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix: credentialLookupPrefix(credential),
      User: ownerUser(),
      secretDigest: hmacDigestForProductPurpose({
        purpose: "deviceCredential",
        value: credential.raw,
      }),
      revokedAt: now,
    });

    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toBeNull();
    expect(db.hostDeviceCredential.update).not.toHaveBeenCalled();
  });

  it("snapshots list and auth selects so digests never appear in list DTOs", () => {
    expect(hostTokenListSelect).toMatchInlineSnapshot(`
      {
        "SandboxHost": {
          "select": {
            "deletionRequestedAt": true,
            "id": true,
            "label": true,
            "lastConnectedAt": true,
            "lastHeartbeatAt": true,
            "slug": true,
            "status": true,
          },
        },
        "createdAt": true,
        "expiresAt": true,
        "id": true,
        "lastUsedAt": true,
        "lookupPrefix": true,
        "name": true,
        "revokedAt": true,
        "sandboxHostId": true,
      }
    `);
    // C45: the device-credential list projection has the same guarantee.
    expect(hostDeviceCredentialListSelect).not.toHaveProperty("secretDigest");
    expect(Object.keys(hostDeviceCredentialListSelect).sort()).toEqual([
      "SandboxHost",
      "createdAt",
      "id",
      "lastUsedAt",
      "lookupPrefix",
      "revokedAt",
      "sandboxHostId",
    ]);
    expect(hostDeviceCredentialListSelect.SandboxHost).toEqual(hostTokenListSelect.SandboxHost);
  });
});

describe("unknown lookup prefix timing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    verifierCalls.length = 0;
  });

  it("runs the same query and the digest verifier for unknown and known-wrong prefixes", async () => {
    for (const kind of ["hostToken", "deviceCredential"] as const) {
      const lookup =
        kind === "hostToken" ? db.hostToken.findUnique : db.hostDeviceCredential.findUnique;
      const credential = generateProductCredentialSecret(kind);
      verifierCalls.length = 0;
      lookup.mockClear();
      lookup.mockResolvedValue(null);
      expect(await authenticateSandboxHostWebsocketSecret(credential.raw, now)).toBeNull();
      expect(verifierCalls).toHaveLength(1);
      expect(verifierCalls[0]?.purpose).toBe(kind);
      const unknownDigest = verifierCalls[0]?.digest;

      // The known-prefix wrong-secret path runs the same verifier once.
      verifierCalls.length = 0;
      lookup.mockResolvedValue({
        id: "row-id",
        userId: "user-id",
        sandboxHostId: "host-id",
        SandboxHost: { userId: "user-id", deletionRequestedAt: null },
        lookupPrefix: credentialLookupPrefix(credential),
        User: ownerUser(),
        secretDigest: hmacDigestForProductPurpose({ purpose: kind, value: `${credential.raw}x` }),
        expiresAt: null,
        revokedAt: null,
      });
      expect(await authenticateSandboxHostWebsocketSecret(credential.raw, now)).toBeNull();
      expect(verifierCalls).toHaveLength(1);
      expect(verifierCalls[0]?.purpose).toBe(kind);
      // Same queries before verification: one row lookup, no relation.
      expect(lookup).toHaveBeenCalledTimes(2);
      expect(lookup.mock.calls[0]).toEqual(lookup.mock.calls[1]);
      expect(lookup.mock.calls[0]?.[0]).toEqual({
        where: { lookupPrefix: credentialLookupPrefix(credential) },
        select: { id: true, secretDigest: true },
      });
      // Same digest shape, so the constant-time comparison runs in both paths.
      expect(verifierCalls[0]?.digest.length).toBe(unknownDigest?.length);
    }
  });
});

describe("host token owner ban expiry", () => {
  it.each([
    [false, null, true],
    [true, null, false],
    [true, new Date(now.getTime() + 1), false],
    [true, now, false],
    [true, new Date(now.getTime() - 1), true],
  ] as const)("banned=%s expires=%s allowed=%s", async (banned, banExpires, allowed) => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
    db.appSetting.findMany.mockResolvedValue([]);
    const credential = generateProductCredentialSecret("hostToken");
    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix: credentialLookupPrefix(credential),
      secretDigest: digestHostTokenSecret(credential),
      revokedAt: null,
      expiresAt: null,
      User: ownerUser({ banned, banExpires }),
    });
    expect((await authenticateSandboxHostWebsocketSecret(credential.raw, now)) !== null).toBe(
      allowed,
    );
    expect(db.hostToken.update).toHaveBeenCalledTimes(allowed ? 1 : 0);
  });
});

describe("host token owner enrollment policy", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
  });

  it("rejects host tokens for past-grace unenrolled owners", async () => {
    const credential = generateProductCredentialSecret("hostToken");
    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix: credentialLookupPrefix(credential),
      secretDigest: digestHostTokenSecret(credential),
      revokedAt: null,
      expiresAt: null,
      User: ownerUser({ twoFactorEnabled: false }),
    });

    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toBeNull();
    expect(db.hostToken.update).not.toHaveBeenCalled();
  });

  it("accepts host tokens for enrolled owners under forced policy", async () => {
    const credential = generateProductCredentialSecret("hostToken");
    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix: credentialLookupPrefix(credential),
      secretDigest: digestHostTokenSecret(credential),
      revokedAt: null,
      expiresAt: null,
      User: ownerUser({ twoFactorEnabled: true }),
    });
    db.hostToken.update.mockResolvedValue({ id: "token-id" });

    await expect(authenticateSandboxHostWebsocketSecret(credential.raw, now)).resolves.toEqual({
      hostId: "host-id",
      userId: "user-id",
      tokenId: "token-id",
      credentialKind: "hostToken",
      expiresAt: null,
    });
  });
});

describe("authentication revocation race", () => {
  it.each(["read-first", "revoke-first"])(
    "cannot return authority after revoke (%s)",
    async (order) => {
      const credential = generateProductCredentialSecret("hostToken");
      const row = {
        id: "token-id",
        userId: "user-id",
        sandboxHostId: "host-id",
        SandboxHost: { userId: "user-id", deletionRequestedAt: null },
        lookupPrefix: credentialLookupPrefix(credential),
        secretDigest: digestHostTokenSecret(credential),
        revokedAt: order === "revoke-first" ? now : null,
        expiresAt: null,
        User: ownerUser(),
      };
      db.hostToken.findUnique.mockResolvedValue(row);
      db.hostToken.update.mockImplementation(async () => {
        await withAuthorityChange({ credentialId: row.id }, async () => {
          row.revokedAt = now;
        });
        return { id: row.id };
      });
      expect(await authenticateSandboxHostWebsocketSecret(credential.raw, now)).toBeNull();
    },
  );
});

it("rejects a token expiring while lastUsedAt is being written", async () => {
  vi.useFakeTimers();
  try {
    vi.setSystemTime(now);
    const credential = generateProductCredentialSecret("hostToken");
    db.hostToken.findUnique.mockResolvedValue({
      id: "token-id",
      userId: "user-id",
      sandboxHostId: "host-id",
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
      lookupPrefix: credentialLookupPrefix(credential),
      secretDigest: digestHostTokenSecret(credential),
      revokedAt: null,
      expiresAt: new Date(now.getTime() + 1),
      User: ownerUser(),
    });
    db.hostToken.update.mockImplementation(async () => {
      vi.setSystemTime(new Date(now.getTime() + 2));
      return { id: "token-id" };
    });
    expect(await authenticateSandboxHostWebsocketSecret(credential.raw, now)).toBeNull();
  } finally {
    vi.useRealTimers();
  }
});

it.each(["hostToken", "deviceCredential"] as const)(
  "revalidates %s owner ban/unban, revocation and ownership",
  async (credentialKind) => {
    const lookup =
      credentialKind === "hostToken" ? db.hostToken.findUnique : db.hostDeviceCredential.findUnique;
    const row = {
      id: "credential",
      userId: "user-id",
      sandboxHostId: "host-id",
      revokedAt: null,
      ...(credentialKind === "hostToken" ? { expiresAt: null } : {}),
      User: ownerUser(),
      SandboxHost: { userId: "user-id", deletionRequestedAt: null },
    };
    const identity = {
      hostId: "host-id",
      userId: "user-id",
      tokenId: "credential",
      credentialKind,
      expiresAt: null,
    };
    lookup.mockResolvedValue(row);
    expect(await revalidateSandboxHostIdentity(identity, now)).toEqual({
      status: "active",
      hostDeletionRequested: false,
    });
    lookup.mockResolvedValue({ ...row, User: ownerUser({ banned: true }) });
    // An explicit verdict: the daemon stops its VMs on it.
    expect(await revalidateSandboxHostIdentity(identity, now)).toEqual({
      status: "inactive",
      reason: "owner_unavailable",
    });
    lookup.mockResolvedValue({
      ...row,
      User: ownerUser({ banned: true, banExpires: new Date(now.getTime() - 1) }),
    });
    expect(await revalidateSandboxHostIdentity(identity, now)).toEqual({
      status: "active",
      hostDeletionRequested: false,
    });
    lookup.mockResolvedValue({ ...row, revokedAt: now, User: ownerUser({ banned: false }) });
    expect(await revalidateSandboxHostIdentity(identity, now)).toEqual({
      status: "inactive",
      reason: "credential_revoked",
    });
    lookup.mockResolvedValue({
      ...row,
      SandboxHost: { userId: "another-owner", deletionRequestedAt: null },
    });
    expect(await revalidateSandboxHostIdentity(identity, now)).toEqual({ status: "inactive" });
    lookup.mockResolvedValue({
      ...row,
      SandboxHost: { userId: "user-id", deletionRequestedAt: now },
    });
    // A host tombstone keeps the relay credential active and reports the
    // tombstone from the same row (no second host read).
    expect(await revalidateSandboxHostIdentity(identity, now)).toEqual({
      status: "active",
      hostDeletionRequested: true,
    });
  },
);
