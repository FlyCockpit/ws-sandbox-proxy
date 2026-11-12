import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("../lib/sdk-key-access", () => ({ revalidateSdkKey: vi.fn() }));
vi.mock("../template-builds/principal", () => ({ loadBuildPrincipal: vi.fn() }));

const { revalidateSdkKey } = await import("../lib/sdk-key-access");
const { loadBuildPrincipal } = await import("../template-builds/principal");
const loadBuild = vi.mocked(loadBuildPrincipal);
const { resolveStoredPrincipal, storedAttributionOf } = await import("./stored-principal");

const revalidate = vi.mocked(revalidateSdkKey);
const tx = { marker: "tx" } as never;
const key = { kind: "sdkKey", keyId: "key-1", ownerId: "user-1" } as never;

describe("storedAttributionOf", () => {
  it.each([
    [
      "recorded key",
      { userId: "user-1", authorizingKeyId: "key-1", sandboxBuildId: null },
      { kind: "sdkKey", keyId: "key-1" },
    ],
    [
      "no key",
      { userId: "user-1", authorizingKeyId: null, sandboxBuildId: null },
      { kind: "session" },
    ],
    // Same truthiness as the readers it replaced: an empty key id is no key.
    [
      "empty key id",
      { userId: "user-1", authorizingKeyId: "", sandboxBuildId: null },
      { kind: "session" },
    ],
  ])("%s", (_name, work, expected) => {
    expect(storedAttributionOf(work)).toEqual(expected);
  });

  it("never infers system attribution", () => {
    for (const authorizingKeyId of ["key-1", null, ""])
      expect(
        storedAttributionOf({ userId: "user-1", authorizingKeyId, sandboxBuildId: null }).kind,
      ).not.toBe("system");
  });
});

describe("resolveStoredPrincipal", () => {
  beforeEach(() => revalidate.mockReset());

  it("revalidates a recorded key on the caller's client", async () => {
    revalidate.mockResolvedValue(key);
    await expect(
      resolveStoredPrincipal(tx, {
        userId: "user-1",
        authorizingKeyId: "key-1",
        sandboxBuildId: null,
      }),
    ).resolves.toBe(key);
    expect(revalidate).toHaveBeenCalledWith("key-1", "user-1", tx);
  });

  it("returns null once the recorded key is inactive", async () => {
    revalidate.mockResolvedValue(null);
    await expect(
      resolveStoredPrincipal(tx, {
        userId: "user-1",
        authorizingKeyId: "key-1",
        sandboxBuildId: null,
      }),
    ).resolves.toBeNull();
  });

  it("resolves keyless work to the owner's session principal without a key read", async () => {
    await expect(
      resolveStoredPrincipal(tx, {
        userId: "user-1",
        authorizingKeyId: null,
        sandboxBuildId: null,
      }),
    ).resolves.toEqual({ kind: "session", ownerId: "user-1" });
    expect(revalidate).not.toHaveBeenCalled();
  });
});

describe("build work (the build fact is checked first)", () => {
  beforeEach(() => {
    revalidate.mockReset();
    loadBuild.mockReset();
  });

  it.each([
    ["build with key", "key-1", { kind: "build", buildId: "b-1", keyId: "key-1" }],
    ["build without key", null, { kind: "build", buildId: "b-1", keyId: null }],
  ] as const)("attributes %s from Sandbox.buildId, not the key", (_name, key, expected) => {
    expect(
      storedAttributionOf({ userId: "user-1", authorizingKeyId: key, sandboxBuildId: "b-1" }),
    ).toEqual(expected);
  });

  it("never infers system attribution from any row shape", () => {
    for (const sandboxBuildId of ["b-1", null])
      for (const authorizingKeyId of ["key-1", null, ""])
        expect(
          storedAttributionOf({ userId: "user-1", authorizingKeyId, sandboxBuildId }).kind,
        ).not.toBe("system");
  });

  it.each(["key-1", null])(
    "resolves build work (key %s) to the owner's build principal, never its key or session",
    async (authorizingKeyId) => {
      const build = { kind: "build", buildId: "b-1", keyId: authorizingKeyId, ownerId: "user-1" };
      loadBuild.mockResolvedValue(build as never);
      await expect(
        resolveStoredPrincipal(tx, { userId: "user-1", authorizingKeyId, sandboxBuildId: "b-1" }),
      ).resolves.toBe(build);
      expect(loadBuild).toHaveBeenCalledWith(tx, "b-1", "user-1");
      expect(revalidate).not.toHaveBeenCalled();
    },
  );

  it("fails closed when the build is gone or its key disagrees with the work's", async () => {
    loadBuild.mockResolvedValue(null);
    await expect(
      resolveStoredPrincipal(tx, {
        userId: "user-1",
        authorizingKeyId: null,
        sandboxBuildId: "b-1",
      }),
    ).resolves.toBeNull();
    loadBuild.mockResolvedValue({ kind: "build", buildId: "b-1", keyId: "key-2" } as never);
    await expect(
      resolveStoredPrincipal(tx, {
        userId: "user-1",
        authorizingKeyId: "key-1",
        sandboxBuildId: "b-1",
      }),
    ).resolves.toBeNull();
    expect(revalidate).not.toHaveBeenCalled();
  });
});

describe("community verify-VM work (community-base I4c)", () => {
  it("attributes verify-VM work to its build", () => {
    expect(
      storedAttributionOf({
        userId: "user-1",
        authorizingKeyId: null,
        sandboxBuildId: null,
        sandboxVerifyBuildId: "b-1",
      }),
    ).toEqual({ kind: "build", buildId: "b-1", keyId: null });
  });

  it("resolves verify-VM work to the build principal", async () => {
    revalidate.mockReset();
    loadBuild.mockReset();
    const build = { kind: "build", buildId: "b-1", keyId: "key-1", ownerId: "user-1" };
    loadBuild.mockResolvedValue(build as never);
    await expect(
      resolveStoredPrincipal(tx, {
        userId: "user-1",
        authorizingKeyId: "key-1",
        sandboxBuildId: null,
        sandboxVerifyBuildId: "b-1",
      }),
    ).resolves.toBe(build);
    expect(revalidate).not.toHaveBeenCalled();
  });
});
