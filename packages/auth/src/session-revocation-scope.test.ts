import { beforeEach, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: { session: { findMany: vi.fn() } } }));

const { default: prisma } = await import("@wssp/db");
const { onAuthSessionsRevoked } = await import("@wssp/db/session-revocation");
const { notifySessionOwners, REVOKED_SESSION_OWNERS_MAX, sessionOwnersFor } = await import(
  "./session-revocation-scope"
);
const findMany = vi.mocked(prisma.session.findMany);

beforeEach(() => {
  findMany.mockReset();
});

it("a userId-scoped delete (string or the adapter's { equals }) needs no read", async () => {
  expect(await sessionOwnersFor({ userId: "u1" })).toEqual(["u1"]);
  expect(await sessionOwnersFor({ userId: { equals: "u2" } })).toEqual(["u2"]);
  expect(findMany).not.toHaveBeenCalled();
});

it("a token-scoped delete (sign-out) reads the matched rows' owners BEFORE the delete", async () => {
  findMany.mockResolvedValue([{ userId: "u3" }] as never);
  const where = { token: { equals: "tok" } };
  expect(await sessionOwnersFor(where)).toEqual(["u3"]);
  expect(findMany).toHaveBeenCalledWith({
    where,
    select: { userId: true },
    distinct: ["userId"],
    take: REVOKED_SESSION_OWNERS_MAX + 1,
  });
});

it("no matched rows → nobody is notified", async () => {
  findMany.mockResolvedValue([] as never);
  expect(await sessionOwnersFor({ token: { equals: "gone" } })).toEqual([]);
});

it("owners are unknown (null → broad) for an unscoped delete, too many owners, or a failed read", async () => {
  expect(await sessionOwnersFor(undefined)).toBeNull();
  expect(await sessionOwnersFor({})).toBeNull();
  findMany.mockResolvedValue(
    Array.from({ length: REVOKED_SESSION_OWNERS_MAX + 1 }, (_, i) => ({
      userId: `u${i}`,
    })) as never,
  );
  expect(await sessionOwnersFor({ expiresAt: { lt: new Date() } })).toBeNull();
  findMany.mockRejectedValue(new Error("db down"));
  expect(await sessionOwnersFor({ token: { equals: "tok" } })).toBeNull();
});

it("notifies each resolved owner, or once unscoped when unknown", async () => {
  const seen: unknown[] = [];
  const off = onAuthSessionsRevoked((revocation) => seen.push(revocation));
  notifySessionOwners(["a", "b"]);
  notifySessionOwners([]);
  notifySessionOwners(null);
  await Promise.resolve();
  off();
  expect(seen).toEqual([{ userId: "a" }, { userId: "b" }, {}]);
});

it("bounded token/id deletes retain session-specific hints; owner-wide delete remains owner-scoped", async () => {
  const { sessionRevocationsFor, notifySessionRevocations } = await import(
    "./session-revocation-scope"
  );
  findMany.mockResolvedValue([{ id: "session-a", userId: "a" }] as never);
  const scopes = await sessionRevocationsFor({ token: { equals: "fixture-token" } });
  expect(scopes).toEqual([{ userId: "a", sessionId: "session-a" }]);
  expect(await sessionRevocationsFor({ userId: "a" })).toEqual([{ userId: "a" }]);
  const seen: unknown[] = [],
    off = onAuthSessionsRevoked((scope) => seen.push(scope));
  notifySessionRevocations(scopes);
  await new Promise<void>((resolve) => queueMicrotask(resolve));
  expect(seen).toEqual(scopes);
  off();
  findMany.mockRejectedValueOnce(new Error("offline"));
  expect(await sessionRevocationsFor({ id: "session-a" })).toEqual([{}]);
});
