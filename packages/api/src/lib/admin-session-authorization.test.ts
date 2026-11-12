import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: {} }));

const { default: prisma } = await import("@wssp/db");
const { defaultSensitiveSessionGateUser } = await import("@wssp/api/test/mock-prisma");
const { isAdminAccountAuthorized, isAdminSessionAuthorized } = await import(
  "./sensitive-session-two-factor-gate"
);
const { invalidateForceTwoFactorSettingsCache } = await import("./two-factor-policy");

const db = prisma as unknown as {
  appSetting: { findMany: MockInstance };
  user: { findUnique: MockInstance };
  session: { findUnique: MockInstance };
};

const REPO = resolve(import.meta.dirname, "../../../..");
const session = { user: { id: "admin-1" }, session: { id: "session-1" } };
const DAY = 24 * 60 * 60 * 1000;

function userRow(overrides: Record<string, unknown> = {}) {
  return { ...defaultSensitiveSessionGateUser, ...overrides };
}

describe("isAdminSessionAuthorized", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
    db.appSetting.findMany.mockResolvedValue([]);
    db.session.findUnique.mockResolvedValue({ id: "session-1" });
    db.user.findUnique.mockResolvedValue(userRow());
  });

  // One matrix for every surface that consumes the gate (oRPC entry/return,
  // admin write transaction, Hono API reference, web /admin route guard).
  it.each([
    ["an enrolled, verified administrator", {}, true],
    [
      "a brand-new administrator inside the 2FA enrollment grace window",
      { twoFactorEnabled: false, createdAt: new Date(Date.now() - 60_000) },
      true,
    ],
    [
      "an administrator past the grace window without 2FA",
      { twoFactorEnabled: false, createdAt: new Date(Date.now() - 2 * DAY) },
      false,
    ],
    ["an unverified administrator", { emailVerified: false }, false],
    ["a non-admin user", { role: "user" }, false],
    ["a banned administrator", { banned: true }, false],
    ["an administrator whose account is being deleted", { deletionRequestedAt: new Date() }, false],
  ] as const)("decides %s", async (_label, overrides, expected) => {
    db.user.findUnique.mockResolvedValue(userRow(overrides));
    expect(await isAdminSessionAuthorized(session)).toBe(expected);
  });

  it("rejects missing, revoked, expired or impersonated sessions before reading the user", async () => {
    expect(await isAdminSessionAuthorized(null)).toBe(false);
    expect(await isAdminSessionAuthorized(undefined)).toBe(false);
    expect(await isAdminSessionAuthorized({ user: { id: "admin-1" }, session: { id: "" } })).toBe(
      false,
    );
    db.session.findUnique.mockResolvedValue(null);
    expect(await isAdminSessionAuthorized(session)).toBe(false);
    expect(db.user.findUnique).not.toHaveBeenCalled();
    expect(db.session.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: "session-1",
          userId: "admin-1",
          impersonatedBy: null,
          expiresAt: { gt: expect.any(Date) },
        }),
      }),
    );
  });

  it("honors an explicit administrator 2FA opt-out stored in settings", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "false" }]);
    db.user.findUnique.mockResolvedValue(
      userRow({ twoFactorEnabled: false, createdAt: new Date(Date.now() - 30 * DAY) }),
    );
    expect(await isAdminSessionAuthorized(session)).toBe(true);
  });
});

describe("isAdminAccountAuthorized (no session: webhook private allowlist)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    invalidateForceTwoFactorSettingsCache();
    db.appSetting.findMany.mockResolvedValue([]);
  });

  it.each([
    ["an enrolled, verified administrator", {}, true],
    ["a demoted administrator", { role: "user" }, false],
    ["an unverified administrator", { emailVerified: false }, false],
    ["a banned administrator", { banned: true }, false],
    ["an administrator whose account is being deleted", { deletionRequestedAt: new Date() }, false],
    [
      "an administrator past the grace window without 2FA",
      { twoFactorEnabled: false, createdAt: new Date(Date.now() - 2 * DAY) },
      false,
    ],
  ] as const)("decides %s without reading any session", async (_label, overrides, expected) => {
    db.user.findUnique.mockResolvedValue(userRow(overrides));
    expect(await isAdminAccountAuthorized("admin-1")).toBe(expected);
    expect(db.session.findUnique).not.toHaveBeenCalled();
  });
});

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === "generated") continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...sourceFiles(path));
    else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(path);
  }
  return out;
}

describe("administrator gate inventory", () => {
  const roots = ["apps/server/src", "apps/web/src", "apps/worker/src", "packages"].map((dir) =>
    resolve(REPO, dir),
  );
  const files = roots.flatMap(sourceFiles).map((path) => ({
    path: relative(REPO, path).replaceAll("\\", "/"),
    text: readFileSync(path, "utf8"),
  }));
  const GATE_MODULE = "packages/api/src/lib/sensitive-session-two-factor-gate.ts";

  it("keeps the two gate primitives private to the gate module", () => {
    const offenders = files
      .filter((file) => file.path !== GATE_MODULE)
      .filter((file) =>
        /\b(isAdminSessionActive|loadAdminSessionGateSnapshot)\s*\(/.test(file.text),
      )
      .map((file) => file.path);
    expect(offenders).toEqual([]);
  });

  it("routes every administrator-visibility decision through isAdminSessionAuthorized", () => {
    const consumers = files
      .filter((file) => file.path !== GATE_MODULE)
      .filter((file) => /\bisAdminSessionAuthorized\s*\(/.test(file.text))
      .map((file) => file.path)
      .sort();
    expect(consumers).toEqual([
      "apps/server/src/admin-session-gate.ts",
      "apps/web/src/server/admin-route-access.ts",
      "packages/api/src/index.ts",
    ]);
    const index = files.find((file) => file.path === "packages/api/src/index.ts")?.text ?? "";
    // Entry and return of `requireAdminOr404`, plus the admin write transaction.
    expect(index.match(/\bisAdminSessionAuthorized\s*\(/g)).toHaveLength(3);
  });

  it("routes every account-level admin decision through isAdminAccountAuthorized", () => {
    const consumers = files
      .filter((file) => file.path !== GATE_MODULE)
      .filter((file) => /\bisAdminAccountAuthorized\s*\(/.test(file.text))
      .map((file) => file.path)
      .sort();
    // Create/update (both planes) and every delivery claim (worker).
    expect(consumers).toEqual([
      "packages/api/src/webhooks/ledger.ts",
      "packages/api/src/webhooks/service.ts",
    ]);
  });
});
