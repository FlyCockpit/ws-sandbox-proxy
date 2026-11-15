import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Fail closed on every changed/new reference, including computed proof claims.
// Each hash covers the COMPLETE reviewed source, not just a matching line.
const digest = (source: string) => createHash("sha256").update(source).digest("hex");
const reviewed: Record<string, string> = {
  "packages/db/src/terminal-proof.ts":
    "9ff895e70988d9ec5cf686e8bf8976c8889ee8f2510580803de7c0a46f6441bd",
  "packages/api/src/sandbox/host-terminal-tickets.ts":
    "ec42d2b5527551376ad0e4d2fc882414e1cf4ee93fddb6a3c88d8f39baa00bc3",
  "packages/auth/src/terminal-hooks.ts":
    "fd5892eec0910cf1162b1ebfb89d224e6d564fd0f321326922d3113cfa9ce42d",
  "packages/api/src/sandbox/services/sharing.ts":
    "09c5735ed08eae111eaba64e596e9f3559556f3aa1930a01a85fd1ce536024a6",
  "apps/web/src/hooks/use-admin-navigation.ts":
    "edda6b0dc1e47f7ce522201510c3d5a4e16c14de20fc3d5652b2ee94eb39235e",
  "apps/web/src/lib/route-session-access.ts":
    "59a8aa2cfccd365e00dcd1badd1ce0da290313b618a6c2d61cce4bf06513e4e2",
  "apps/web/src/server/auth-session.ts":
    "45d680463d56aa864720a380f703ad275206bed29f837501fbd88b82e65978c7",
  "apps/web/src/routes/$lang/_app/verify-email.tsx":
    "2bc11a672816e859f9e11a58321d59a7b705beac2e6ff21aa3eb53a44a39f284",
  "apps/web/src/components/admin/admin-users-page.tsx":
    "84f1c7a6909f76ae8ab6bb036a5c3e8d57ce45b6bd148f3b6777f76053ab12a8",
  "apps/worker/src/operational-alerts.ts":
    "c60c93d8c519bfb0a69f84a088a27b57799a4f7e368070a872d7673cc9497d59",
  "apps/server/src/signup-gate.ts":
    "fdefe353a9bec8bbe260b57df4f043f53a8d4decb0eda5cde2c510da068a56f9",
  "packages/db/src/admin-governance.ts":
    "8dfdfe8c74e4776dff92c9a32c4bae6e4f233b389632c5c5afe3e7666f72071e",
  "packages/auth/src/index.ts": "eba06783efc3ad681463c5e6aa37d056343b082aae886e7f8c979c37e8a03232",
  "packages/api/src/routers/users.ts":
    "99d459a0be0cda733a10c0371afdf12a52effe253e41355034587297a503d800",
  // Webhooks: isAdminAccountAuthorized reads the gate snapshot's emailVerified (read only).
  "packages/api/src/lib/sensitive-session-two-factor-gate.ts":
    "efa5f35914250f409604ad4ea80a8a4f91072b5090e2b6f94f1d4274d456c122",
  // Webhook disable notice: selects emailVerified to skip unverified addresses (read only).
  "apps/worker/src/handlers/deliver-webhook.ts":
    "2aa4705a8815f360e7fe7cdbec2f67887ba88ef0cfe8a86c80507cf739fbb48e",
  "packages/api/src/lib/owner-device-session-gate.ts":
    "a5a5b9f7bc8e50e59525635ae44b3bfd23c664f2884534a9a5437f9c5ded9976",
  "packages/api/src/lib/host-device-credential-access.ts":
    "a73bcc93cee271d54e8cb77809af7e36bbe59e7b41473f996ebdea619fe3f175",
};
function unsafeProofWriters(source: string, reviewedDigest?: string) {
  if (/emailVerified|changeEmail|socialProviders/.test(source) && digest(source) !== reviewedDigest)
    return ["unreviewed mailbox proof reference or provider configuration"];
  return [];
}

const root = resolve(import.meta.dirname, "../../..");
function productionSources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (
      ["node_modules", "generated", "dist", ".turbo", "test", "testing", "test-utils"].includes(
        entry.name,
      )
    )
      return [];
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return productionSources(path);
    return /\.(?:ts|tsx)$/.test(entry.name) && !/\.(?:test|spec)\.|routeTree\.gen/.test(entry.name)
      ? [path]
      : [];
  });
}

describe("verified mailbox writer inventory", () => {
  it("production code has only reads/projections; Better Auth owns mailbox proof", () => {
    const failures = ["apps", "packages", "scripts"]
      .flatMap((dir) => productionSources(join(root, dir)))
      .flatMap((path) =>
        unsafeProofWriters(readFileSync(path, "utf8"), reviewed[relative(root, path)]).map(
          (finding) => `${relative(root, path)}: ${finding}`,
        ),
      );
    expect(failures).toEqual([]);
  });
  it.each([
    "adapter.updateUser(id, { emailVerified: true })",
    "prisma.user.update({ data: { emailVerified: true } })",
    "prisma.user.create({ data: { emailVerified: claims.verified } })",
    "user.emailVerified = true",
    'user["emailVerified"] = true',
    "const config = { socialProviders: { google: {} } }",
    "const config = { user: { changeEmail: { enabled: true } } }",
  ])("rejects injected unsafe writer/provider: %s", (source) =>
    expect(unsafeProofWriters(source)).not.toEqual([]),
  );
  it("distinguishes projections, filters and copies from proof", () => {
    const source =
      "const USER_SELECT = { emailVerified: true }; const recipientWhere = { emailVerified: true }; const view = { emailVerified: user.emailVerified };";
    expect(unsafeProofWriters(source, digest(source))).toEqual([]);
    expect(
      unsafeProofWriters(
        `${source} adapter.updateUser(id, { emailVerified: true })`,
        digest(source),
      ),
    ).not.toEqual([]);
  });
  it("keeps mailbox verification required and has no caller/admin proof input", () => {
    const config = readFileSync(join(root, "packages/auth/src/index.ts"), "utf8");
    expect(config).toMatch(/requireEmailVerification:\s*true/);
    expect(config).not.toMatch(/sendVerificationEmail:\s*false/);
  });
});
// Real HTTP/direct mailbox-proof and scoped-invite adapter coverage: signup-policy.pg.test.ts.
