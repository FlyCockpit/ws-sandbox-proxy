import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

// Fail closed on every changed/new reference, including computed proof claims.
// Each hash covers the COMPLETE reviewed source, not just a matching line.
const digest = (source: string) => createHash("sha256").update(source).digest("hex");
const reviewed: Record<string, string> = {
  "packages/db/src/terminal-proof.ts":
    "237f60137936aeaabd690be1365540e1f6e609f68240e6665bd29d733fc5f71e",
  "packages/api/src/sandbox/host-terminal-tickets.ts":
    "ec42d2b5527551376ad0e4d2fc882414e1cf4ee93fddb6a3c88d8f39baa00bc3",
  "packages/auth/src/terminal-hooks.ts":
    "fd5892eec0910cf1162b1ebfb89d224e6d564fd0f321326922d3113cfa9ce42d",
  // Pool invitations: acceptance and its preview require (read) a verified email.
  "packages/api/src/sandbox/services/sharing.ts":
    "2277349e144318dcdea25c423a065ae99bae1cfc9076ef77bcb6020607418d62",
  "apps/web/src/hooks/use-admin-navigation.ts":
    "edda6b0dc1e47f7ce522201510c3d5a4e16c14de20fc3d5652b2ee94eb39235e",
  // Reviewed 11-26 (home-nav): decideRootLanding removed; the emailVerified reads are unchanged, read only.
  "apps/web/src/lib/route-session-access.ts":
    "052afb3730c95ca4bee2ea7baea3a5f1ca35dd5aa712595c755452ed8e21cc7f",
  // Reviewed 11-26 (home-nav): root landing probe replaced by a session-cookie presence hint
  // (no session read); the session projection's emailVerified copy is unchanged, read only.
  "apps/web/src/server/auth-session.ts":
    "bfe724c746d71d6d9d40b1b36abff28b5711cfb8a98d7ffa3a2df1af6d2bec20",
  // Reviewed 11-26 (wssp-fix phase B): pending-state staticData added; the emailVerified reads are unchanged, read only.
  // Reviewed 11-26 (home-nav): the continue link targets APP_HOME; comment-only emailVerified mention unchanged.
  "apps/web/src/routes/$lang/_app/verify-email.tsx":
    "93b8e611eac6f763eacc2f601f9f2fd6d52c586fda2e4f05628d316c32b7d5e3",
  // Reviewed 11-26 (wssp-fix): the unverified pill reads `user.emailVerified` only.
  // Reviewed 11-26 (viewport-pass): row/badge class names only; the emailVerified read is unchanged, read only.
  "apps/web/src/components/admin/admin-users-page.tsx":
    "91745acc4b5d6cea92e2f5cbf86ce24bb1e85ba3281fbada3d26e2e407d4d4cf",
  "apps/worker/src/operational-alerts.ts":
    "c60c93d8c519bfb0a69f84a088a27b57799a4f7e368070a872d7673cc9497d59",
  // Reviewed 11-24: comment only (sign-up answers are address-independent).
  "apps/server/src/signup-gate.ts":
    "c985a44c9f84b407f19dd33a1d6c5a09c6b69eaaadf7422c9d534d88cf82fb79",
  "packages/db/src/admin-governance.ts":
    "8dfdfe8c74e4776dff92c9a32c4bae6e4f233b389632c5c5afe3e7666f72071e",
  // Reviewed 11-23: adds the temporary-password guard to hooks.before/after and
  // revokeSessionsOnPasswordReset; no mailbox proof input or write.
  // Reviewed 11-24: adds the neutral sign-up after-hook and a user.create.after
  // mark (signup-response.ts); no mailbox proof input or write.
  "packages/auth/src/index.ts": "ab7c0b4273f8f739994adee9bcfac3b2b8546d390ba03fcfbc976417f040d226",
  // Invites: no proof write. The mailed accept link is Better Auth's own
  // verify-email link (admin-invite-verification.ts mints its signed token, as
  // its sendVerificationEmail does); Better Auth's endpoint writes the proof.
  // The new row is created with mustChangePassword, not emailVerified.
  "packages/api/src/routers/users.ts":
    "6a6c6a8e4fbd9cf302b0e49309778986acf2f12c31be7dbceb99d723d28cc7fa",
  // App shell: reads the session's emailVerified to show admins their 2FA deadline (read only).
  // Reviewed 11-26 (wssp-fix): pending/error frames added; the emailVerified read is unchanged.
  // Reviewed 11-26 (wssp-fix phase B): pendingFrame staticData and the route content skeleton; the emailVerified read is unchanged, read only.
  // Reviewed 11-26 (home-nav): the gate writes the public session hint; the emailVerified read is unchanged, read only.
  "apps/web/src/routes/$lang/_app/_auth.tsx":
    "9cab3b6722b07f36b940a3292366a30cd862700adafe67a46d98e12104ffc09d",
  // Webhooks: isAdminAccountAuthorized reads the gate snapshot's emailVerified (read only).
  "packages/api/src/lib/sensitive-session-two-factor-gate.ts":
    "6a51bb5c7a528ca30fda6700413196bda144bbfc9f6f58d77e878250c192cbcf",
  // Webhook disable notice: selects emailVerified to skip unverified addresses (read only).
  "apps/worker/src/handlers/deliver-webhook.ts":
    "2aa4705a8815f360e7fe7cdbec2f67887ba88ef0cfe8a86c80507cf739fbb48e",
  "packages/api/src/lib/owner-device-session-gate.ts":
    "4bdd48a03e1b376842e83130e15f763b583eac0dc5b5e911d4c334797c4d26e4",
  "packages/api/src/lib/host-device-credential-access.ts":
    "7287f6e4b29bd4d638f783cd86b4a1aac08749cb662caf2224fa175b2221c871",
  // `wssp login` mint: reads the owner's emailVerified for the credential policy (read only).
  "packages/api/src/lib/user-login-credential-access.ts":
    "c31f23df0cdfa739d5e27306c9b79ab7e26d664386ccf6e4c52f3084564aa086",
  // SETUP_KEY first-admin claim: the one non-Better-Auth writer. It creates the
  // first administrator with emailVerified=true on the word of the SETUP_KEY
  // holder (the operator typed the address into deploy:generate-admin), only
  // while no administrator exists, and never for an existing account.
  "packages/api/src/lib/admin-bootstrap.ts":
    "d107cf7c8ae4aba6990fae7d4156e42601ef1cef79415e3911e1b096b42ec063",
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
