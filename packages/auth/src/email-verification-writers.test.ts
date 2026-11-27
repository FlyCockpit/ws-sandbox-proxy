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
  // Reviewed 11-26 (e2e5-fups): listPoolShares counts contributed hosts and the pool host-policy read; the emailVerified reads are unchanged, read only.
  "packages/api/src/sandbox/services/sharing.ts":
    "ec4631603e5809d0f276f75bb30f0c937fa7553cf0b2ac4c1ee095794ec4d5df",
  "apps/web/src/hooks/use-admin-navigation.ts":
    "edda6b0dc1e47f7ce522201510c3d5a4e16c14de20fc3d5652b2ee94eb39235e",
  // Reviewed 11-26 (home-nav): decideRootLanding removed; the emailVerified reads are unchanged, read only.
  "apps/web/src/lib/route-session-access.ts":
    "052afb3730c95ca4bee2ea7baea3a5f1ca35dd5aa712595c755452ed8e21cc7f",
  // Reviewed 11-26 (home-nav): root landing probe replaced by a session-cookie presence hint
  // (no session read); the session projection's emailVerified copy is unchanged, read only.
  // Reviewed 11-26 (identity-cache): a JSDoc points to resolveRouteSession; emailVerified copy unchanged, read only.
  "apps/web/src/server/auth-session.ts":
    "78630ae45d0d2c05b2d9c169be7cabc11c6eb4690bdbb4d6e6380c726be0ea40",
  // Reviewed 11-26 (wssp-fix phase B): pending-state staticData added; the emailVerified reads are unchanged, read only.
  // Reviewed 11-26 (home-nav): the continue link targets APP_HOME; comment-only emailVerified mention unchanged.
  // Reviewed 11-27 (tpl-polish-final): gated pending/invalid descriptions without resend; comment-only emailVerified mention unchanged.
  "apps/web/src/routes/$lang/_app/verify-email.tsx":
    "66d0271366b99f489af54e88a7c565840ca5643c1edb028c72e831abf85a598e",
  // Reviewed 11-26 (wssp-fix): the unverified pill reads `user.emailVerified` only.
  // Reviewed 11-26 (viewport-pass): row/badge class names only; the emailVerified read is unchanged, read only.
  // Reviewed 11-26 (tpl-e2e5-fups lane C): invite "Email language" select and the archive Undo toast; the emailVerified read is unchanged, read only.
  // Reviewed 11-26 (e2e5-fups): the invite's temporary password uses the masked secret panel; the emailVerified read is unchanged, read only.
  "apps/web/src/components/admin/admin-users-page.tsx":
    "355c2c0081fcf0c6c3d64b6bdd9d3789a782158ba1db6317c2a2eebb538a275b",
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
  // Password pepper supplies hash and verify callbacks; mailbox proof is unchanged.
  // Reviewed 11-27 (e2e5-fups T1): password length limits read from ./password-policy.ts (12 / 128, unchanged); no mailbox proof input or write.
  // Reviewed 11-27 (tpl-e2e5-fups r2): wires mailbox-proof-policy.ts as user.create.before
  // (first) and user.update.before; refusals only, no proof input or write.
  // Password recovery revokes standing credentials before and after reset; no mailbox proof input or write.
  // Round 3: durable session write checks and reset-link/temporary-password finalization; no mailbox proof input or write.
  // Reset-race: session/write fences and all-session post-sweep; mailbox proof unchanged.
  // Activation port: selective reset adapter preserves proof policy and defers session signals until commit.
  // Reviewed 11-27 (precut-signin-race): cookie cache disabled; mailbox proof configuration and writers unchanged.
  "packages/auth/src/index.ts": "c9e5fc539ccb023d04b1d29dc15257907a33731cd962b3eb3221ec423483c092",
  // Refusals only: no Better Auth create with emailVerified=true, no update carrying email,
  // no emailVerified write outside /verify-email. Writes nothing.
  // Activation: only mediates BA verify-email proof writes under PW -> owner,
  // with atomic reset-token deletion. Reset never writes mailbox proof.
  "packages/auth/src/password-reset-adapter.ts":
    "3bc14d2c6deedba44f19677aad5f5a36dfedfa805e0b2e623f592dfb39bea377",
  "packages/auth/src/mailbox-proof-policy.ts":
    "b0f9738a039840e2abe1b026b768df4cc4d1d54dbaa3df7dd4d55875e9402c25",
  // Invites: no proof write. The mailed accept link is Better Auth's own
  // verify-email link (admin-invite-verification.ts mints its signed token, as
  // its sendVerificationEmail does); Better Auth's endpoint writes the proof.
  // The new row is created with mustChangePassword, not emailVerified.
  // Reviewed 11-26 (tpl-e2e5-fups lane C): the invite input takes the invitee's locale, written in the same insert, plus the mail's expiry days; still no proof write.
  // Reset-race: only invite budget key/ceiling changed (30/hour); proof handling unchanged.
  "packages/api/src/routers/users.ts":
    "c2c0c72ba73d3e715106e8974c5bd791193d378eacaba3795d42721bba066b19",
  // App shell: reads the session's emailVerified to show admins their 2FA deadline (read only).
  // Reviewed 11-26 (wssp-fix): pending/error frames added; the emailVerified read is unchanged.
  // Reviewed 11-26 (wssp-fix phase B): pendingFrame staticData and the route content skeleton; the emailVerified read is unchanged, read only.
  // Reviewed 11-26 (home-nav): the gate writes the public session hint; the emailVerified read is unchanged, read only.
  // Reviewed 11-26 (identity-cache): the gate probes through resolveProtectedRouteSession; the emailVerified read is unchanged, read only.
  "apps/web/src/routes/$lang/_app/_auth.tsx":
    "1e1610631d0f0fafef95705f5a297437d46029576cb7eaee9b721d3a7001c5a0",
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
