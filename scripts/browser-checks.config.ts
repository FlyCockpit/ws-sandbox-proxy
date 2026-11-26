/**
 * wssp's own settings for `pnpm check:dialogs` and `pnpm check:shell-loading`:
 * how to sign in, every dialog to open, and the signed-in pages to
 * hard-reload. The check scripts and `browser-check-lib.ts` stay identical to
 * the template's; only this file changes per app.
 * Usage: docs/design/shell-rules.md § Dialog fit and shell loading checks
 *
 * wssp has no mock mode: the checks run against a running stack (seeded with
 * an admin account) and sign in through the real login form, second factor
 * included. Nothing machine-specific or secret is committed here:
 *
 *   WSSP_CHECK_URL          the web origin (else pass `--url`)
 *   WSSP_CHECK_CREDS_FILE   a KEY=value file read at run time, with
 *                           ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_TOTP_SECRET
 *                           (and USER_* for the `user` role); the TOTP secret
 *                           may be absent for an account without 2FA
 */
import { createHmac } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { CheckRun } from "./browser-check-lib.ts";

/** No mock dev server: the checks need `--url` (or `WSSP_CHECK_URL`). */
export const MOCK_SERVER = false;

// The check scripts read `--url` from argv; the env var fills it in.
if (!process.argv.includes("--url") && process.env.WSSP_CHECK_URL)
  process.argv.push("--url", process.env.WSSP_CHECK_URL);

export type Role = "anonymous" | "user" | "admin";

export interface SignInOptions {
  /** Mock-mode scenarios; a real stack has none (ignored). */
  overrides?: Record<string, string>;
  /** Mock mode only (ignored): the check throttles the network itself. */
  slow?: boolean;
}

/** Parses a KEY=value file (comments and blank lines ignored). */
export function parseCredentials(text: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*([A-Z0-9_]+)\s*=(.*)$/.exec(line);
    if (match?.[1]) values[match[1]] = (match[2] ?? "").trim();
  }
  return values;
}

/** RFC 6238 TOTP (SHA-1, 30 s, 6 digits) for a base32 secret at `window`. */
export function totpCode(secret: string, window: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of secret.replace(/[\s=]/g, "").toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("TOTP secret is not base32");
    bits += index.toString(2).padStart(5, "0");
  }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((byte) => Number.parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(window));
  const hmac = createHmac("sha1", key).update(counter).digest();
  const offset = (hmac[hmac.length - 1] ?? 0) & 15;
  const value = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(value).padStart(6, "0");
}

function credentialsFor(role: Exclude<Role, "anonymous">) {
  const file = process.env.WSSP_CHECK_CREDS_FILE;
  if (!file) throw new Error("set WSSP_CHECK_CREDS_FILE to the seeded accounts' KEY=value file");
  const values = parseCredentials(readFileSync(file, "utf8"));
  const prefix = role === "admin" ? "ADMIN" : "USER";
  const email = values[`${prefix}_EMAIL`];
  const password = values[`${prefix}_PASSWORD`];
  if (!email || !password) throw new Error(`${file} has no ${prefix}_EMAIL / ${prefix}_PASSWORD`);
  return { file, email, password, totpSecret: values[`${prefix}_TOTP_SECRET`] };
}

/**
 * A code from a 30 s window no earlier run used (the server refuses a replay):
 * the last window per account is kept next to the credentials file, which is
 * the convention other tools on the same stack follow.
 */
async function freshTotp(credsFile: string, role: string, secret: string): Promise<string> {
  const dir = join(dirname(credsFile), ".totp");
  const marker = join(dir, `${role}.last`);
  mkdirSync(dir, { recursive: true });
  let last = 0;
  try {
    last = Number(readFileSync(marker, "utf8").trim()) || 0;
  } catch {
    // First use.
  }
  for (;;) {
    const now = Date.now() / 1000;
    const window = Math.floor(now / 30);
    // Leave a few seconds of the window to submit in.
    if (window > last && now % 30 <= 24) {
      writeFileSync(marker, String(window));
      return totpCode(secret, window);
    }
    await new Promise((done) => setTimeout(done, 1000));
  }
}

async function waitFor(run: CheckRun, condition: string, what: string): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    if ((await run.browser.run(["eval", condition])).endsWith("true")) return;
    await new Promise((done) => setTimeout(done, 1000));
  }
  throw new Error(`sign-in: timed out waiting for ${what}`);
}

/** The role this browser session is signed in as (sign-in is rate limited and 2FA'd). */
let signedInAs: Role | null = null;

/**
 * Leaves the browser signed in as `role`, through the real login form and
 * the second-factor step. Secrets reach agent-browser on stdin, never argv.
 * Signs in once per role and run.
 */
export async function signIn(run: CheckRun, role: Role, _options: SignInOptions = {}) {
  if (signedInAs === role) return;
  const { base, browser } = run;
  await browser.run(["cookies", "clear"]);
  signedInAs = null;
  if (role === "anonymous") {
    signedInAs = role;
    return;
  }
  const account = credentialsFor(role);
  await browser.run(["open", `${base}/en-US/login`]);
  await waitFor(run, '!!document.querySelector("main input[type=email]")', "the login form");
  await browser.run(
    ["batch", "--bail"],
    JSON.stringify([
      ["fill", 'main input[type="email"]', account.email],
      ["fill", 'main input[type="password"]', account.password],
      ["click", 'main form button[type="submit"]'],
    ]),
  );
  await waitFor(
    run,
    '!!document.querySelector("#totp-code") || /\\/dashboard/.test(location.pathname)',
    "the second-factor step",
  );
  if ((await browser.run(["eval", '!!document.querySelector("#totp-code")'])).endsWith("true")) {
    if (!account.totpSecret) throw new Error(`sign-in: ${role} needs a TOTP secret`);
    const code = await freshTotp(account.file, role, account.totpSecret);
    await browser.run(["batch", "--bail"], JSON.stringify([["fill", "#totp-code", code]]));
    await browser.run([
      "eval",
      '(() => { const b = document.querySelector("#totp-code").form?.querySelector("button[type=submit]"); b?.click(); return !!b; })()',
    ]);
  }
  await waitFor(run, "/\\/dashboard/.test(location.pathname)", "the signed-in dashboard");
  signedInAs = role;
}

export type DialogStep =
  /** Click the first element matching a CSS selector. */
  | { click: string }
  /** Click the button, link or menu item whose trimmed text is exactly this. */
  | { clickText: string };

export interface DialogCase {
  /** Unique; shown in failures and used by `--only`. */
  name: string;
  /** Path with the locale, opened after signing in as `role`. */
  path: string;
  role: Role;
  overrides?: Record<string, string>;
  /** Wait for this selector before the steps. */
  ready: string;
  /** Steps that open the dialog. */
  steps: DialogStep[];
}

/** The seeded running sandbox's row link (its id differs per stack). */
const OPEN_RUNNING_SANDBOX = {
  click: 'li[data-sandbox-state="READY"] a[aria-label^="Open sandbox "]',
};
/** The sandbox detail page's "Sandbox actions" menu. */
const SANDBOX_MENU = { click: '[data-page-actions] button[aria-label="Sandbox actions"]' };
const RUNNING_SANDBOX_READY = 'li[data-sandbox-state="READY"] a[aria-label^="Open sandbox "]';

/**
 * Every dialog wssp ships that the seeded admin can open, confirmations
 * included. A dialog that cannot fit moves to a page or a wide side sheet and
 * leaves this list; there is no exemption field. Long forms already live on
 * pages (`/dashboard/sandboxes/new`, `/dashboard/templates/new/*`,
 * `/settings/hosts/add`, `/settings/webhooks/new`) or wide sheets.
 *
 * Not listed: Forget host. It is offered only for an offline or stale host
 * (on its detail page), the seeded hosts are Connected, and the check has no
 * way to skip a case whose precondition is absent.
 */
export const DIALOGS: DialogCase[] = [
  {
    name: "New template chooser",
    path: "/en-US/dashboard/templates",
    role: "admin",
    ready: "main h1",
    steps: [{ clickText: "New template" }],
  },
  {
    name: "Community template",
    path: "/en-US/dashboard/templates",
    role: "admin",
    ready: "main h1",
    steps: [{ clickText: "New template" }, { click: '[data-new-template="community"]' }],
  },
  {
    name: "Archive template",
    path: "/en-US/dashboard/templates",
    role: "admin",
    ready: 'ul li [data-page-actions] button[aria-haspopup="menu"]',
    steps: [
      { click: 'ul li [data-page-actions] button[aria-haspopup="menu"]' },
      { click: '[data-overflow-action="archive"]' },
    ],
  },
  {
    name: "Renew lifetime",
    path: "/en-US/dashboard/sandboxes",
    role: "admin",
    ready: RUNNING_SANDBOX_READY,
    steps: [OPEN_RUNNING_SANDBOX, SANDBOX_MENU, { click: '[data-overflow-action="renew"]' }],
  },
  {
    name: "Save as template",
    path: "/en-US/dashboard/sandboxes",
    role: "admin",
    ready: RUNNING_SANDBOX_READY,
    steps: [OPEN_RUNNING_SANDBOX, SANDBOX_MENU, { click: '[data-overflow-action="capture"]' }],
  },
  {
    name: "Destroy sandbox",
    path: "/en-US/dashboard/sandboxes",
    role: "admin",
    ready: RUNNING_SANDBOX_READY,
    steps: [OPEN_RUNNING_SANDBOX, SANDBOX_MENU, { click: '[data-overflow-action="destroy"]' }],
  },
  {
    name: "Create pool",
    path: "/en-US/settings/pools",
    role: "admin",
    ready: "main h1",
    steps: [{ clickText: "Create pool" }],
  },
  {
    name: "Delete pool",
    path: "/en-US/settings/pools",
    role: "admin",
    ready: 'button[aria-label^="More actions for "]',
    steps: [
      { click: 'button[aria-label^="More actions for "]' },
      { click: '[data-overflow-action="delete"]' },
    ],
  },
  {
    name: "Revoke API key",
    path: "/en-US/settings/sdk-keys",
    role: "admin",
    ready: 'button[aria-label^="Revoke "]',
    steps: [{ click: 'button[aria-label^="Revoke "]' }],
  },
  {
    name: "Invite user",
    path: "/en-US/admin/users",
    role: "admin",
    ready: "main h1",
    steps: [{ clickText: "Invite user" }],
  },
];

export interface ShellPage {
  name: string;
  path: string;
  role: Role;
  /**
   * A selector that exists only once the page's real content has loaded, not
   * in any skeleton (a row's action button, say; a card or a list item also
   * exists in the skeleton).
   */
  ready: string;
}

/** Signed-in pages `check:shell-loading` hard-reloads (two or more different shapes). */
export const SHELL_PAGES: ShellPage[] = [
  {
    name: "sandboxes (list in the dashboard frame)",
    path: "/en-US/dashboard/sandboxes",
    role: "admin",
    ready: 'a[aria-label^="Open sandbox "]',
  },
  {
    name: "settings hub (card grid)",
    path: "/en-US/settings",
    role: "admin",
    ready: "[data-hub-item]",
  },
  {
    name: "new sandbox (form page)",
    path: "/en-US/dashboard/sandboxes/new",
    role: "admin",
    ready: '[data-slot="form-action-bar"] button[type="submit"]',
  },
];
