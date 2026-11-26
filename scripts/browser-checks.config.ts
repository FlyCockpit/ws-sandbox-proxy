/**
 * wssp's own settings for `pnpm check:layout`, `pnpm check:dialogs` and
 * `pnpm check:shell-loading`:
 * how to sign in, every dialog to open, and the signed-in pages to
 * hard-reload. `check-dialogs.ts`, `check-shell-loading.ts` and
 * `browser-check-lib.ts` follow the template's; this file is wssp's.
 * Usage: docs/design/shell-rules.md § Dialog fit and shell loading checks
 *
 * wssp has no mock mode: the checks run against a running stack (seeded with
 * an admin account) and sign in through the real login form, second factor
 * included. Nothing machine-specific or secret is committed here:
 *
 *   WSSP_CHECK_URL          the web origin (else pass `--url`)
 *   WSSP_CHECK_CREDS_FILE   (else pass `--accounts <file>`) a KEY=value
 *                           file read at run time, with
 *                           ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_TOTP_SECRET
 *                           (and USER_* for the `user` role); the TOTP secret
 *                           may be absent for an account without 2FA
 */
import { createHmac } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { type CheckRun, formSignIn } from "./browser-check-lib.ts";

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

/**
 * The seeded accounts' KEY=value file: `--accounts <file>`, else
 * `WSSP_CHECK_CREDS_FILE`; undefined when neither is given.
 */
export function credentialsFile(args: string[]): string | undefined {
  const index = args.indexOf("--accounts");
  if (index >= 0) {
    const file = args[index + 1];
    if (!file || file.startsWith("--"))
      throw new Error("--accounts needs the seeded accounts' KEY=value file");
    return file;
  }
  return process.env.WSSP_CHECK_CREDS_FILE || undefined;
}

/**
 * One role's account from the credentials file, with clear errors for each
 * missing piece. An error names the file and the keys, never a value.
 */
export function seededAccount(args: string[], role: Exclude<Role, "anonymous">) {
  const file = credentialsFile(args);
  if (!file)
    throw new Error(
      "no credentials: pass --accounts <file> (or set WSSP_CHECK_CREDS_FILE), a KEY=value file with ADMIN_EMAIL, ADMIN_PASSWORD and ADMIN_TOTP_SECRET (USER_* for the user role)",
    );
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    throw new Error(`no credentials file at ${file}; write the seeded accounts there`);
  }
  const values = parseCredentials(text);
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

/** The role this browser session is signed in as (sign-in is rate limited and 2FA'd). */
let signedInAs: Role | null = null;

/**
 * Leaves the browser signed in as `role`, through the real login form and
 * the second-factor step (`formSignIn`, which survives the full page load a
 * sign-in ends in). Secrets reach agent-browser on stdin, never argv. Signs
 * in once per role and run; another role is signed out first.
 */
export async function signIn(
  run: Pick<CheckRun, "base" | "browser" | "args">,
  role: Role,
  _options: SignInOptions = {},
) {
  if (signedInAs === role) return;
  // Read before touching the browser, so a missing file stops the run cleanly.
  const account = role === "anonymous" ? null : seededAccount(run.args, role);
  await run.browser.run(["cookies", "clear"]);
  signedInAs = null;
  if (account) {
    const { file, totpSecret } = account;
    await formSignIn(run, {
      email: account.email,
      password: account.password,
      totp: totpSecret ? () => freshTotp(file, role, totpSecret) : undefined,
    });
  }
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
  /** What the account must hold for the dialog to open, said when it does not. */
  needs?: string;
}

/** The seeded running sandbox's row link (its id differs per stack). */
const OPEN_RUNNING_SANDBOX = {
  click: 'li[data-sandbox-state="READY"] a[aria-label^="Open sandbox "]',
};
/** The sandbox detail page's "Sandbox actions" menu. */
const SANDBOX_MENU = { click: '[data-page-actions] button[aria-label="Sandbox actions"]' };
const RUNNING_SANDBOX_READY = 'li[data-sandbox-state="READY"] a[aria-label^="Open sandbox "]';
const NEEDS_RUNNING_SANDBOX = "a running (READY) sandbox in the admin's account";

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
    needs: "a template in the admin's account",
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
    needs: NEEDS_RUNNING_SANDBOX,
    steps: [OPEN_RUNNING_SANDBOX, SANDBOX_MENU, { click: '[data-overflow-action="renew"]' }],
  },
  {
    name: "Save as template",
    path: "/en-US/dashboard/sandboxes",
    role: "admin",
    ready: RUNNING_SANDBOX_READY,
    needs: NEEDS_RUNNING_SANDBOX,
    steps: [OPEN_RUNNING_SANDBOX, SANDBOX_MENU, { click: '[data-overflow-action="capture"]' }],
  },
  {
    name: "Destroy sandbox",
    path: "/en-US/dashboard/sandboxes",
    role: "admin",
    ready: RUNNING_SANDBOX_READY,
    needs: NEEDS_RUNNING_SANDBOX,
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
    needs: "a pool the admin owns",
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
    needs: "an API key in the admin's account",
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
  /** What the account must hold for `ready` to appear, said when it does not. */
  needs?: string;
}

/** Signed-in pages `check:shell-loading` hard-reloads (two or more different shapes). */
export const SHELL_PAGES: ShellPage[] = [
  {
    name: "sandboxes (list in the dashboard frame)",
    path: "/en-US/dashboard/sandboxes",
    role: "admin",
    ready: 'a[aria-label^="Open sandbox "]',
    needs: "a sandbox in the admin's account",
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
