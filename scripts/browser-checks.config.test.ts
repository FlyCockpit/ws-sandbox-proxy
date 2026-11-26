/** Unit tests for the pure parts of scripts/browser-checks.config.ts: node --test */
import assert from "node:assert/strict";
import { test } from "node:test";

import { DIALOGS, parseCredentials, SHELL_PAGES, totpCode } from "./browser-checks.config.ts";

test("reads KEY=value credentials, ignoring comments and blank lines", () => {
  assert.deepEqual(
    parseCredentials("# accounts\n\nADMIN_EMAIL=a@example.test\nADMIN_PASSWORD= p=w \n"),
    { ADMIN_EMAIL: "a@example.test", ADMIN_PASSWORD: "p=w" },
  );
});

test("computes RFC 6238 TOTP codes (SHA-1 test vectors, 6 digits)", () => {
  // The RFC's secret "12345678901234567890" in base32.
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(totpCode(secret, Math.floor(59 / 30)), "287082");
  assert.equal(totpCode(secret, Math.floor(1111111109 / 30)), "081804");
  assert.equal(totpCode(secret.toLowerCase(), Math.floor(1234567890 / 30)), "005924");
});

test("lists uniquely named dialogs and at least two shell pages", () => {
  const names = DIALOGS.map((dialog) => dialog.name);
  assert.equal(new Set(names).size, names.length);
  for (const dialog of DIALOGS) assert.match(dialog.path, /^\/en-US\//);
  assert.ok(SHELL_PAGES.length >= 2);
});
