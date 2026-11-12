import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Runtime/lock claims: sandbox/host-terminal-tickets.pg.test.ts uses this real router.
// Unit coverage keeps both entry points at the registered gate and preserves cookie-only output.
describe("host terminal router boundary (source contract; real PG in host-terminal-tickets.pg.test.ts)", () => {
  const source = readFileSync(new URL("./host-terminals.ts", import.meta.url), "utf8");
  it.each(["createSession", "raiseHostTerminalTotp"])(
    "%s starts at the live-owner gate",
    (name) => {
      expect(source).toMatch(new RegExp(`${name}: liveOwnerSessionProcedure`));
    },
  );
  it("keeps distinct host ticket namespace and online-only, bounded raise", () => {
    expect(source).toContain("HOST_TERMINAL_TICKET_PROTOCOL_PREFIX");

    expect(source).toContain("return raiseHostTerminalTotp(");
    expect(source).not.toContain("requireHostTerminalTotp: false");
  });
});
