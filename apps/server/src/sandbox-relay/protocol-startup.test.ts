import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { revisionStartup } from "@wssp/sandbox-contracts";
import { expect, it } from "vitest";
import { encodeServerControlMessage, type ServerControlMessage } from "./protocol";

// Shared with `crates/sandbox-protocol/tests/startup_fields.rs` (template builds B9).
const fixture = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "../../../../crates/sandbox-protocol/fixtures/control_startup.json",
    ),
    "utf8",
  ),
) as { server: ServerControlMessage[]; rejectedServer: ServerControlMessage[] };

it("shares the startup dispatch fixture with Rust: valid frames encode, invalid ones are refused", () => {
  for (const message of fixture.server)
    expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
  for (const message of fixture.rejectedServer)
    expect(() => encodeServerControlMessage(message, "1.0"), JSON.stringify(message)).toThrow();
});

it("refuses startup outside launches", () => {
  for (const kind of ["sandbox.stop", "sandbox.kill", "command.run", "file.put", "process.signal"])
    expect(() =>
      encodeServerControlMessage(
        {
          type: "operation.dispatch",
          sandboxOwnerId: "owner",
          operationId: "op",
          sandboxId: "sbx",
          idempotencyKey: "k",
          generation: 1,
          attempt: 1,
          kind,
          startup: { command: "npm start" },
        } as ServerControlMessage,
        "1.0",
      ),
    ).toThrow();
});

it("maps revision columns to the dispatch field", () => {
  const none = { startCmd: null, readyCmd: null, readyTimeoutMs: null, defaultCwd: null };
  expect(revisionStartup(none)).toBeUndefined();
  expect(revisionStartup({ ...none, startCmd: "npm start", readyTimeoutMs: 5000 })).toEqual({
    command: "npm start",
  });
  expect(
    revisionStartup({
      startCmd: "npm start",
      readyCmd: "curl -sf localhost:3000",
      readyTimeoutMs: 5000,
      defaultCwd: "/home/user/app",
    }),
  ).toEqual({
    command: "npm start",
    ready: "curl -sf localhost:3000",
    readyTimeoutMs: 5000,
    cwd: "/home/user/app",
  });
});
