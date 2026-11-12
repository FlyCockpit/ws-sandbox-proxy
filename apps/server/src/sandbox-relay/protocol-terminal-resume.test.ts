import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { daemonCapabilitiesV11Schema } from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: {} }));

const { encodeServerControlMessage, negotiatedCapabilities, parseDaemonControlFrame } =
  await import("./protocol");
const { TERMINAL_RESUME_GRACE_DEFAULT_MS, TERMINAL_RESUME_GRACE_MAX_MS } = await import(
  "@wssp/config/browser-terminal"
);

// Shared with `crates/sandbox-protocol/tests/terminal_resume.rs` (WP8).
const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/sandbox-protocol/fixtures",
);
const read = (name: string) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
const fixture = read("terminal_resume.json") as {
  graceDefaultMs: number;
  graceMaxMs: number;
  validOffers: unknown[];
  rejectedOffers: unknown[];
  helloOk: { capabilities: Record<string, unknown> } & Record<string, unknown>;
  rejectedAnswers: unknown[];
  resume: Record<string, unknown>[];
  rejectedResume: Record<string, unknown>[];
  ready: Record<string, unknown>[];
  rejectedReady: Record<string, unknown>[];
};
const hello = read("control_hello_daemon.json") as {
  daemon: { capabilities: Record<string, unknown> };
};
const helloOk = (terminalResume?: unknown) => ({
  ...fixture.helloOk,
  capabilities: {
    ...negotiatedCapabilities("1.0"),
    ...(terminalResume === undefined ? {} : { terminalResume }),
  },
});

describe("WP8 terminal resume parity with Rust", () => {
  it("shares the grace bounds", () => {
    expect(fixture.graceDefaultMs).toBe(TERMINAL_RESUME_GRACE_DEFAULT_MS);
    expect(fixture.graceMaxMs).toBe(TERMINAL_RESUME_GRACE_MAX_MS);
  });

  it("parses the capability strictly and only within range", () => {
    const caps = hello.daemon.capabilities;
    expect(daemonCapabilitiesV11Schema.parse(caps).terminalResume).toBeUndefined();
    for (const offer of fixture.validOffers) {
      const frame = {
        ...hello,
        daemon: { ...hello.daemon, capabilities: { ...caps, terminalResume: offer } },
      };
      const parsed = parseDaemonControlFrame(JSON.stringify(frame), "1.0");
      expect(parsed.type === "hello" && parsed.daemon.capabilities.terminalResume).toEqual(offer);
    }
    for (const offer of fixture.rejectedOffers)
      expect(
        daemonCapabilitiesV11Schema.safeParse({ ...caps, terminalResume: offer }).success,
        JSON.stringify(offer),
      ).toBe(false);
  });

  it("encodes the shared hello.ok and refuses an invalid answer", () => {
    expect(JSON.parse(encodeServerControlMessage(helloOk(true) as never, "1.0"))).toEqual(
      fixture.helloOk,
    );
    expect(
      JSON.parse(encodeServerControlMessage(helloOk() as never, "1.0")).capabilities,
    ).not.toHaveProperty("terminalResume");
    for (const answer of fixture.rejectedAnswers)
      expect(
        () => encodeServerControlMessage(helloOk(answer) as never, "1.0"),
        JSON.stringify(answer),
      ).toThrow();
  });

  it("encodes resume frames for sandbox targets only", () => {
    for (const frame of fixture.resume)
      expect(JSON.parse(encodeServerControlMessage(frame as never, "1.0"))).toEqual(frame);
    for (const frame of fixture.rejectedResume)
      expect(
        () => encodeServerControlMessage(frame as never, "1.0"),
        JSON.stringify(frame),
      ).toThrow();
  });

  it("parses the resume answer's output sequence strictly", () => {
    for (const frame of fixture.ready)
      expect(parseDaemonControlFrame(JSON.stringify(frame), "1.0")).toEqual(frame);
    for (const frame of fixture.rejectedReady)
      expect(
        () => parseDaemonControlFrame(JSON.stringify(frame), "1.0"),
        JSON.stringify(frame),
      ).toThrow();
  });
});
