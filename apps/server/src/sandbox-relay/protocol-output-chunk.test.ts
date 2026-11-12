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
const { commandOutputChunk, negotiatedOutputChunkBytes } = await import("./command-output");

// Shared with `crates/sandbox-protocol/tests/output_chunk.rs` (D3b).
const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/sandbox-protocol/fixtures",
);
const read = (name: string) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
const fixture = read("output_chunk_negotiation.json") as {
  daemonOffer: number;
  serverMax: number;
  validOffers: unknown[];
  rejectedOffers: unknown[];
  helloOk: { capabilities: Record<string, unknown> } & Record<string, unknown>;
  rejectedAnswers: unknown[];
  matrix: {
    case: string;
    server: "older" | "current";
    offer: number;
    answer: number | null;
    chunkBytes: number;
  }[];
};
const hello = read("control_hello_daemon.json") as {
  daemon: { capabilities: Record<string, unknown> };
};
const helloOk = (outputChunkBytes?: unknown) => ({
  ...fixture.helloOk,
  capabilities: {
    ...negotiatedCapabilities("1.0"),
    ...(outputChunkBytes === undefined ? {} : { outputChunkBytes }),
  },
});

describe("D3b output chunk negotiation parity with Rust", () => {
  it("parses the offer strictly and only within range", () => {
    const caps = hello.daemon.capabilities;
    expect(daemonCapabilitiesV11Schema.parse(caps).maxOutputChunkBytes).toBe(fixture.daemonOffer);
    for (const offer of fixture.validOffers) {
      const frame = {
        ...hello,
        daemon: { ...hello.daemon, capabilities: { ...caps, maxOutputChunkBytes: offer } },
      };
      const parsed = parseDaemonControlFrame(JSON.stringify(frame), "1.0");
      expect(parsed.type === "hello" && parsed.daemon.capabilities.maxOutputChunkBytes).toBe(offer);
    }
    for (const offer of fixture.rejectedOffers)
      expect(
        daemonCapabilitiesV11Schema.safeParse({ ...caps, maxOutputChunkBytes: offer }).success,
        JSON.stringify(offer),
      ).toBe(false);
  });

  it("encodes the shared hello.ok and refuses an invalid answer", () => {
    expect(
      JSON.parse(encodeServerControlMessage(helloOk(fixture.serverMax) as never, "1.0")),
    ).toEqual(fixture.helloOk);
    expect(
      JSON.parse(encodeServerControlMessage(helloOk() as never, "1.0")).capabilities,
    ).toHaveProperty("outputChunkBytes", fixture.serverMax);
    for (const answer of fixture.rejectedAnswers)
      expect(
        () => encodeServerControlMessage(helloOk(answer) as never, "1.0"),
        JSON.stringify(answer),
      ).toThrow("Invalid hello capabilities.");
  });

  it("answers the matrix's offers and accepts chunks up to the answer", () => {
    for (const row of fixture.matrix) {
      const answer = negotiatedOutputChunkBytes(row.offer);
      expect(answer, row.case).toBe(row.answer);
      const meta = {
        type: "stream.chunk" as const,
        streamId: "op",
        operationId: "op",
        generation: 1,
        attempt: 1,
        sequence: 0,
        offset: 0,
        flags: { stdout: true },
      };
      expect(commandOutputChunk(meta, new Uint8Array(row.chunkBytes), answer).body).toHaveLength(
        row.chunkBytes,
      );
      expect(() => commandOutputChunk(meta, new Uint8Array(row.chunkBytes + 1), answer)).toThrow();
    }
  });
});
