import { describe, expect, it } from "vitest";
import limits from "../../config/src/sandbox-channel-limits.json";
import {
  CONNECT_LIMITS,
  connectClientControlSchema,
  connectServerControlSchema,
  encodeConnectDataFrame,
  parseConnectDataFrame,
} from "./connect-wire";
import fixtures from "./connect-wire-fixtures.json";

const hex = (value: string) =>
  new Uint8Array((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));

function rawFrame(metadata: unknown, body: Uint8Array): Uint8Array {
  const header = new TextEncoder().encode(JSON.stringify(metadata));
  const frame = new Uint8Array(4 + header.byteLength + body.byteLength);
  new DataView(frame.buffer).setUint32(0, header.byteLength, false);
  frame.set(header, 4);
  frame.set(body, 4 + header.byteLength);
  return frame;
}

describe("wssp.connect.v1 client wire vectors", () => {
  it.each(fixtures.client.valid)("client frame %j parses", (frame) => {
    expect(connectClientControlSchema.safeParse(frame).success).toBe(true);
  });
  it.each(fixtures.client.invalid)("client frame %j is refused", (frame) => {
    expect(connectClientControlSchema.safeParse(frame).success).toBe(false);
  });
  it.each(fixtures.server.valid)("server frame %j parses", (frame) => {
    expect(connectServerControlSchema.safeParse(frame).success).toBe(true);
  });
  it.each(fixtures.server.invalid)("server frame %j is refused", (frame) => {
    expect(connectServerControlSchema.safeParse(frame).success).toBe(false);
  });

  it("the announced limits are the hello vector and the channel manifest", () => {
    const hello = fixtures.server.valid.find((frame) => frame.type === "hello");
    expect(hello?.limits).toEqual(CONNECT_LIMITS);
    expect(CONNECT_LIMITS.windowFrames).toEqual({
      pty: limits.ptyWindowFrames,
      exec: limits.bulkWindowFrames,
    });
    expect(CONNECT_LIMITS.maxChannels).toBe(limits.maxChannelsPerConnection);
  });

  it.each(fixtures.data.valid)("data frame %j round-trips", ({ metadata, bodyHex }) => {
    const body = hex(bodyHex);
    const frame = encodeConnectDataFrame(metadata as never, body);
    const parsed = parseConnectDataFrame(frame);
    expect(parsed?.metadata).toEqual(metadata);
    expect([...(parsed?.body ?? [])]).toEqual([...body]);
  });

  it.each(fixtures.data.invalidMetadata)("data metadata %j is refused", (metadata) => {
    expect(parseConnectDataFrame(rawFrame(metadata, hex("00")))).toBeNull();
  });

  it("refuses empty, oversized and truncated data frames", () => {
    const metadata = { type: "data", channel: 1, stream: "stdin", seq: 0 } as const;
    expect(parseConnectDataFrame(rawFrame(metadata, new Uint8Array(0)))).toBeNull();
    expect(
      parseConnectDataFrame(rawFrame(metadata, new Uint8Array(limits.bulkDataMaxBytes + 1))),
    ).toBeNull();
    expect(parseConnectDataFrame(new Uint8Array([0, 0, 0]))).toBeNull();
    const truncated = rawFrame(metadata, hex("00")).subarray(0, 10);
    expect(parseConnectDataFrame(truncated)).toBeNull();
    expect(() => encodeConnectDataFrame(metadata, new Uint8Array(0))).toThrow(RangeError);
  });
});
