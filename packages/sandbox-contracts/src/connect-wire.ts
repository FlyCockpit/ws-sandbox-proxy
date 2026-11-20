/**
 * Client wire `wssp.connect.v1` (CLI ↔ server, `GET /v1/sandboxes/{id}/connect`).
 *
 * One WebSocket multiplexes many channels. Control frames are JSON text;
 * channel data is binary: a big-endian u32 metadata length, the JSON metadata
 * `{type: "data", channel, stream, seq}`, then the body (the host leg's
 * layout). Every schema is strict: an unknown field is a protocol error.
 *
 * Channel ids are client-chosen u32 numbers, strictly increasing per
 * connection (never reused). The server maps each to a host channel id it
 * mints; nothing but the kind parameters travels from the client to the node.
 * Sequences count data frames per channel and stream from 0; acks are
 * cumulative (the highest delivered `seq`); `eof.frames` and `exit.frames`
 * count the data frames sent on a stream. See
 * `docs/design/connect-channel-contract.md#client-wire-wsspconnectv1`.
 */
import { z } from "zod";
import limits from "../../config/src/sandbox-channel-limits.json";
import terminalLimits from "../../config/src/sandbox-terminal-limits.json";

export const CONNECT_SUBPROTOCOL = "wssp.connect.v1";
/** The client WebSocket's close code after a final `end` frame. */
export const CONNECT_CLOSE_CODE = 4401;
/** Largest accepted text control frame (an `open` with a full argv and env). */
export const CONNECT_CONTROL_MAX_BYTES = 256 * 1024;
/** Largest accepted binary metadata header. */
export const CONNECT_DATA_METADATA_MAX_BYTES = 1024;

/** Connection-level limits; the server announces them in `hello.limits`. */
export const CONNECT_LIMITS = {
  maxChannels: limits.maxChannelsPerConnection,
  maxPtyChannels: limits.maxPtyChannelsPerConnection,
  opensPerMinute: 120,
  /** Unacknowledged data frames per channel and direction (both output streams together). */
  windowFrames: { pty: limits.ptyWindowFrames, exec: limits.bulkWindowFrames },
  dataMaxBytes: { pty: limits.ptyDataMaxBytes, exec: limits.bulkDataMaxBytes },
  /** The node closes a channel whose oldest unacknowledged output frame is this old. */
  ackStallMs: 60_000,
  /** The server pings every `pingIntervalMs`; a client silent for `idleTimeoutMs` is gone. */
  pingIntervalMs: 20_000,
  idleTimeoutMs: 60_000,
  /** An open the node does not answer in time ends with `expired` / `timeout`. */
  openTimeoutMs: 30_000,
  /** stdin bytes not yet acknowledged by the server, across the connection's channels. */
  unackedInputBytes: 4 * 1024 * 1024,
} as const;

/**
 * Why `UNSUPPORTED_CAPABILITY` refused a connect upgrade (`reason`):
 * `connect_host_outdated` — the sandbox's node did not negotiate channels
 * (update the node daemon); `connect_sandbox_unsupported` — a build, verify
 * or CLI-login sandbox, which never gets a shell.
 */
export const CONNECT_REFUSAL_REASONS = [
  "connect_host_outdated",
  "connect_sandbox_unsupported",
] as const;
export const connectRefusalReasonSchema = z.enum(CONNECT_REFUSAL_REASONS);
export type ConnectRefusalReason = z.infer<typeof connectRefusalReasonSchema>;

/** Kinds of this release (`tcp`/`unix` come later, behind a new hello kind). */
export const CONNECT_CHANNEL_KINDS = ["pty", "exec"] as const;
export type ConnectChannelKind = (typeof CONNECT_CHANNEL_KINDS)[number];

export const CONNECT_CLOSE_INTENTS = [
  "client",
  "detached",
  "backpressure",
  "revoked",
  "superseded",
  "protocol_violation",
  "host_disconnected",
  "expired",
  "sandbox_stopped",
  "sandbox_destroyed",
  "lifecycle_unconfirmed",
  "shutdown",
] as const;
export type ConnectCloseIntent = (typeof CONNECT_CLOSE_INTENTS)[number];

const utf8 = new TextEncoder();
const utf8Bytes = (value: string) => utf8.encode(value).byteLength;
const noNul = (value: string) => !value.includes("\0");

const channelSchema = z.number().int().min(0).max(4_294_967_295);
const seqSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const rowsSchema = z.number().int().min(1).max(terminalLimits.maxRows);
const colsSchema = z.number().int().min(1).max(terminalLimits.maxCols);
const intentSchema = z.enum(CONNECT_CLOSE_INTENTS);
/** A stable lower-case error code and a short message (never request data). */
export const connectErrorSchema = z.strictObject({
  code: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z][a-z0-9_]*$/),
  message: z
    .string()
    .max(1024)
    .refine((message) => utf8Bytes(message) <= 1024),
});
export type ConnectError = z.infer<typeof connectErrorSchema>;

const argvSchema = z
  .array(z.string().refine(noNul))
  .min(1)
  .max(limits.argvMaxItems)
  .refine((argv) => argv.reduce((total, arg) => total + utf8Bytes(arg), 0) <= limits.argvMaxBytes);
const cwdSchema = z
  .string()
  .refine((cwd) => cwd.startsWith("/") && noNul(cwd) && utf8Bytes(cwd) <= limits.cwdMaxBytes);
/** Only locale and colour hints; `TERM` travels in `pty.term`. */
const envSchema = z
  .record(
    z.string().regex(/^(COLORTERM|LANG|LC_[A-Z0-9_]+)$/),
    z.string().refine((value) => noNul(value) && utf8Bytes(value) <= limits.envValueMaxBytes),
  )
  .refine((env) => Object.keys(env).length <= limits.envMaxEntries);
const ptySchema = z.strictObject({
  rows: rowsSchema,
  cols: colsSchema,
  term: z
    .string()
    .min(1)
    .max(limits.termMaxBytes)
    .regex(/^[A-Za-z0-9._+-]+$/),
});

// ------------------------------------------------------- client → server

export const connectClientControlSchema = z.discriminatedUnion("type", [
  /**
   * `argv` is structural (never a shell string); absent: the guest shell, a
   * login shell with `login: true`. `pty` is required exactly for `kind: "pty"`.
   */
  z
    .strictObject({
      type: z.literal("open"),
      channel: channelSchema,
      kind: z.enum(CONNECT_CHANNEL_KINDS),
      argv: argvSchema.optional(),
      login: z.boolean().optional(),
      cwd: cwdSchema.optional(),
      env: envSchema.optional(),
      pty: ptySchema.optional(),
    })
    .refine((open) => (open.kind === "pty") === (open.pty !== undefined), {
      message: "pty parameters are required exactly for pty channels",
    }),
  /** Cumulative output credit: the highest delivered `seq` of `stream`. */
  z.strictObject({
    type: z.literal("ack"),
    channel: channelSchema,
    stream: z.enum(["stdout", "stderr"]),
    seq: seqSchema,
  }),
  /** stdin is complete after `frames` data frames (exec channels). */
  z.strictObject({
    type: z.literal("eof"),
    channel: channelSchema,
    stream: z.literal("stdin"),
    frames: seqSchema,
  }),
  z.strictObject({
    type: z.literal("resize"),
    channel: channelSchema,
    rows: rowsSchema,
    cols: colsSchema,
  }),
  /** Exec channels; `KILL` kill-closes the channel's guest scope. */
  z.strictObject({
    type: z.literal("signal"),
    channel: channelSchema,
    signal: z.enum(["TERM", "INT", "HUP", "KILL"]),
  }),
  /** A normal close (sshd semantics: the session hangs up). */
  z.strictObject({ type: z.literal("close"), channel: channelSchema }),
]);
export type ConnectClientControl = z.infer<typeof connectClientControlSchema>;

// ------------------------------------------------------- server → client

export const connectServerControlSchema = z.discriminatedUnion("type", [
  /** First frame of every connection; the client sends nothing before it. */
  z.strictObject({
    type: z.literal("hello"),
    connectionId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/),
    sandboxId: z.string().min(1).max(128),
    limits: z.strictObject({
      maxChannels: z.number().int().positive(),
      maxPtyChannels: z.number().int().positive(),
      opensPerMinute: z.number().int().positive(),
      windowFrames: z.strictObject({
        pty: z.number().int().positive(),
        exec: z.number().int().positive(),
      }),
      dataMaxBytes: z.strictObject({
        pty: z.number().int().positive(),
        exec: z.number().int().positive(),
      }),
      ackStallMs: z.number().int().positive(),
      pingIntervalMs: z.number().int().positive(),
      idleTimeoutMs: z.number().int().positive(),
      openTimeoutMs: z.number().int().positive(),
      unackedInputBytes: z.number().int().positive(),
    }),
  }),
  z.strictObject({
    type: z.literal("ready"),
    channel: channelSchema,
    pty: z.strictObject({ rows: rowsSchema, cols: colsSchema }).optional(),
  }),
  /** stdin credit: the highest `seq` the guest side consumed. */
  z.strictObject({
    type: z.literal("ack"),
    channel: channelSchema,
    stream: z.literal("stdin"),
    seq: seqSchema,
  }),
  /** `stream` ended after `frames` data frames (exec channels). */
  z.strictObject({
    type: z.literal("eof"),
    channel: channelSchema,
    stream: z.enum(["stdout", "stderr"]),
    frames: seqSchema,
  }),
  /**
   * The channel's last frame, after every output frame and eof. At most one
   * of `exitCode` and `signal`; neither is an unknown status. `intent`: the
   * channel was closed (absent: it ended on its own); `error`: why it failed.
   */
  z
    .strictObject({
      type: z.literal("exit"),
      channel: channelSchema,
      exitCode: z.number().int().min(-2_147_483_648).max(2_147_483_647).optional(),
      signal: z.number().int().min(1).max(64).optional(),
      intent: intentSchema.optional(),
      error: connectErrorSchema.optional(),
      frames: z.strictObject({ stdout: seqSchema, stderr: seqSchema }),
    })
    .refine((exit) => exit.exitCode === undefined || exit.signal === undefined),
  /** A non-fatal notice; the channel stays open. */
  z.strictObject({
    type: z.literal("error"),
    channel: channelSchema,
    code: z.enum(["unsupported_signal", "state_conflict"]),
  }),
  /** The whole connection ends; the server then closes with 4401. */
  z.strictObject({
    type: z.literal("end"),
    intent: intentSchema,
    error: connectErrorSchema.optional(),
  }),
]);
export type ConnectServerControl = z.infer<typeof connectServerControlSchema>;

// ------------------------------------------------------------ data frames

export const connectDataMetadataSchema = z.strictObject({
  type: z.literal("data"),
  channel: channelSchema,
  stream: z.enum(["stdin", "stdout", "stderr"]),
  seq: seqSchema,
});
export type ConnectDataMetadata = z.infer<typeof connectDataMetadataSchema>;

/** Body 1..=32 KiB (16 KiB on pty channels, checked by the endpoints). */
export function encodeConnectDataFrame(
  metadata: ConnectDataMetadata,
  body: Uint8Array,
): Uint8Array {
  if (body.byteLength === 0 || body.byteLength > limits.bulkDataMaxBytes)
    throw new RangeError("connect data body is empty or oversized");
  const header = utf8.encode(JSON.stringify(connectDataMetadataSchema.parse(metadata)));
  const frame = new Uint8Array(4 + header.byteLength + body.byteLength);
  new DataView(frame.buffer).setUint32(0, header.byteLength, false);
  frame.set(header, 4);
  frame.set(body, 4 + header.byteLength);
  return frame;
}

/**
 * The strictly parsed data frame, or `null` for anything malformed (short
 * frame, oversized or invalid metadata, unknown field, empty or oversized
 * body). The body is a view into `frame`.
 */
export function parseConnectDataFrame(
  frame: Uint8Array,
): { metadata: ConnectDataMetadata; body: Uint8Array } | null {
  if (frame.byteLength < 4) return null;
  const length = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(0, false);
  if (length > CONNECT_DATA_METADATA_MAX_BYTES || 4 + length > frame.byteLength) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(frame.subarray(4, 4 + length)),
    );
  } catch {
    return null;
  }
  const metadata = connectDataMetadataSchema.safeParse(raw);
  if (!metadata.success) return null;
  const body = frame.subarray(4 + length);
  if (body.byteLength === 0 || body.byteLength > limits.bulkDataMaxBytes) return null;
  return { metadata: metadata.data, body };
}
