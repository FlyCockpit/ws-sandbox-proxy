import { createHash } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type OperationState, type Prisma } from "@wssp/db";
import {
  type CommandOutputPageDto,
  OUTPUT_HEAD_BYTES,
  OUTPUT_PAGE_MAX_BYTES,
  OUTPUT_PAGE_MAX_CHUNKS,
  OUTPUT_RETENTION_MS,
  OUTPUT_TAIL_BYTES,
} from "@wssp/sandbox-contracts";
import { operationNotFound, sandboxStateConflict } from "./errors";
import { requireRelayFence } from "./relay-fence";

/**
 * Durable command output (C26). One `SandboxCommandOutput` row per RUN_COMMAND
 * operation plus at most `OUTPUT_MAX_*_SEGMENTS` rows of ≤ 8 KiB each. Bytes at
 * aggregate offsets below 256 KiB are the head; later bytes form a rolling
 * 768 KiB tail. Nothing else is stored, so the aggregate cap is 1 MiB and every
 * missing range reads back as an explicit gap.
 *
 * Writers run inside the relay transaction after the operation row (O) is
 * locked, so lock order stays H → S → O → output rows. Readers take one
 * REPEATABLE READ snapshot of the operation, header and segments, so a page
 * never mixes an append/trim with the state it was written under.
 */
export const OUTPUT_SEGMENT_BYTES = 8 * 1024;
/**
 * Largest command-output body the server stores in one relay chunk (D3b). It
 * is advertised to daemons that offer `maxOutputChunkBytes`; a stored chunk is
 * still split into `OUTPUT_SEGMENT_BYTES` rows, so caps, fingerprints and
 * paging are unchanged.
 */
export const OUTPUT_CHUNK_MAX_BYTES = 64 * 1024;
/** Legitimate output needs 32 head segments; the rest absorbs host gaps. */
export const OUTPUT_MAX_HEAD_SEGMENTS = 64;
/** Legitimate output needs 97 tail segments; the rest absorbs host gaps. */
export const OUTPUT_MAX_TAIL_SEGMENTS = 192;
/** Segment rows one page examines. */
export const OUTPUT_PAGE_MAX_SEGMENTS = 64;
const RECENT_FINGERPRINTS = 4;

/** States in which the fence admits no further output for any attempt. */
const FINAL_OUTPUT_STATES: ReadonlySet<OperationState> = new Set([
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
]);

type Tx = Prisma.TransactionClient;

// ── stderr bit masks: bit i (LSB first) is set when byte i came from stderr ──

export function maskBit(mask: Uint8Array, index: number): boolean {
  return (((mask[index >> 3] ?? 0) >> (index & 7)) & 1) === 1;
}

function packMask(length: number, bit: (index: number) => boolean): Uint8Array<ArrayBuffer> {
  const mask = new Uint8Array(Math.ceil(length / 8));
  for (let i = 0; i < length; i++) if (bit(i)) mask[i >> 3]! |= 1 << (i & 7);
  return mask;
}

export function fillMask(length: number, stderr: boolean) {
  return packMask(length, () => stderr);
}

export function concatMask(a: Uint8Array, aLength: number, b: Uint8Array, bLength: number) {
  return packMask(aLength + bLength, (i) =>
    i < aLength ? maskBit(a, i) : maskBit(b, i - aLength),
  );
}

export function sliceMask(mask: Uint8Array, from: number, to: number) {
  return packMask(to - from, (i) => maskBit(mask, from + i));
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

// ── write path ──

export type CommandOutputChunk = {
  operationId: string;
  attempt: number;
  sequence: number;
  offset: number;
  gapStart?: number;
  stderr: boolean;
  body: Uint8Array;
};

type Fingerprint = { sequence: number; hash: string };
type HeaderState = {
  id: string;
  attempt: number;
  nextSequence: number;
  receivedEnd: number;
  totalBytes: number | null;
  headBytes: number;
  tailBytes: number;
  headSegments: number;
  tailSegments: number;
  recent: Fingerprint[];
};

function fingerprint(chunk: CommandOutputChunk): string {
  return createHash("sha256")
    .update(
      JSON.stringify([chunk.attempt, chunk.sequence, chunk.offset, chunk.gapStart, chunk.stderr]),
    )
    .update(chunk.body)
    .digest("hex");
}

function parseRecent(value: unknown): Fingerprint[] {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (entry): entry is Fingerprint =>
      entry !== null &&
      typeof entry === "object" &&
      typeof entry.sequence === "number" &&
      typeof entry.hash === "string",
  );
}

async function loadHeader(tx: Tx, operationId: string): Promise<HeaderState | null> {
  const row = await tx.sandboxCommandOutput.findUnique({ where: { id: operationId } });
  if (!row) return null;
  return {
    id: row.id,
    attempt: row.attempt,
    nextSequence: row.nextSequence,
    receivedEnd: Number(row.receivedEnd),
    totalBytes: row.totalBytes === null ? null : Number(row.totalBytes),
    headBytes: row.headBytes,
    tailBytes: row.tailBytes,
    headSegments: row.headSegments,
    tailSegments: row.tailSegments,
    recent: parseRecent(row.recent),
  };
}

function freshHeader(operationId: string, attempt: number): HeaderState {
  return {
    id: operationId,
    attempt,
    nextSequence: 0,
    receivedEnd: 0,
    totalBytes: null,
    headBytes: 0,
    tailBytes: 0,
    headSegments: 0,
    tailSegments: 0,
    recent: [],
  };
}

function headerData(state: HeaderState) {
  return {
    attempt: state.attempt,
    nextSequence: state.nextSequence,
    receivedEnd: BigInt(state.receivedEnd),
    totalBytes: state.totalBytes === null ? null : BigInt(state.totalBytes),
    headBytes: state.headBytes,
    tailBytes: state.tailBytes,
    headSegments: state.headSegments,
    tailSegments: state.tailSegments,
    recent: state.recent,
  };
}

/**
 * Returns the header row this attempt may write, creating or resetting it. A
 * newer dispatch attempt discards bytes authored by an older one; an older
 * attempt than the stored one never writes. Caller holds the operation row lock.
 */
async function headerForAttempt(tx: Tx, operationId: string, attempt: number) {
  const current = await loadHeader(tx, operationId);
  if (current) {
    requireRelayFence(current.attempt <= attempt);
    if (current.attempt === attempt) return current;
    await tx.sandboxCommandOutputSegment.deleteMany({ where: { outputId: operationId } });
    const fresh = freshHeader(operationId, attempt);
    await saveHeader(tx, fresh);
    return fresh;
  }
  const fresh = freshHeader(operationId, attempt);
  await tx.sandboxCommandOutput.create({ data: { id: operationId, ...headerData(fresh) } });
  return fresh;
}

async function saveHeader(tx: Tx, state: HeaderState) {
  await tx.sandboxCommandOutput.update({ where: { id: state.id }, data: headerData(state) });
}

type SegmentRow = {
  id: string;
  startOffset: bigint;
  endOffset: bigint;
  bytes: Uint8Array;
  stderrMask: Uint8Array;
};

function lastSegment(tx: Tx, outputId: string, tail: boolean): Promise<SegmentRow | null> {
  return tx.sandboxCommandOutputSegment.findFirst({
    where: { outputId, tail },
    orderBy: { startOffset: "desc" },
  });
}

async function dropOldestTailBytes(tx: Tx, state: HeaderState, excess: number) {
  const oldest = await tx.sandboxCommandOutputSegment.findFirst({
    where: { outputId: state.id, tail: true },
    orderBy: { startOffset: "asc" },
  });
  if (!oldest) throw new Error("Command output tail accounting is inconsistent.");
  const length = oldest.bytes.length;
  if (length <= excess) {
    await tx.sandboxCommandOutputSegment.deleteMany({ where: { id: oldest.id } });
    state.tailBytes -= length;
    state.tailSegments -= 1;
    return;
  }
  await tx.sandboxCommandOutputSegment.update({
    where: { id: oldest.id },
    data: {
      startOffset: oldest.startOffset + BigInt(excess),
      bytes: oldest.bytes.slice(excess),
      stderrMask: sliceMask(oldest.stderrMask, excess, length),
    },
  });
  state.tailBytes -= excess;
}

async function storeRegion(
  tx: Tx,
  state: HeaderState,
  tail: boolean,
  start: number,
  bytes: Uint8Array,
  stderr: boolean,
) {
  let written = 0;
  const last = await lastSegment(tx, state.id, tail);
  if (last && Number(last.endOffset) === start && last.bytes.length < OUTPUT_SEGMENT_BYTES) {
    written = Math.min(OUTPUT_SEGMENT_BYTES - last.bytes.length, bytes.length);
    const part = bytes.subarray(0, written);
    await tx.sandboxCommandOutputSegment.update({
      where: { id: last.id },
      data: {
        endOffset: last.endOffset + BigInt(written),
        bytes: concatBytes(last.bytes, part),
        stderrMask: concatMask(
          last.stderrMask,
          last.bytes.length,
          fillMask(written, stderr),
          written,
        ),
      },
    });
  }
  let stored = written;
  while (written < bytes.length) {
    const length = Math.min(OUTPUT_SEGMENT_BYTES, bytes.length - written);
    // Only a gap-fragmenting host can exhaust tail rows; the oldest row goes.
    if (tail && state.tailSegments >= OUTPUT_MAX_TAIL_SEGMENTS)
      await dropOldestTailBytes(tx, state, Number.MAX_SAFE_INTEGER);
    // Only a gap-fragmenting host can exhaust head rows; its bytes become a gap.
    if (!tail && state.headSegments >= OUTPUT_MAX_HEAD_SEGMENTS) break;
    const offset = start + written;
    await tx.sandboxCommandOutputSegment.create({
      data: {
        outputId: state.id,
        tail,
        startOffset: BigInt(offset),
        endOffset: BigInt(offset + length),
        bytes: bytes.slice(written, written + length),
        stderrMask: fillMask(length, stderr),
      },
    });
    if (tail) state.tailSegments += 1;
    else state.headSegments += 1;
    written += length;
    stored += length;
  }
  if (tail) {
    state.tailBytes += stored;
    while (state.tailBytes > OUTPUT_TAIL_BYTES)
      await dropOldestTailBytes(tx, state, state.tailBytes - OUTPUT_TAIL_BYTES);
  } else state.headBytes += stored;
}

function validChunk(chunk: CommandOutputChunk): boolean {
  const { offset, body } = chunk;
  return !(
    body.length === 0 ||
    body.length > OUTPUT_CHUNK_MAX_BYTES ||
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    !Number.isSafeInteger(offset + body.length) ||
    !Number.isSafeInteger(chunk.sequence) ||
    chunk.sequence < 0 ||
    chunk.sequence > 2_147_483_646
  );
}

/**
 * Persist one fenced relay chunk. Returns true for a stored chunk or an exact
 * replay of one of the last four (both are acknowledged). A conflicting replay
 * or a cursor that skips bytes without declaring the gap throws (protocol
 * error); a sealed output or a superseded attempt is a fence rejection.
 * Caller has locked the operation row and verified the exact dispatch binding.
 */
export async function appendCommandOutput(tx: Tx, chunk: CommandOutputChunk): Promise<true> {
  return appendCommandOutputBatch(tx, [chunk]);
}

/**
 * Persist consecutive fenced relay chunks of one operation attempt (D3b): the
 * header is read and saved once, and every chunk passes exactly the checks of
 * `appendCommandOutput` against the state its predecessors left, so the rows
 * written equal those of the same chunks appended one by one. Any refusal or
 * protocol error rejects the whole batch (the caller's transaction rolls back).
 */
export async function appendCommandOutputBatch(
  tx: Tx,
  chunks: readonly CommandOutputChunk[],
): Promise<true> {
  const first = chunks[0];
  if (
    first === undefined ||
    chunks.some(
      (chunk) =>
        !validChunk(chunk) ||
        chunk.operationId !== first.operationId ||
        chunk.attempt !== first.attempt,
    )
  )
    throw new Error("Invalid command output metadata.");
  const state = await headerForAttempt(tx, first.operationId, first.attempt);
  // The completion watermark is final: nothing reopens committed output.
  requireRelayFence(state.totalBytes === null);
  let changed = false;
  for (const chunk of chunks) {
    const { offset, body } = chunk;
    const hash = fingerprint(chunk);
    const replay = state.recent.find((entry) => entry.sequence === chunk.sequence);
    if (replay) {
      if (replay.hash !== hash) throw new Error("Conflicting output replay.");
      continue;
    }
    const end = state.receivedEnd;
    if (
      chunk.sequence !== state.nextSequence ||
      offset < end ||
      (offset > end ? chunk.gapStart !== end : chunk.gapStart !== undefined)
    )
      throw new Error("Invalid output cursor.");
    const headLength = Math.max(0, Math.min(body.length, OUTPUT_HEAD_BYTES - offset));
    if (headLength > 0)
      await storeRegion(tx, state, false, offset, body.subarray(0, headLength), chunk.stderr);
    if (headLength < body.length)
      await storeRegion(
        tx,
        state,
        true,
        offset + headLength,
        body.subarray(headLength),
        chunk.stderr,
      );
    state.nextSequence += 1;
    state.receivedEnd = offset + body.length;
    state.recent = [...state.recent, { sequence: chunk.sequence, hash }].slice(
      -RECENT_FINGERPRINTS,
    );
    changed = true;
  }
  if (changed) await saveHeader(tx, state);
  return true;
}

/**
 * Commit the output completion watermark with the host's final result. The
 * host sends every output frame for an attempt before that attempt's final
 * result on the same ordered socket, so bytes missing now were dropped: they
 * become a trailing gap. Idempotent for the same total. Caller holds O.
 */
export async function sealCommandOutput(
  tx: Tx,
  input: { operationId: string; attempt: number; totalBytes: number },
) {
  requireRelayFence(Number.isSafeInteger(input.totalBytes) && input.totalBytes >= 0);
  const state = await headerForAttempt(tx, input.operationId, input.attempt);
  requireRelayFence(state.receivedEnd <= input.totalBytes);
  if (state.totalBytes !== null) {
    requireRelayFence(state.totalBytes === input.totalBytes);
    return;
  }
  state.totalBytes = input.totalBytes;
  await saveHeader(tx, state);
}

/** Output content expires 24 hours after its operation completes. */
export function commandOutputExpiresAt(completedAt: Date | null): Date | null {
  return completedAt ? new Date(completedAt.getTime() + OUTPUT_RETENTION_MS) : null;
}

export function isCommandOutputExpired(completedAt: Date | null, now: Date): boolean {
  const expiresAt = commandOutputExpiresAt(completedAt);
  return expiresAt !== null && now.getTime() >= expiresAt.getTime();
}

/** Deletes expired output content in bounded batches; operation rows remain. */
export async function purgeExpiredCommandOutput(
  now: Date,
  batch = 100,
  client: Pick<typeof prisma, "sandboxCommandOutput"> = prisma,
): Promise<number> {
  const expired = {
    Operation: { completedAt: { lte: new Date(now.getTime() - OUTPUT_RETENTION_MS) } },
  };
  const rows = await client.sandboxCommandOutput.findMany({
    where: expired,
    select: { id: true },
    orderBy: { id: "asc" },
    take: batch,
  });
  if (rows.length === 0) return 0;
  const deleted = await client.sandboxCommandOutput.deleteMany({
    where: { id: { in: rows.map((row) => row.id) }, ...expired },
  });
  return deleted.count;
}

// ── read path ──

const CURSOR = /^([0-9]{1,10})_([0-9]{1,16})$/;

export function encodeOutputCursor(attempt: number, offset: number): string {
  return `${attempt}_${offset}`;
}

export function decodeOutputCursor(cursor: string): { attempt: number; offset: number } | null {
  const match = CURSOR.exec(cursor);
  if (!match) return null;
  const attempt = Number(match[1]);
  const offset = Number(match[2]);
  if (!Number.isSafeInteger(attempt) || !Number.isSafeInteger(offset)) return null;
  return { attempt, offset };
}

export function outputExpired() {
  return new ORPCError("GONE", {
    status: 410,
    message: "Command output has expired; the operation status is still available.",
    data: { code: "OUTPUT_EXPIRED" },
  });
}

export type OutputPageOperation = {
  id: string;
  kind: string;
  state: OperationState;
  completedAt: Date | null;
  result: unknown;
};
export type OutputPageHeader = {
  attempt: number;
  receivedEnd: bigint;
  totalBytes: bigint | null;
  headBytes: number;
  tailBytes: number;
};
export type OutputPageSegment = {
  startOffset: bigint;
  endOffset: bigint;
  bytes: Uint8Array;
  stderrMask: Uint8Array;
};

function exitCodeOf(result: unknown): number | null {
  if (result === null || typeof result !== "object" || !("exitCode" in result)) return null;
  const code = (result as { exitCode: unknown }).exitCode;
  return typeof code === "number" && Number.isSafeInteger(code) ? code : null;
}

/**
 * Pure page builder. `segments` are the retained segments ending after the
 * cursor, ascending, at most `OUTPUT_PAGE_MAX_SEGMENTS + 1` of them (the extra
 * one only signals that more exist). A range below the received end that no
 * retained segment covers can never be filled again, so it is a gap.
 */
export function buildCommandOutputPage(input: {
  operation: OutputPageOperation;
  header: OutputPageHeader | null;
  segments: readonly OutputPageSegment[];
  cursor?: string;
  maxBytes?: number;
  now: Date;
  /** The sandbox generation has advanced past this operation: its output is
   * permanently fenced, so no byte can ever commit again (C26). */
  superseded?: boolean;
}): CommandOutputPageDto {
  const { operation, header } = input;
  if (isCommandOutputExpired(operation.completedAt, input.now)) throw outputExpired();
  const maxBytes = Math.min(input.maxBytes ?? OUTPUT_PAGE_MAX_BYTES, OUTPUT_PAGE_MAX_BYTES);
  const received = Number(header?.receivedEnd ?? 0n);
  const total = header?.totalBytes == null ? null : Number(header.totalBytes);
  const complete =
    total !== null || FINAL_OUTPUT_STATES.has(operation.state) || input.superseded === true;
  const bound = Math.max(received, total ?? 0);
  const attempt = header?.attempt ?? 0;
  let start = 0;
  let reset = false;
  if (input.cursor !== undefined) {
    const cursor = decodeOutputCursor(input.cursor);
    if (!cursor) throw new ORPCError("BAD_REQUEST", { message: "Invalid output cursor." });
    if (cursor.attempt !== attempt) reset = true;
    else if (cursor.offset > bound)
      throw new ORPCError("BAD_REQUEST", { message: "Invalid output cursor." });
    else start = cursor.offset;
  }
  const chunks: CommandOutputPageDto["chunks"] = [];
  const gaps: CommandOutputPageDto["gaps"] = [];
  const full = () => chunks.length + gaps.length >= OUTPUT_PAGE_MAX_CHUNKS;
  let position = start;
  let bytes = 0;
  let stopped = false;
  const examined = input.segments.slice(0, OUTPUT_PAGE_MAX_SEGMENTS);
  for (const segment of examined) {
    const segmentStart = Number(segment.startOffset);
    const segmentEnd = Number(segment.endOffset);
    if (segmentEnd <= position) continue;
    if (segmentStart > position) {
      if (full()) {
        stopped = true;
        break;
      }
      gaps.push({ start: position, end: segmentStart });
      position = segmentStart;
    }
    let index = position - segmentStart;
    const length = segment.bytes.length;
    while (index < length) {
      if (bytes >= maxBytes || full()) {
        stopped = true;
        break;
      }
      const stderr = maskBit(segment.stderrMask, index);
      const limit = Math.min(length, index + (maxBytes - bytes));
      let next = index + 1;
      while (next < limit && maskBit(segment.stderrMask, next) === stderr) next++;
      chunks.push({
        stream: stderr ? "stderr" : "stdout",
        offset: segmentStart + index,
        data: Buffer.from(segment.bytes.subarray(index, next)).toString("base64"),
      });
      bytes += next - index;
      index = next;
    }
    position = segmentStart + index;
    if (stopped) break;
  }
  const moreSegments = input.segments.length > OUTPUT_PAGE_MAX_SEGMENTS;
  if (!stopped && !moreSegments && position < bound) {
    if (full()) stopped = true;
    else {
      gaps.push({ start: position, end: bound });
      position = bound;
    }
  }
  const retained = (header?.headBytes ?? 0) + (header?.tailBytes ?? 0);
  const expiresAt = commandOutputExpiresAt(operation.completedAt);
  return {
    operationId: operation.id,
    state: operation.state,
    exitCode: exitCodeOf(operation.result),
    attempt,
    reset,
    offset: start,
    chunks,
    gaps,
    nextCursor: encodeOutputCursor(attempt, position),
    hasMore: stopped || moreSegments,
    receivedBytes: received,
    totalBytes: total,
    retainedBytes: retained,
    truncated: retained < bound,
    complete,
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
  };
}

/**
 * One owner-scoped page from a single REPEATABLE READ snapshot. Callers
 * authorize first; `ownerId` still scopes every row read here.
 */
export async function readCommandOutputPage(input: {
  ownerId: string;
  operationId: string;
  cursor?: string;
  maxBytes?: number;
  now: Date;
}): Promise<CommandOutputPageDto> {
  return prisma.$transaction(
    async (tx) => {
      const operation = await tx.sandboxOperation.findFirst({
        where: {
          id: input.operationId,
          userId: input.ownerId,
          Sandbox: { userId: input.ownerId },
        },
        select: {
          id: true,
          kind: true,
          state: true,
          completedAt: true,
          result: true,
          generation: true,
          // Same REPEATABLE READ snapshot: a newer sandbox generation permanently
          // fences this operation's output, which then reports completion.
          Sandbox: { select: { generation: true } },
        },
      });
      if (!operation) throw operationNotFound();
      if (operation.kind !== "RUN_COMMAND")
        throw sandboxStateConflict("Operation is not a command.");
      if (isCommandOutputExpired(operation.completedAt, input.now)) throw outputExpired();
      const header = await tx.sandboxCommandOutput.findUnique({
        where: { id: operation.id },
        select: {
          attempt: true,
          receivedEnd: true,
          totalBytes: true,
          headBytes: true,
          tailBytes: true,
        },
      });
      const cursor = input.cursor === undefined ? undefined : decodeOutputCursor(input.cursor);
      const from = cursor && header && cursor.attempt === header.attempt ? cursor.offset : 0;
      const segments = header
        ? await tx.sandboxCommandOutputSegment.findMany({
            where: { outputId: operation.id, endOffset: { gt: BigInt(from) } },
            orderBy: { startOffset: "asc" },
            take: OUTPUT_PAGE_MAX_SEGMENTS + 1,
            select: { startOffset: true, endOffset: true, bytes: true, stderrMask: true },
          })
        : [];
      return buildCommandOutputPage({
        operation,
        header,
        segments,
        cursor: input.cursor,
        maxBytes: input.maxBytes,
        now: input.now,
        superseded: operation.Sandbox.generation > operation.generation,
      });
    },
    { isolationLevel: "RepeatableRead" },
  );
}
