import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, open, rm, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

/**
 * Transient spool for relayed peer image parts. Nothing here is durable: a
 * server restart fails every OPEN relay transfer (`server_restart`) and the
 * daemons re-request. Parts are 0600 files deleted on the destination's ACK.
 */
export type SpooledPart = { path: string; size: number; sha256: string };

type Waiter = () => void;

/** A PUT in progress: its reservation, abort handle and settlement. */
type Writer = { transferId: string; abort: AbortController; done: Promise<unknown> };

/** How long an ended transfer refuses late PUTs (links live 10 minutes). */
const ENDED_TTL_MS = 60 * 60_000;

export class ImageRelaySpool {
  private readonly parts = new Map<string, SpooledPart>();
  /** Parts being written: reserved synchronously, before any IO (P2-10). */
  private readonly writers = new Map<string, Writer>();
  /** Transfers dropped here (round-2 P2-6): a late PUT is refused and an
   * in-flight one is aborted, so a cancelled part is never published. */
  private readonly ended = new Map<string, number>();
  private readonly waiters = new Map<string, Set<Waiter>>();
  private bytes = 0;

  constructor(
    private readonly dir: string,
    private readonly maxBytes: number,
  ) {}

  private key(transferId: string, part: number) {
    return `${transferId}:${part}`;
  }

  get usedBytes(): number {
    return this.bytes;
  }

  has(transferId: string, part: number): boolean {
    return this.parts.has(this.key(transferId, part));
  }

  get(transferId: string, part: number): SpooledPart | undefined {
    return this.parts.get(this.key(transferId, part));
  }

  /**
   * Stream exactly `expectedSize` bytes into a 0600 file and record its
   * SHA-256. Refuses a body of any other length, a full spool and a
   * transfer that already ended here. The reservation is released exactly
   * once, on failure, abort or (by `drop`) after publication.
   */
  async put(
    transferId: string,
    part: number,
    expectedSize: number,
    body: ReadableStream<Uint8Array> | null,
  ): Promise<SpooledPart> {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(transferId)) throw new SpoolError("invalid", 400);
    if (!body) throw new SpoolError("empty", 400);
    const key = this.key(transferId, part);
    // Reserve the part and its bytes before the first await: a concurrent
    // PUT of the same part (e.g. through a replacement link) is refused here
    // and can never touch this writer's file.
    if (this.ended.has(transferId)) throw new SpoolError("ended", 409);
    if (this.has(transferId, part) || this.writers.has(key)) throw new SpoolError("duplicate", 409);
    if (this.bytes + expectedSize > this.maxBytes) throw new SpoolError("spool_full", 503);
    this.bytes += expectedSize;
    const abort = new AbortController();
    const run = (async () => {
      try {
        const spooled = await this.write(transferId, part, expectedSize, body, abort.signal);
        // Published synchronously after the last await: a transfer dropped
        // while this writer ran was aborted, and is checked once more here.
        if (abort.signal.aborted || this.ended.has(transferId)) {
          await rm(spooled.path, { force: true });
          throw new SpoolError("ended", 409);
        }
        this.parts.set(key, spooled);
        this.wakeWaiters(key);
        return spooled;
      } catch (error) {
        this.bytes -= expectedSize;
        throw error instanceof SpoolError ? error : new SpoolError("io", 500);
      } finally {
        this.writers.delete(key);
      }
    })();
    // `done` settles only after the reservation was released or published.
    this.writers.set(key, { transferId, abort, done: run.catch(() => {}) });
    return run;
  }

  private async write(
    transferId: string,
    part: number,
    expectedSize: number,
    body: ReadableStream<Uint8Array>,
    signal: AbortSignal,
  ): Promise<SpooledPart> {
    const path = resolve(join(this.dir, `${transferId}.${part}.part`));
    const hash = createHash("sha256");
    let size = 0;
    // Only a file this writer created (O_EXCL) is ever unlinked by it.
    let owned = false;
    try {
      await mkdir(this.dir, { recursive: true, mode: 0o700 });
      signal.throwIfAborted();
      const handle = await open(path, "wx", 0o600);
      owned = true;
      // The original source is a pipeline stage (round-3 P2-3): an abort
      // destroys it, which cancels the request body and interrupts a pending
      // read at once. (A `.map()` wrapper waited for the next chunk first.)
      const source = Readable.fromWeb(body as never);
      const counter = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
          size += chunk.length;
          if (size > expectedSize) return callback(new SpoolError("too_large", 413));
          hash.update(chunk);
          callback(null, chunk);
        },
      });
      await pipeline(source, counter, handle.createWriteStream(), { signal });
      if (size !== expectedSize) throw new SpoolError("size_mismatch", 400);
      return { path, size, sha256: hash.digest("hex") };
    } catch (error) {
      if (owned) await rm(path, { force: true });
      if (signal.aborted) throw new SpoolError("ended", 409);
      throw error;
    }
  }

  /** Resolve once the part is spooled, or null after `timeoutMs`. */
  waitFor(transferId: string, part: number, timeoutMs: number): Promise<SpooledPart | null> {
    const existing = this.get(transferId, part);
    if (existing) return Promise.resolve(existing);
    const key = this.key(transferId, part);
    return new Promise((done) => {
      const set = this.waiters.get(key) ?? new Set<Waiter>();
      const wake = () => {
        clearTimeout(timer);
        set.delete(wake);
        // A timed-out last waiter leaves no empty set behind.
        if (set.size === 0 && this.waiters.get(key) === set) this.waiters.delete(key);
        done(this.get(transferId, part) ?? null);
      };
      const timer = setTimeout(wake, timeoutMs);
      set.add(wake);
      this.waiters.set(key, set);
    });
  }

  read(spooled: SpooledPart): ReadableStream<Uint8Array> {
    return Readable.toWeb(createReadStream(spooled.path)) as ReadableStream<Uint8Array>;
  }

  async drop(transferId: string, part: number): Promise<void> {
    const key = this.key(transferId, part);
    const spooled = this.parts.get(key);
    if (!spooled) return;
    this.parts.delete(key);
    this.bytes -= spooled.size;
    await rm(spooled.path, { force: true });
  }

  /**
   * End a transfer here (cancelled, failed, expired): refuse its later PUTs,
   * abort and await its in-flight writers (each releases its own
   * reservation), then drop its spooled parts.
   */
  async dropTransfer(transferId: string, now = Date.now()): Promise<void> {
    for (const [id, at] of this.ended) if (now - at > ENDED_TTL_MS) this.ended.delete(id);
    this.ended.set(transferId, now);
    const active = [...this.writers.values()].filter((w) => w.transferId === transferId);
    for (const writer of active) writer.abort.abort();
    await Promise.all(active.map((writer) => writer.done));
    for (const key of [...this.parts.keys()])
      if (key.startsWith(`${transferId}:`))
        await this.drop(transferId, Number(key.slice(transferId.length + 1)));
    // Its waiters resolve null now instead of at their timeout.
    for (const key of [...this.waiters.keys()])
      if (key.startsWith(`${transferId}:`)) this.wakeWaiters(key);
  }

  private wakeWaiters(key: string) {
    const set = this.waiters.get(key);
    this.waiters.delete(key);
    for (const wake of set ?? []) wake();
  }

  /** Transfers holding spooled parts or in-flight writers in this process. */
  transferIds(): string[] {
    const keys = [...this.parts.keys(), ...this.writers.keys()];
    return [...new Set(keys.map((key) => key.slice(0, key.lastIndexOf(":"))))];
  }

  /** Startup: remove anything a previous process left behind. */
  async reset(): Promise<void> {
    for (const writer of this.writers.values()) writer.abort.abort();
    await Promise.all([...this.writers.values()].map((writer) => writer.done));
    this.parts.clear();
    this.bytes = 0;
    for (const key of [...this.waiters.keys()]) this.wakeWaiters(key);
    if (await stat(this.dir).catch(() => null))
      await rm(this.dir, { recursive: true, force: true });
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
  }
}

export class SpoolError extends Error {
  constructor(
    readonly code: string,
    readonly status: 400 | 409 | 413 | 500 | 503,
  ) {
    super(code);
  }
}
