import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import {
  type FileHandle,
  lstat,
  mkdtemp,
  open,
  readdir,
  readlink,
  rm,
  stat as statPath,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WsspError } from "./errors";
import {
  USTAR_BLOCK,
  type UstarEntry,
  UstarPathError,
  ustarHeader,
  ustarPadding,
  ustarTrailer,
} from "./ustar";

/** Default ceiling; the server's `contextMaxBytes` capability may be lower. */
export const BUILD_CONTEXT_DEFAULT_MAX_BYTES = 1024 * 1024 * 1024;

export type PackContextOptions = {
  /**
   * Return false to leave an entry (and, for a directory, everything below
   * it) out of the context. `path` is context-relative with `/` separators.
   */
  filter?: (path: string, kind: "directory" | "file" | "symlink") => boolean;
  /** Refuse a context whose tar is larger than this (default 1 GiB). */
  maxBytes?: number;
  /** Directory for the temporary tar (default: the OS temp directory). */
  tempDir?: string;
  /**
   * Pack even where directory traversal cannot be anchored to open
   * descriptors (no `/proc/self/fd`: every platform but Linux). Without it
   * such a pack is refused with `WsspError` kind `unsupported`, reason
   * `unanchored_context`. With it, entries are resolved by pathname and
   * re-checked: a concurrent attacker on this machine who can write inside
   * the context could swap a directory for a link to outside files and back
   * between an open and its re-check, so outside files could be uploaded.
   * Opt in only when nothing untrusted can write to the context while it is
   * packed.
   */
  allowUnanchoredContext?: boolean;
};

export type PackedContext = {
  /** Temporary tar file; remove it with `dispose()` after the upload. */
  path: string;
  /** Lowercase hex SHA-256 of the tar bytes (`contextSha256`). */
  sha256: string;
  /** Tar size in bytes (`contextBytes`). */
  bytes: number;
  /** Archived entry paths, in archive order (directories end in `/`). */
  entries: string[];
  dispose(): Promise<void>;
};

function invalid(message: string, cause?: unknown): WsspError {
  return new WsspError({ kind: "invalid_request", message, ...(cause ? { cause } : {}) });
}

function unanchored(dir: string): WsspError {
  return new WsspError({
    kind: "unsupported",
    reason: "unanchored_context",
    message:
      `Build context ${dir} cannot be packed safely on this platform: directory ` +
      "traversal cannot be anchored to open descriptors (no /proc/self/fd), so a " +
      "concurrent writer could swap in files from outside the context. Pass " +
      "`allowUnanchoredContext: true` to pack it anyway.",
  });
}

const READ_CHUNK = 1024 * 1024;

/**
 * Pack `dir` into a deterministic ustar archive in a private temp file and
 * hash it. Entries are sorted, timestamps and owners are zeroed, permission
 * bits are kept (setuid/setgid/sticky dropped). Symlinks are archived as
 * links only when their target stays inside `dir`; devices, FIFOs and sockets
 * are refused. No component is ever followed through a symlink: directories
 * are traversed through their open descriptors with their identity checked
 * (see `walk`), files are opened with `O_NOFOLLOW`, and nothing may change
 * identity or size while it is read. Where traversal cannot be anchored to
 * descriptors (no `/proc/self/fd`), packing is refused unless
 * `allowUnanchoredContext` is set (see that option for the residual).
 */
export async function packContext(
  dir: string,
  options: PackContextOptions = {},
): Promise<PackedContext> {
  const maxBytes = options.maxBytes ?? BUILD_CONTEXT_DEFAULT_MAX_BYTES;
  const root = await lstat(dir).catch((cause: unknown) => {
    throw invalid(`Build context ${dir} is not readable.`, cause);
  });
  if (!root.isDirectory()) throw invalid(`Build context ${dir} must be a directory (not a link).`);

  const tempRoot = await mkdtemp(join(options.tempDir ?? tmpdir(), "wssp-context-"));
  const dispose = () => rm(tempRoot, { recursive: true, force: true });
  const path = join(tempRoot, "context.tar");
  const out = await open(
    path,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  const hash = createHash("sha256");
  const entries: string[] = [];
  let bytes = 0;
  const write = async (chunk: Uint8Array) => {
    if (chunk.length === 0) return;
    bytes += chunk.length;
    if (bytes > maxBytes) throw invalid(`Build context is larger than ${maxBytes} bytes.`);
    hash.update(chunk);
    let offset = 0;
    while (offset < chunk.length) {
      const { bytesWritten } = await out.write(chunk, offset, chunk.length - offset);
      offset += bytesWritten;
    }
  };
  const header = (entry: UstarEntry) => {
    try {
      return ustarHeader(entry);
    } catch (error) {
      if (error instanceof UstarPathError) throw invalid(error.message, error);
      throw error;
    }
  };

  /**
   * Traversal is anchored to directory descriptors (Node has no `openat`):
   * every directory is opened `O_DIRECTORY | O_NOFOLLOW` and its identity
   * (dev/ino) checked against the `lstat` taken before the open. On Linux
   * its entries are then read, `lstat`ed and opened through
   * `/proc/self/fd/<fd>/<name>`, which the kernel resolves from the open
   * directory itself, so no ancestor swap can redirect a read. Elsewhere
   * packing is refused unless `allowUnanchoredContext` is set; then the
   * pathname is used and every directory on the current path is re-`lstat`ed
   * after each read and open (and after the directory is done); any change
   * of identity, or a symlink at any component, fails the pack. Residual of
   * that opt-in: an ancestor swapped out and restored between one open and
   * the re-check that follows it is not detected.
   */
  type Dir = { handle: FileHandle; path: string; ref: string; dev: number; ino: number };
  const changed = (relative: string, cause?: unknown) =>
    invalid(`Context entry ${relative || "."} changed while packing.`, cause);
  const sameNode = (a: { dev: number; ino: number }, b: { dev: number; ino: number }) =>
    a.dev === b.dev && a.ino === b.ino;
  const stack: Dir[] = [];
  let anchored = false;
  const recheck = async () => {
    if (anchored) return;
    for (const level of stack) {
      const now = await lstat(level.path).catch((cause: unknown) => {
        throw changed(level.path, cause);
      });
      if (!now.isDirectory() || !sameNode(now, level)) throw changed(level.path);
    }
  };
  const openDir = async (path: string, ref: string, relative: string, expected: Stats) => {
    const handle = await open(
      ref,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    ).catch((cause: unknown) => {
      throw changed(relative, cause);
    });
    try {
      const opened = await handle.stat();
      if (!opened.isDirectory() || !sameNode(opened, expected)) throw changed(relative);
      const anchor = `/proc/self/fd/${handle.fd}`;
      if (stack.length === 0) {
        // Linux: the magic link resolves to this very directory.
        const viaProc = await statPath(anchor).catch(() => null);
        anchored = viaProc?.isDirectory() === true && sameNode(viaProc, opened);
        if (!anchored && options.allowUnanchoredContext !== true) throw unanchored(path);
      }
      const level: Dir = {
        handle,
        path,
        ref: anchored ? anchor : path,
        dev: opened.dev,
        ino: opened.ino,
      };
      stack.push(level);
      await recheck();
      return level;
    } catch (error) {
      await handle.close();
      throw error;
    }
  };
  const closeDir = async (level: Dir, relative: string) => {
    try {
      // The directory must still be the one that was read, at its place.
      const now = await lstat(level.path).catch((cause: unknown) => {
        throw changed(relative, cause);
      });
      if (!now.isDirectory() || !sameNode(now, level)) throw changed(relative);
    } finally {
      stack.pop();
      await level.handle.close();
    }
  };

  const copyFile = async (ref: string, relative: string, stat: Stats) => {
    // O_NONBLOCK: a file swapped for a FIFO must not block the open.
    const handle = await open(
      ref,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    ).catch((cause: unknown) => {
      throw changed(relative, cause);
    });
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || !sameNode(opened, stat))
        throw invalid(`Context file ${relative} changed while packing.`);
      await recheck();
      await write(header({ type: "file", path: relative, mode: opened.mode, size: opened.size }));
      const buffer = new Uint8Array(Math.min(READ_CHUNK, Math.max(opened.size, 1)));
      let remaining = opened.size;
      while (remaining > 0) {
        const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, remaining));
        if (bytesRead === 0) throw invalid(`Context file ${relative} shrank while packing.`);
        await write(buffer.subarray(0, bytesRead));
        remaining -= bytesRead;
      }
      const { bytesRead: extra } = await handle.read(buffer, 0, 1);
      if (extra !== 0) throw invalid(`Context file ${relative} grew while packing.`);
      await write(ustarPadding(opened.size));
    } finally {
      await handle.close();
    }
  };

  const walk = async (level: Dir, relativeDir: string) => {
    const names = (await readdir(level.ref)).sort();
    await recheck();
    for (const name of names) {
      const ref = join(level.ref, name);
      const path = join(level.path, name);
      const relative = relativeDir === "" ? name : `${relativeDir}/${name}`;
      const stat = await lstat(ref);
      await recheck();
      if (stat.isDirectory()) {
        if (options.filter && !options.filter(relative, "directory")) continue;
        await write(header({ type: "directory", path: relative, mode: stat.mode }));
        entries.push(`${relative}/`);
        const child = await openDir(path, ref, relative, stat);
        try {
          await walk(child, relative);
        } finally {
          await closeDir(child, relative);
        }
      } else if (stat.isFile()) {
        if (options.filter && !options.filter(relative, "file")) continue;
        await copyFile(ref, relative, stat);
        entries.push(relative);
      } else if (stat.isSymbolicLink()) {
        if (options.filter && !options.filter(relative, "symlink")) continue;
        const target = await readlink(ref);
        await recheck();
        await write(header({ type: "symlink", path: relative, target }));
        entries.push(relative);
      } else {
        throw invalid(`Context entry ${relative} is not a file, directory or symlink.`);
      }
    }
  };

  try {
    const top = await openDir(dir, dir, "", root);
    try {
      await walk(top, "");
    } finally {
      await closeDir(top, "");
    }
    await write(ustarTrailer());
    await out.sync();
  } catch (error) {
    await out.close().catch(() => undefined);
    await dispose();
    throw error;
  }
  await out.close();
  if (bytes % USTAR_BLOCK !== 0) throw new Error("ustar writer produced a partial block");
  return { path, sha256: hash.digest("hex"), bytes, entries, dispose };
}
