import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, type FileHandle, lstat, mkdir, open } from "node:fs/promises";
import { dirname, join, parse } from "node:path";
import { TRANSFER_CHUNK_BYTES } from "@wssp/sandbox-contracts";
import { transferError } from "./limits.js";

/**
 * Spool file IO shared by the transfer store and the build-context store
 *. Each store owns its own root directory; these
 * helpers carry no state and never decide what a name means. Extracted from
 * `store.ts` without behaviour change.
 */

export const digest = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
export const missing = (e: unknown) => e instanceof Error && "code" in e && e.code === "ENOENT";
export const storageFailure = (error: unknown) =>
  error instanceof Error &&
  "code" in error &&
  [
    "TRANSFER_IO",
    "ENOSPC",
    "EIO",
    "EROFS",
    "EACCES",
    "EPERM",
    "ELOOP",
    "ENOENT",
    "ENOTDIR",
    "EISDIR",
  ].includes(String(error.code));

/**
 * Creates every missing component of `root` (0700, parent fsync) and refuses a
 * symlink or non-directory in any component. No request chooses this path.
 * Returns the root's `dev:ino` identity, which later checks pin.
 */
export async function createSpoolRoot(root: string): Promise<string> {
  let current = parse(root).root;
  for (const part of root.slice(current.length).split("/")) {
    current = join(current, part);
    try {
      await mkdir(current, { mode: 0o700 });
      const parent = await open(
        dirname(current),
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "EEXIST")) throw error;
    }
    const stat = await lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw transferError("TRANSFER_IO");
  }
  const stat = await lstat(root);
  return `${stat.dev}:${stat.ino}`;
}

/** The root is our own 0700 directory (not a symlink) and still the one we
 * started with. `identity` null checks everything except the pinned identity
 * (a sibling store's root, validated by shape only). */
export async function checkSpoolRoot(root: string, identity: string | null) {
  const stat = await lstat(root);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid?.() ||
    (stat.mode & 0o777) !== 0o700 ||
    (identity !== null && `${stat.dev}:${stat.ino}` !== identity)
  )
    throw transferError("TRANSFER_IO");
  await access(root, constants.W_OK);
}

export async function syncSpoolRoot(root: string, identity: string | null) {
  await checkSpoolRoot(root, identity);
  const handle = await open(
    root,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/** Refuses anything but our own private regular file with exactly one name. */
export function checkSpoolStat(
  stat: { isFile(): boolean; nlink: number; uid: number; mode: number },
  links = 1,
) {
  if (
    !stat.isFile() ||
    stat.nlink !== links ||
    stat.uid !== process.getuid?.() ||
    (stat.mode & 0o077) !== 0
  )
    throw transferError("TRANSFER_IO");
}

/**
 * Opens one spool file read-write without following a symlink. `create`:
 * `"exclusive"` must create it, `"allow"` creates it when absent.
 */
export async function openSpoolFile(
  root: string,
  identity: string | null,
  path: string,
  create: "exclusive" | "allow" | false = false,
) {
  await checkSpoolRoot(root, identity);
  const file = await open(
    path,
    constants.O_RDWR |
      constants.O_NOFOLLOW |
      constants.O_NONBLOCK |
      (create === "exclusive"
        ? constants.O_CREAT | constants.O_EXCL
        : create === "allow"
          ? constants.O_CREAT
          : 0),
    0o600,
  );
  try {
    checkSpoolStat(await file.stat());
    return file;
  } catch (error) {
    await file.close();
    throw error;
  }
}

/** Writes all of `bytes` at `position`; a zero-byte write is an IO failure. */
export async function writeFully(file: FileHandle, bytes: Uint8Array, position: number) {
  let written = 0;
  while (written < bytes.byteLength) {
    const result = await file.write(bytes, written, bytes.byteLength - written, position + written);
    if (result.bytesWritten <= 0) throw transferError("TRANSFER_IO");
    written += result.bytesWritten;
  }
}

/** Reads exactly `bytes.length` bytes at `position`; EOF is an IO failure. */
export async function readFully(file: FileHandle, bytes: Buffer, position: number) {
  let read = 0;
  while (read < bytes.length) {
    const next = await file.read(bytes, read, bytes.length - read, position + read);
    if (!next.bytesRead) throw transferError("TRANSFER_IO");
    read += next.bytesRead;
  }
  return bytes;
}

/** Whole-content SHA-256 of the first `size` bytes. */
export async function hashSpoolFile(file: FileHandle, size: number) {
  const whole = createHash("sha256");
  const buffer = Buffer.alloc(TRANSFER_CHUNK_BYTES);
  for (let offset = 0; offset < size; ) {
    const { bytesRead } = await file.read(
      buffer,
      0,
      Math.min(buffer.length, size - offset),
      offset,
    );
    if (!bytesRead) throw transferError("TRANSFER_IO");
    whole.update(buffer.subarray(0, bytesRead));
    offset += bytesRead;
  }
  return whole.digest("hex");
}

/**
 * Restart verification: every acknowledged byte matches its durable
 * fixed-grid chunk digest, then the unacknowledged tail is cut and synced.
 * `chunkAt` returns the recorded chunk at an offset, or null.
 */
export async function verifyAcknowledged(
  file: FileHandle,
  receivedBytes: number,
  totalBytes: number,
  chunkAt: (offset: number) => Promise<{ length: number; digest: string } | null>,
) {
  if ((await file.stat()).size < receivedBytes) throw transferError("TRANSFER_IO");
  for (let offset = 0; offset < receivedBytes; offset += TRANSFER_CHUNK_BYTES) {
    const chunk = await chunkAt(offset);
    if (!chunk || chunk.length !== Math.min(TRANSFER_CHUNK_BYTES, totalBytes - offset))
      throw transferError("TRANSFER_IO");
    const bytes = await readFully(file, Buffer.alloc(chunk.length), offset);
    if (digest(bytes) !== chunk.digest) throw transferError("TRANSFER_IO");
  }
  await file.truncate(receivedBytes);
  await file.sync();
}

/** Why a staged import source was refused (`TransferStore.importSealed`). */
export type ImportSourceReason = "missing" | "invalid" | "linked";
export class ImportSourceError extends Error {
  constructor(readonly reason: ImportSourceReason) {
    super(`Import source refused: ${reason}`);
    this.name = "ImportSourceError";
  }
}

const SOURCE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * Opens a sibling store's staged file for adoption with the transfer store's
 * own file checks: the root passes the
 * directory checks, the name is one plain component, the open never follows a
 * symlink, and the file is our private regular file with exactly one name and
 * exactly `size` bytes. `linked` (a second name still exists) is transient;
 * `missing` and `invalid` are final.
 */
export async function openImportSource(root: string, name: string, size: number) {
  if (!SOURCE_NAME.test(name) || name.includes("..")) throw new ImportSourceError("invalid");
  try {
    await checkSpoolRoot(root, null);
  } catch {
    throw new ImportSourceError("invalid");
  }
  let file: FileHandle;
  try {
    file = await open(
      join(root, name),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
  } catch (error) {
    throw new ImportSourceError(missing(error) ? "missing" : "invalid");
  }
  try {
    const stat = await file.stat();
    if (stat.isFile() && stat.nlink > 1) throw new ImportSourceError("linked");
    try {
      checkSpoolStat(stat);
    } catch {
      throw new ImportSourceError("invalid");
    }
    if (stat.size !== size) throw new ImportSourceError("invalid");
    return { file, stat };
  } catch (error) {
    await file.close();
    throw error;
  }
}
