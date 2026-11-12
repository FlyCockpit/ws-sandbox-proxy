import type { LoginDefinition } from "./definition";
import { LOGIN_DEFINITION_LIMITS as L } from "./limits";
import { pathProblem, pathWithin } from "./paths";
import { compareBytes, utf8 } from "./text";

/**
 * Bundle v1: the in-memory, never-persisted plaintext of one credential value.
 * All integers are big-endian (network order).
 *
 * ```
 * header     : "WSCB"(4) | u8 version=1 | definitionDigest[32] | u16 fileCount | u16 envCount  = 41 bytes
 * file entry : u8 kind(1=file,2=dir) | u16 mode | u16 pathLen | path | u32 dataLen | data     = 9 + pathLen + dataLen
 * env entry  : u8 nameLen | name | u16 valueLen | value                                        = 3 + nameLen + valueLen
 * ```
 *
 * The encoding is canonical: files are in strictly ascending path byte order,
 * env entries in strictly ascending name order, file modes are exactly 0600
 * or 0700 and directory modes exactly 0700. The decoder refuses anything else,
 * so one value has exactly one encoding. Shared with `crates/login-definition`.
 */
export const BUNDLE_MAGIC = utf8("WSCB");
export const BUNDLE_VERSION = 1;
export const BUNDLE_KIND_FILE = 1;
export const BUNDLE_KIND_DIR = 2;
export const BUNDLE_FILE_MODES = [0o600, 0o700] as const;
export const BUNDLE_DIR_MODE = 0o700;

export type BundleFile =
  | { kind: "file"; path: string; mode: number; data: Uint8Array }
  | { kind: "dir"; path: string; mode: number };
export type BundleEnv = { name: string; value: Uint8Array };
export type Bundle = { definitionDigest: Uint8Array; files: BundleFile[]; env: BundleEnv[] };

export const BUNDLE_ERROR_REASONS = [
  "truncated",
  "bad_magic",
  "unsupported_version",
  "digest_mismatch",
  "file_count",
  "env_count",
  "bad_kind",
  "bad_mode",
  "path_length",
  "path_total",
  "invalid_path",
  "unsorted_path",
  "duplicate_path",
  "undeclared_path",
  "excluded_path",
  "under_file",
  "dir_has_data",
  "data_total",
  "env_name_length",
  "unsorted_env",
  "duplicate_env",
  "undeclared_env",
  "env_value_length",
  "env_value_nul",
  "trailing_bytes",
] as const;
export type BundleErrorReason = (typeof BUNDLE_ERROR_REASONS)[number];

/** Never carries bundle bytes, paths' contents or values: only the failed rule. */
export class BundleError extends Error {
  /** `path`: the offending file entry's path when one is known (non-secret). */
  constructor(
    readonly reason: BundleErrorReason,
    readonly path?: string,
  ) {
    super(`invalid credential bundle: ${reason}${path === undefined ? "" : ` (${path})`}`);
    this.name = "BundleError";
  }
}

/** File modes keep only the owner execute bit; directories are always 0700. */
export function normalizeMode(kind: BundleFile["kind"], mode: number): number {
  if (kind === "dir") return BUNDLE_DIR_MODE;
  return mode & 0o100 ? 0o700 : 0o600;
}

/** Serializes entries exactly as given, without any validation (vectors and tests). */
export function serializeBundleUnchecked(bundle: Bundle): Uint8Array {
  const paths = bundle.files.map((f) => utf8(f.path));
  const names = bundle.env.map((e) => utf8(e.name));
  let size = L.bundleHeaderBytes;
  bundle.files.forEach((f, i) => {
    size += 9 + (paths[i]?.length ?? 0) + (f.kind === "file" ? f.data.length : 0);
  });
  bundle.env.forEach((e, i) => {
    size += 3 + (names[i]?.length ?? 0) + e.value.length;
  });
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let at = 0;
  const put = (bytes: Uint8Array) => {
    out.set(bytes, at);
    at += bytes.length;
  };
  put(BUNDLE_MAGIC);
  view.setUint8(at++, BUNDLE_VERSION);
  put(bundle.definitionDigest);
  view.setUint16(at, bundle.files.length);
  view.setUint16(at + 2, bundle.env.length);
  at += 4;
  bundle.files.forEach((f, i) => {
    const path = paths[i] ?? new Uint8Array();
    const data = f.kind === "file" ? f.data : new Uint8Array();
    view.setUint8(at, f.kind === "file" ? BUNDLE_KIND_FILE : BUNDLE_KIND_DIR);
    view.setUint16(at + 1, f.mode);
    view.setUint16(at + 3, path.length);
    at += 5;
    put(path);
    view.setUint32(at, data.length);
    at += 4;
    put(data);
  });
  bundle.env.forEach((e, i) => {
    const name = names[i] ?? new Uint8Array();
    view.setUint8(at++, name.length);
    put(name);
    view.setUint16(at, e.value.length);
    at += 2;
    put(e.value);
  });
  return out;
}

/**
 * Encodes a bundle canonically (sorted, modes normalized) and validates the
 * result with the decoder, so every encoded bundle decodes.
 */
export function encodeBundle(bundle: Bundle, definition: LoginDefinition): Uint8Array {
  const files = bundle.files
    .map((f) => ({ ...f, mode: normalizeMode(f.kind, f.mode) }))
    .sort((a, b) => compareBytes(utf8(a.path), utf8(b.path)));
  const env = [...bundle.env].sort((a, b) => compareBytes(utf8(a.name), utf8(b.name)));
  const bytes = serializeBundleUnchecked({ definitionDigest: bundle.definitionDigest, files, env });
  decodeBundle(bytes, definition, bundle.definitionDigest);
  return bytes;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Decodes and validates a bundle against its verified definition. Throws `BundleError`. */
export function decodeBundle(
  bytes: Uint8Array,
  definition: LoginDefinition,
  expectedDigest: Uint8Array,
): Bundle {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 0;
  const need = (n: number) => {
    if (bytes.length - at < n) throw new BundleError("truncated");
  };
  const take = (n: number) => {
    need(n);
    const slice = bytes.subarray(at, at + n);
    at += n;
    return slice;
  };

  need(L.bundleHeaderBytes);
  if (compareBytes(take(4), BUNDLE_MAGIC) !== 0) throw new BundleError("bad_magic");
  if (view.getUint8(at++) !== BUNDLE_VERSION) throw new BundleError("unsupported_version");
  const digest = take(32);
  if (expectedDigest.length !== 32 || compareBytes(digest, expectedDigest) !== 0) {
    throw new BundleError("digest_mismatch");
  }
  const fileCount = view.getUint16(at);
  const envCount = view.getUint16(at + 2);
  at += 4;
  if (fileCount > L.bundleFileCountMax) throw new BundleError("file_count");
  if (envCount > L.bundleEnvCountMax) throw new BundleError("env_count");

  const declared = [
    ...(definition.credentials.files?.required ?? []),
    ...(definition.credentials.files?.optional ?? []),
  ];
  const excluded = definition.credentials.files?.exclude ?? [];
  const maxData = definition.credentials.maxBytes;
  const filePaths = new Set<string>();
  const files: BundleFile[] = [];
  let pathTotal = 0;
  let dataTotal = 0;
  let previous: Uint8Array | null = null;
  for (let i = 0; i < fileCount; i++) {
    need(5);
    const kindByte = view.getUint8(at);
    const mode = view.getUint16(at + 1);
    const pathLen = view.getUint16(at + 3);
    at += 5;
    if (kindByte !== BUNDLE_KIND_FILE && kindByte !== BUNDLE_KIND_DIR) {
      throw new BundleError("bad_kind");
    }
    const kind = kindByte === BUNDLE_KIND_FILE ? "file" : "dir";
    const modeOk =
      kind === "file"
        ? (BUNDLE_FILE_MODES as readonly number[]).includes(mode)
        : mode === BUNDLE_DIR_MODE;
    if (!modeOk) throw new BundleError("bad_mode");
    if (pathLen > L.bundlePathMaxBytes) throw new BundleError("path_length");
    pathTotal += pathLen;
    if (pathTotal > L.bundlePathTotalMaxBytes) throw new BundleError("path_total");
    const rawPath = take(pathLen);
    let path: string;
    try {
      path = strictUtf8.decode(rawPath);
    } catch {
      throw new BundleError("invalid_path");
    }
    if (pathProblem(path, L.bundlePathMaxBytes)) throw new BundleError("invalid_path", path);
    if (previous) {
      const order = compareBytes(previous, rawPath);
      if (order === 0) throw new BundleError("duplicate_path", path);
      if (order > 0) throw new BundleError("unsorted_path", path);
    }
    previous = rawPath;
    if (!declared.some((d) => pathWithin(path, d))) throw new BundleError("undeclared_path", path);
    if (excluded.some((e) => pathWithin(path, e))) throw new BundleError("excluded_path", path);
    for (let slash = path.indexOf("/"); slash !== -1; slash = path.indexOf("/", slash + 1)) {
      if (filePaths.has(path.slice(0, slash))) throw new BundleError("under_file", path);
    }
    need(4);
    const dataLen = view.getUint32(at);
    at += 4;
    if (kind === "dir" && dataLen !== 0) throw new BundleError("dir_has_data", path);
    dataTotal += dataLen;
    if (dataTotal > maxData) throw new BundleError("data_total");
    const data = take(dataLen);
    if (kind === "file") {
      filePaths.add(path);
      files.push({ kind, path, mode, data });
    } else {
      files.push({ kind, path, mode });
    }
  }

  const envNames = new Set((definition.credentials.env ?? []).map((e) => e.name));
  const env: BundleEnv[] = [];
  let previousName: Uint8Array | null = null;
  for (let i = 0; i < envCount; i++) {
    need(1);
    const nameLen = view.getUint8(at++);
    if (nameLen > L.envNameMaxBytes) throw new BundleError("env_name_length");
    const rawName = take(nameLen);
    if (previousName) {
      const order = compareBytes(previousName, rawName);
      if (order === 0) throw new BundleError("duplicate_env");
      if (order > 0) throw new BundleError("unsorted_env");
    }
    previousName = rawName;
    let name: string;
    try {
      name = strictUtf8.decode(rawName);
    } catch {
      throw new BundleError("undeclared_env");
    }
    if (!envNames.has(name)) throw new BundleError("undeclared_env");
    need(2);
    const valueLen = view.getUint16(at);
    at += 2;
    if (valueLen > L.envValueMaxBytes) throw new BundleError("env_value_length");
    const value = take(valueLen);
    if (value.includes(0)) throw new BundleError("env_value_nul");
    env.push({ name, value });
  }
  if (at !== bytes.length) throw new BundleError("trailing_bytes");
  return { definitionDigest: digest, files, env };
}

/** Required paths with no entry at or below them (a capture missing them is incomplete). */
export function missingRequiredPaths(bundle: Bundle, definition: LoginDefinition): string[] {
  return (definition.credentials.files?.required ?? []).filter(
    (required) => !bundle.files.some((f) => pathWithin(f.path, required)),
  );
}
