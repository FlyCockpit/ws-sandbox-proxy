import { z } from "zod";
import vmLimits from "./vm-size-limits.json";

/**
 * Relay 1.0 additive image frames. Mirrors `crates/sandbox-protocol/src/image.rs`;
 * `crates/sandbox-protocol/fixtures/control_image.json` is the shared fixture.
 * The disk offload frames at the end mirror `crates/sandbox-protocol/src/disk.rs`
 * (`fixtures/control_disk.json`).
 */
export const IMAGE_CENSUS_PAGE_MAX = 256;
export const IMAGE_CENSUS_OWNERS_MAX = 16;
export const IMAGE_LINKS_MAX = 16;
export const IMAGE_UPLOAD_PARTS_MAX = 64;
export const IMAGE_CAPTURE_MARKERS_MAX = 16;
export const CAPTURE_SCRUB_PATHS_MAX = 80;
export const IMAGE_RELAY_PART_BYTES = 32 * 1024 * 1024;
export const IMAGE_S3_PART_BYTES = 64 * 1024 * 1024;
export const IMAGE_ENCRYPTION_RECORD_BYTES = 1024 * 1024;
export const IMAGE_ENCRYPTION_TAG_BYTES = 16;
export const IMAGE_ENCRYPTION_SCHEME = "aes256gcm-r1";
export const IMAGE_SIZE_MAX = 2 ** 40;
/** Bound on a heartbeat's `wireBytes`: every part of the largest stored
 * object sent 8 times (the daemon sends a part at most 4 times). */
export const IMAGE_WIRE_BYTES_MAX = IMAGE_SIZE_MAX * 2 * 8;

/** Longest presigned URL lifetime a grant may carry (S3's own bound). */
const IMAGE_UPLOAD_TTL_MAX_SECONDS = 7 * 24 * 3600;
/** S3's bound on parts per multipart upload. */
export const S3_PARTS_MAX = 10_000;
/** Smallest upload part, in 1 MiB records (16 MiB: S3 needs >= 5 MiB but the last). */
const IMAGE_UPLOAD_PART_RECORDS_MIN = 16;

/**
 * Stored bytes per part of a template upload session of `plain` image bytes
 * (docs/operations/templates.md#capture): whole 1 MiB records,
 * `max(16, ceil(records / 10 000))` of them, so a part is 16 MiB normally
 * (short enough to finish, and cheap to retry, on a slow uplink) and an image
 * up to `IMAGE_SIZE_MAX` still fits S3's 10 000 parts. Encrypted parts are
 * whole sealed records (record + tag each).
 */
export function imageUploadPartBytes(plain: number, encrypted: boolean): number {
  const records = Math.max(1, Math.ceil(plain / IMAGE_ENCRYPTION_RECORD_BYTES));
  const perPart = Math.max(IMAGE_UPLOAD_PART_RECORDS_MIN, Math.ceil(records / S3_PARTS_MAX));
  return (
    perPart *
    (encrypted
      ? IMAGE_ENCRYPTION_RECORD_BYTES + IMAGE_ENCRYPTION_TAG_BYTES
      : IMAGE_ENCRYPTION_RECORD_BYTES)
  );
}

/** Ciphertext length of an `aes256gcm-r1` object for `plain` bytes. */
export function encryptedImageLength(plain: number): number {
  const records = Math.max(1, Math.ceil(plain / IMAGE_ENCRYPTION_RECORD_BYTES));
  return plain + records * IMAGE_ENCRYPTION_TAG_BYTES;
}

export const imageFingerprintSchema = z.string().regex(/^sha256:[0-9a-f]{64}$/);
const idSchema = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);
const sizeSchema = z.number().int().min(1).max(IMAGE_SIZE_MAX);
const totalBytesSchema = z
  .number()
  .int()
  .min(0)
  .max(IMAGE_SIZE_MAX * 8);
const partNumberSchema = z.number().int().min(1).max(10_000);
const codeSchema = z.string().regex(/^[a-z_.]{1,64}$/);
/** A host report that stays durable until acknowledged (`report.ack`):
 * random per report, so a repeat names the same report. */
const reportIdSchema = z.string().regex(/^[0-9a-f]{32}$/);
const urlSchema = z
  .string()
  .max(8192)
  .refine((value) => value.startsWith("https://") || value.startsWith("http://"));

export const imageCapabilitiesV11Schema = z
  .strictObject({
    fetch: z.boolean(),
    serve: z.boolean(),
    publish: z.boolean(),
    capture: z.boolean(),
    acceptForeign: z.boolean(),
    leaseFromReady: z.boolean(),
    formats: z.array(z.literal("unified")).min(1).max(4),
    /** Template builds (omitted while false); requires `capture`. */
    build: z.boolean().optional(),
    /** Builds for other accounts (omitted while false); requires `build`. */
    acceptForeignBuilds: z.boolean().optional(),
  })
  .refine(
    (value) => (!value.build || value.capture) && (!value.acceptForeignBuilds || value.build),
    "build capabilities require capture",
  );
export type ImageCapabilitiesV11 = z.infer<typeof imageCapabilitiesV11Schema>;

export const imageAdmissionV11Schema = z
  .strictObject({
    capBytes: totalBytesSchema,
    usedBytes: totalBytesSchema,
    foreignUsedBytes: totalBytesSchema,
    captureStorageMarkers: z.array(z.string().min(1).max(128)).max(IMAGE_CAPTURE_MARKERS_MAX),
  })
  .refine((value) => value.foreignUsedBytes <= value.usedBytes);
export type ImageAdmissionV11 = z.infer<typeof imageAdmissionV11Schema>;

/** The only host a daemon downloads upstream images from; paths are relative to it. */
export const UPSTREAM_IMAGE_BASE_URL = "https://images.linuxcontainers.org/";
/** Largest upstream metadata file (`incus.tar.xz`). */
export const UPSTREAM_META_MAX_BYTES = 1024 * 1024;
/** Largest upstream disk file (`disk.qcow2`). */
export const UPSTREAM_DISK_MAX_BYTES = 4 * 1024 * 1024 * 1024;
export const UPSTREAM_PATH_MAX_BYTES = 512;
export const UPSTREAM_META_FILE = "incus.tar.xz";
export const UPSTREAM_DISK_FILE = "disk.qcow2";

const UPSTREAM_SEGMENT = /^[A-Za-z0-9._:+-]+$/;

/**
 * An upstream path relative to {@link UPSTREAM_IMAGE_BASE_URL}: at most
 * {@link UPSTREAM_PATH_MAX_BYTES}, starting with `images/`, every segment
 * non-empty, `[A-Za-z0-9._:+-]` only, and neither `.` nor `..`.
 */
export function validUpstreamImagePath(path: string): boolean {
  return (
    path.length <= UPSTREAM_PATH_MAX_BYTES &&
    path.startsWith("images/") &&
    path
      .split("/")
      .every((segment) => UPSTREAM_SEGMENT.test(segment) && segment !== "." && segment !== "..")
  );
}

const sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/);

/**
 * The two files of an upstream split VM image (mirrors
 * `DispatchUpstreamImageV11` in `crates/sandbox-protocol/src/image.rs`):
 * same directory, fixed basenames, per-file sha256 and size.
 */
export const dispatchUpstreamImageV11Schema = z
  .strictObject({
    metaPath: z.string().refine(validUpstreamImagePath, "invalid upstream path"),
    metaSha256: sha256HexSchema,
    metaSize: z.number().int().min(1).max(UPSTREAM_META_MAX_BYTES),
    diskPath: z.string().refine(validUpstreamImagePath, "invalid upstream path"),
    diskSha256: sha256HexSchema,
    diskSize: z.number().int().min(1).max(UPSTREAM_DISK_MAX_BYTES),
  })
  .refine((value) => {
    const meta = value.metaPath.lastIndexOf("/");
    const disk = value.diskPath.lastIndexOf("/");
    return (
      value.metaPath.slice(0, meta) === value.diskPath.slice(0, disk) &&
      value.metaPath.slice(meta + 1) === UPSTREAM_META_FILE &&
      value.diskPath.slice(disk + 1) === UPSTREAM_DISK_FILE
    );
  }, "upstream files must share one directory and the fixed file names");
export type DispatchUpstreamImageV11 = z.infer<typeof dispatchUpstreamImageV11Schema>;

/**
 * Exactly one of: a `unified` image fetched through the control plane, or a
 * raw `split` upstream image the daemon downloads itself. The fingerprint of
 * a split image is sha256(meta || disk). An upstream plan rides only on a
 * create whose build carries `bootstrap` (see `validDispatchImageFields`).
 */
export const dispatchImageV11Schema = z.union([
  z.strictObject({
    fingerprint: imageFingerprintSchema,
    sizeBytes: sizeSchema,
    format: z.literal("unified"),
    source: z.literal("fetch"),
  }),
  z
    .strictObject({
      fingerprint: imageFingerprintSchema,
      sizeBytes: sizeSchema,
      format: z.literal("split"),
      source: z.literal("upstream"),
      upstream: dispatchUpstreamImageV11Schema,
    })
    .refine(
      (value) => value.sizeBytes === value.upstream.metaSize + value.upstream.diskSize,
      "sizeBytes must equal metaSize + diskSize",
    ),
]);
export type DispatchImageV11 = z.infer<typeof dispatchImageV11Schema>;

/**
 * Dispatch-level image rules: a plan rides only on `sandbox.create` (or a
 * restoring `sandbox.reconnect`, whose stored disk it fetches; the disk rules
 * pin its fingerprint), and an upstream plan only when the same dispatch's
 * build carries `bootstrap`.
 */
export function validDispatchImageFields(dispatch: {
  kind: string;
  image?: unknown;
  build?: unknown;
  restore?: unknown;
}): boolean {
  if (dispatch.image === undefined) return true;
  const image = dispatchImageV11Schema.safeParse(dispatch.image);
  if (!image.success) return false;
  if (dispatch.kind === "sandbox.reconnect")
    return dispatch.restore !== undefined && image.data.format === "unified";
  if (dispatch.kind !== "sandbox.create") return false;
  if (image.data.format !== "split") return true;
  const build = dispatch.build as { bootstrap?: unknown } | undefined;
  return typeof build === "object" && build !== null && build.bootstrap === true;
}

/** Absolute normalized guest path; `*` only within the last segment. */
export function validScrubPath(path: string): boolean {
  if (path.length < 2 || path.length > 256 || !path.startsWith("/") || path.includes("\0"))
    return false;
  const segments = path.slice(1).split("/");
  return segments.every(
    (segment, index) =>
      segment.length > 0 &&
      segment !== "." &&
      segment !== ".." &&
      (index === segments.length - 1 || !segment.includes("*")),
  );
}
export const scrubPathSchema = z.string().refine(validScrubPath, "invalid scrub path");

export const dispatchCaptureV11Schema = z.strictObject({
  scrubPaths: z.array(scrubPathSchema).max(CAPTURE_SCRUB_PATHS_MAX),
  stopped: z.boolean(),
  upload: z.boolean(),
});
export type DispatchCaptureV11 = z.infer<typeof dispatchCaptureV11Schema>;

export const PROGRESS_PHASES = [
  "fetching_image",
  "importing_image",
  "freezing",
  "snapshotting",
  "copying",
  "scrubbing",
  "publishing",
  "uploading",
  // Disk offload and restore (§8).
  "exporting_disk",
  "uploading_disk",
  "fetching_disk",
  "importing_disk",
] as const;
export type ProgressPhase = (typeof PROGRESS_PHASES)[number];
export const operationProgressV11Schema = z.strictObject({
  phase: z.enum(PROGRESS_PHASES),
  bytesDone: z
    .number()
    .int()
    .min(0)
    .max(IMAGE_SIZE_MAX * 2)
    .optional(),
  bytesTotal: z
    .number()
    .int()
    .min(0)
    .max(IMAGE_SIZE_MAX * 2)
    .optional(),
});

const originSchema = z.enum(["fetched", "captured", "replica"]);
const failureCodeSchema = z.enum([
  "corrupt",
  "rejected",
  "io",
  "cache_full",
  "timeout",
  "format_unsupported",
  "cancelled",
]);
export type ImageFailureCode = z.infer<typeof failureCodeSchema>;
/** Why a host-side upload or export ended (Rust `ImageFailureCause`). */
export const IMAGE_FAILURE_CAUSES = [
  "timeout",
  "stalled",
  "reset",
  "connect",
  "tls",
  "http_status",
  "url_expired",
  "local_io",
  "export",
  "no_grant",
  "refused",
  "protocol",
] as const;
export type ImageFailureCause = (typeof IMAGE_FAILURE_CAUSES)[number];
const roleSchema = z.enum(["SOURCE", "DEST"]);
const totalsSchema = z
  .strictObject({ usedBytes: totalBytesSchema, foreignBytes: totalBytesSchema })
  .refine((totals) => totals.foreignBytes <= totals.usedBytes);

/** Daemon → server image frames (members of the daemon discriminated union). */
export const daemonImageMessageSchemas = [
  z.strictObject({
    type: z.literal("image.fetch.request"),
    requestId: idSchema,
    operationId: idSchema,
    sandboxId: idSchema,
    generation: z.number().int().min(1),
    attempt: z.number().int().min(0),
    fingerprint: imageFingerprintSchema,
    resumeOffset: z.number().int().min(0).max(IMAGE_SIZE_MAX),
  }),
  z
    .strictObject({
      type: z.literal("image.cached"),
      fingerprint: imageFingerprintSchema,
      imageOwnerId: idSchema,
      transferId: idSchema.optional(),
      operationId: idSchema.optional(),
      compressedBytes: sizeSchema,
      unpackedBytes: z.number().int().min(0).optional(),
      origin: originSchema,
      totals: totalsSchema,
    })
    .refine((frame) => (frame.transferId === undefined) !== (frame.operationId === undefined)),
  z.strictObject({
    type: z.literal("image.evicted"),
    fingerprint: imageFingerprintSchema,
    imageOwnerId: idSchema,
    reason: z.enum(["lru", "access_lost", "released", "operator", "corrupt"]),
    totals: totalsSchema,
  }),
  z
    .strictObject({
      type: z.literal("image.fetch.failed"),
      requestId: idSchema.optional(),
      transferId: idSchema.optional(),
      fingerprint: imageFingerprintSchema,
      code: failureCodeSchema,
    })
    .refine((frame) => frame.requestId !== undefined || frame.transferId !== undefined),
  z.strictObject({
    type: z.literal("image.cache.census"),
    page: z.number().int().min(0).max(4096),
    complete: z.boolean(),
    entries: z
      .array(
        z.strictObject({
          fingerprint: imageFingerprintSchema,
          owners: z.array(idSchema).min(1).max(IMAGE_CENSUS_OWNERS_MAX),
          compressedBytes: sizeSchema,
          unpackedBytes: z.number().int().min(0).optional(),
          origin: originSchema,
          pinned: z.boolean(),
        }),
      )
      .max(IMAGE_CENSUS_PAGE_MAX),
    totals: totalsSchema,
  }),
  z.strictObject({
    type: z.literal("image.links.request"),
    transferId: idSchema,
    role: roleSchema,
    parts: z.array(partNumberSchema).min(1).max(IMAGE_LINKS_MAX),
  }),
  z.strictObject({
    type: z.literal("image.part.ack"),
    transferId: idSchema,
    part: partNumberSchema,
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
  }),
  z
    .strictObject({
      type: z.literal("image.upload.begin"),
      transferId: idSchema.optional(),
      operationId: idSchema.optional(),
      // Capture only (round-3 P2-2/P2-4): the daemon's request id, echoed on
      // the answering grant or cancel, and the originating dispatch attempt.
      requestId: idSchema.optional(),
      attempt: z.number().int().min(0).optional(),
      fingerprint: imageFingerprintSchema,
      sizeBytes: sizeSchema,
      unpackedBytes: z.number().int().min(0).optional(),
      format: z.literal("unified"),
    })
    .refine((frame) =>
      frame.transferId !== undefined
        ? frame.operationId === undefined &&
          frame.requestId === undefined &&
          frame.attempt === undefined
        : frame.operationId !== undefined &&
          frame.requestId !== undefined &&
          frame.attempt !== undefined,
    ),
  z.strictObject({
    type: z.literal("image.upload.parts"),
    transferId: idSchema,
    parts: z
      .array(
        z.strictObject({
          n: partNumberSchema,
          etag: z.string().regex(/^[\x21-\x7e]{1,256}$/),
        }),
      )
      .min(1)
      .max(IMAGE_UPLOAD_PARTS_MAX),
  }),
  z.strictObject({
    type: z.literal("image.upload.complete"),
    transferId: idSchema,
    reportId: reportIdSchema.optional(),
  }),
  // Exactly one reference: the transfer, or (a capture upload before its
  // first grant) its operation and dispatch attempt, as SOURCE with nothing
  // done.
  z
    .strictObject({
      type: z.literal("image.job.resume"),
      transferId: idSchema.optional(),
      operationId: idSchema.optional(),
      attempt: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
      role: roleSchema,
      bytesDone: z.number().int().min(0).max(IMAGE_SIZE_MAX),
    })
    .refine((frame) =>
      frame.transferId !== undefined
        ? frame.operationId === undefined && frame.attempt === undefined
        : frame.operationId !== undefined &&
          frame.attempt !== undefined &&
          frame.role === "SOURCE" &&
          frame.bytesDone === 0,
    ),
  // Exactly one reference: the transfer, or (a capture upload that never got
  // one) its operation and dispatch attempt. `httpStatus` exactly for
  // `http_status` / `url_expired`, `refusal` exactly for `refused`.
  z
    .strictObject({
      type: z.literal("image.job.failed"),
      transferId: idSchema.optional(),
      operationId: idSchema.optional(),
      attempt: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
      code: failureCodeSchema,
      cause: z.enum(IMAGE_FAILURE_CAUSES),
      httpStatus: z.number().int().min(100).max(599).optional(),
      part: partNumberSchema.optional(),
      refusal: codeSchema.optional(),
      reportId: reportIdSchema.optional(),
    })
    .refine(
      (frame) =>
        (frame.transferId !== undefined
          ? frame.operationId === undefined && frame.attempt === undefined
          : frame.operationId !== undefined && frame.attempt !== undefined) &&
        (frame.httpStatus !== undefined) ===
          (frame.cause === "http_status" || frame.cause === "url_expired") &&
        (frame.refusal !== undefined) === (frame.cause === "refused"),
    ),
  /**
   * Upload liveness heartbeat: the furthest stored-object offset reached
   * (`bytesSent`, logical) and every body byte the transport took, retries
   * included (`wireBytes`, physical, monotonic). Either advancing is liveness.
   */
  z.strictObject({
    type: z.literal("image.upload.progress"),
    transferId: idSchema,
    bytesSent: z
      .number()
      .int()
      .min(0)
      .max(IMAGE_SIZE_MAX * 2),
    wireBytes: z.number().int().min(0).max(IMAGE_WIRE_BYTES_MAX),
  }),
  /** Fresh part URLs, granted from the server's lowest unrecorded part. */
  z.strictObject({ type: z.literal("image.upload.renew"), transferId: idSchema }),
] as const;
export type DaemonImageMessage = z.infer<(typeof daemonImageMessageSchemas)[number]>;

const relayLinkSchema = z.strictObject({
  part: partNumberSchema,
  linkId: idSchema,
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
});
export type ImageRelayLinkV11 = z.infer<typeof relayLinkSchema>;
const encryptionSchema = z.strictObject({
  scheme: z.literal(IMAGE_ENCRYPTION_SCHEME),
  key: z.string().length(44),
});

/** Server → daemon image frames. Encoding validates against these. */
export const serverImageMessageSchema = z.union([
  z
    .strictObject({
      type: z.literal("image.fetch.grant"),
      requestId: idSchema,
      transferId: idSchema,
      mode: z.enum(["S3", "RELAY"]),
      sizeBytes: sizeSchema,
      partSize: z.number().int().min(1),
      expiresAtUnixMs: z.number().int().min(0),
      url: urlSchema.optional(),
      links: z.array(relayLinkSchema).max(IMAGE_LINKS_MAX).optional(),
      encryption: encryptionSchema.optional(),
    })
    .refine((grant) =>
      grant.mode === "S3"
        ? grant.url !== undefined && grant.links === undefined
        : grant.links !== undefined && grant.url === undefined && grant.encryption === undefined,
    ),
  z.strictObject({ type: z.literal("image.fetch.refused"), requestId: idSchema, code: codeSchema }),
  z.strictObject({
    type: z.literal("image.serve.request"),
    transferId: idSchema,
    imageOwnerId: idSchema,
    fingerprint: imageFingerprintSchema,
    sizeBytes: sizeSchema,
    partSize: z.number().int().min(1),
    links: z.array(relayLinkSchema).max(IMAGE_LINKS_MAX),
  }),
  z.strictObject({
    type: z.literal("image.publish.request"),
    transferId: idSchema,
    imageOwnerId: idSchema,
    fingerprint: imageFingerprintSchema,
  }),
  z.strictObject({
    type: z.literal("image.links.grant"),
    transferId: idSchema,
    role: roleSchema,
    links: z.array(relayLinkSchema).max(IMAGE_LINKS_MAX),
  }),
  z
    .strictObject({
      type: z.literal("image.upload.grant"),
      transferId: idSchema,
      requestId: idSchema.optional(),
      partSize: z.number().int().min(1),
      parts: z
        .array(z.strictObject({ n: partNumberSchema, url: urlSchema, sizeBytes: sizeSchema }))
        .max(IMAGE_UPLOAD_PARTS_MAX),
      expiresAtUnixMs: z.number().int().min(0),
      /** URL lifetime relative to receipt (the host's own clock). */
      ttlSeconds: z.number().int().min(1).max(IMAGE_UPLOAD_TTL_MAX_SECONDS),
      encryption: encryptionSchema.optional(),
    })
    .refine((grant) => grant.parts.every((part) => part.sizeBytes <= grant.partSize)),
  // The reference of the resume it answers (exactly one shape).
  z
    .strictObject({
      type: z.literal("image.job.resume.result"),
      transferId: idSchema.optional(),
      operationId: idSchema.optional(),
      attempt: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).optional(),
      continue: z.boolean(),
    })
    .refine((frame) =>
      frame.transferId !== undefined
        ? frame.operationId === undefined && frame.attempt === undefined
        : frame.operationId !== undefined && frame.attempt !== undefined,
    ),
  z.strictObject({
    type: z.literal("image.job.cancel"),
    transferId: idSchema,
    reason: codeSchema,
    requestId: idSchema.optional(),
  }),
  z.strictObject({
    type: z.literal("image.release"),
    fingerprint: imageFingerprintSchema,
    imageOwnerId: idSchema,
    reason: z.enum(["stored", "replicated", "gc", "access_lost", "released"]),
  }),
  z.strictObject({ type: z.literal("image.cache.census.ack"), page: z.number().int().min(0) }),
  /** The server handled the report carrying this `reportId` (it took
   * effect, or nothing is left for it to end): the host stops re-sending. */
  z.strictObject({ type: z.literal("report.ack"), reportId: reportIdSchema }),
]);
export type ServerImageMessage = z.infer<typeof serverImageMessageSchema>;
export const SERVER_IMAGE_MESSAGE_TYPES = new Set<string>([
  "image.fetch.grant",
  "image.fetch.refused",
  "image.serve.request",
  "image.publish.request",
  "image.links.grant",
  "image.upload.grant",
  "image.job.resume.result",
  "image.job.cancel",
  "image.release",
  "image.cache.census.ack",
  "report.ack",
]);

/**
 * Grants carry URLs, link tokens and data keys: never log one verbatim. Covers
 * the disk upload grant too (its `encryption.key` is the session's DEK).
 */
export function redactImageFrame(frame: { type: string } & Record<string, unknown>): unknown {
  if (!SERVER_IMAGE_MESSAGE_TYPES.has(frame.type) && !SERVER_DISK_MESSAGE_TYPES.has(frame.type))
    return frame;
  const copy: Record<string, unknown> = { ...frame };
  if ("url" in copy) copy.url = "<redacted>";
  if ("encryption" in copy) copy.encryption = "<redacted>";
  if (Array.isArray(copy.links)) copy.links = `<${copy.links.length} links>`;
  if (
    Array.isArray(copy.parts) &&
    (frame.type === "image.upload.grant" || frame.type === "disk.upload.grant")
  )
    copy.parts = `<${copy.parts.length} parts>`;
  return copy;
}

// ------------------------------------------------------------ disk offload
//
// Stopped-sandbox disk offload. Mirrors
// `crates/sandbox-protocol/src/disk.rs`. The server sends these frames and the
// dispatch fields only to sessions whose hello advertised `diskOffload` (I10:
// the server deploys before daemons). Disk images never appear in image cache
// frames (S6). A disk upload grant without encryption does not parse (I13).

/** A copy's create key is an operation idempotency key (`sandbox-receipt-limits.json`
 * `idempotencyKeyBytes`; Rust `RECEIPT_LIMITS`). */
export const DISK_CREATE_KEY_MAX_BYTES = 256;
const seqSchema = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const diskGenerationSchema = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const storagePoolNameSchema = z.string().min(1).max(63);
const storageMarkerSchema = z.string().min(1).max(128);

/** A launch's immutable root mode (`SandboxOperation.launchMode`). */
export const LAUNCH_MODES = ["new_root", "cold", "warm"] as const;
export type LaunchMode = (typeof LAUNCH_MODES)[number];
export const launchModeSchema = z.enum(LAUNCH_MODES);

/** Rust `valid_cloud_init_instance_id`: 1–128 bytes of `[A-Za-z0-9._:-]`. */
export const cloudInitInstanceIdSchema = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/);

/** `restore` on a `sandbox.reconnect`: boot a new root from the stored disk. */
export const dispatchRestoreV11Schema = z.strictObject({
  offloadId: idSchema,
  seq: seqSchema,
  fingerprint: imageFingerprintSchema,
  /** The stored copy's `volatile.cloud-init.instance-id` (from
   * `disk.upload.begin`), pinned on the restored instance (§7). Omitted when
   * unknown. */
  cloudInitInstanceId: cloudInitInstanceIdSchema.optional(),
});
export type DispatchRestoreV11 = z.infer<typeof dispatchRestoreV11Schema>;

/** `expectDisk` on a cold reconnect of a cached offloaded copy (§8.1). */
export const dispatchExpectDiskV11Schema = z.strictObject({
  seq: seqSchema,
  fingerprint: imageFingerprintSchema,
});
export type DispatchExpectDiskV11 = z.infer<typeof dispatchExpectDiskV11Schema>;

/** The dispatch fields a pre-offload daemon's strict parser rejects. */
export type DispatchDiskFields = {
  restore?: DispatchRestoreV11;
  launchMode?: LaunchMode;
  expectDisk?: DispatchExpectDiskV11;
  diskBaseFingerprint?: string;
};

export function dispatchHasDiskFields(dispatch: DispatchDiskFields): boolean {
  return (
    dispatch.restore !== undefined ||
    dispatch.launchMode !== undefined ||
    dispatch.expectDisk !== undefined ||
    dispatch.diskBaseFingerprint !== undefined
  );
}

/**
 * Dispatch-level disk rules (Rust `valid_dispatch_disk_fields`):
 * - `restore` only on `sandbox.reconnect`, with `launchMode: new_root`, a
 *   unified `fetch` image of the same fingerprint, no `expectDisk`, no build,
 *   and a `diskBaseFingerprint` (if any) equal to it;
 * - `launchMode` only on launches: a create is `new_root`, a reconnect is
 *   `new_root` exactly when it carries `restore`;
 * - `expectDisk` only on a cold reconnect without `restore`;
 * - `diskBaseFingerprint` is a fingerprint.
 */
export function validDispatchDiskFields(dispatch: {
  kind: string;
  image?: unknown;
  build?: unknown;
  restore?: unknown;
  launchMode?: unknown;
  expectDisk?: unknown;
  diskBaseFingerprint?: unknown;
}): boolean {
  const reconnect = dispatch.kind === "sandbox.reconnect";
  const restore =
    dispatch.restore === undefined
      ? undefined
      : dispatchRestoreV11Schema.safeParse(dispatch.restore);
  const launchMode =
    dispatch.launchMode === undefined ? undefined : launchModeSchema.safeParse(dispatch.launchMode);
  const expect =
    dispatch.expectDisk === undefined
      ? undefined
      : dispatchExpectDiskV11Schema.safeParse(dispatch.expectDisk);
  if (restore?.success === false || launchMode?.success === false || expect?.success === false)
    return false;
  const mode = launchMode?.data;
  const base = dispatch.diskBaseFingerprint;
  if (base !== undefined && !imageFingerprintSchema.safeParse(base).success) return false;
  if (restore) {
    const image = dispatchImageV11Schema.safeParse(dispatch.image);
    if (
      !reconnect ||
      mode !== "new_root" ||
      expect !== undefined ||
      dispatch.build !== undefined ||
      !image.success ||
      image.data.format !== "unified" ||
      image.data.fingerprint !== restore.data.fingerprint ||
      (base !== undefined && base !== restore.data.fingerprint)
    )
      return false;
  }
  if (mode !== undefined) {
    if (dispatch.kind === "sandbox.create") {
      if (mode !== "new_root" || restore !== undefined) return false;
    } else if (reconnect) {
      if ((mode === "new_root") !== (restore !== undefined)) return false;
    } else return false;
  }
  if (expect && (!reconnect || restore !== undefined || (mode !== undefined && mode !== "cold")))
    return false;
  return true;
}

/**
 * The census root observation (`sandbox.inventory` entry `root`), reused as
 * the root-absence proof of `disk.evicted` / `disk.discarded`.
 */
export const rootObservationV11Schema = z.strictObject({
  storagePoolName: storagePoolNameSchema,
  storageMarker: storageMarkerSchema,
  diskGiB: z.number().int().min(vmLimits.diskGiBMin).max(vmLimits.diskGiBMax),
  state: z.enum(["present", "absent"]),
  networkCleanupComplete: z.boolean(),
  observationSequence: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
});
export type RootObservationV11 = z.infer<typeof rootObservationV11Schema>;
const rootAbsenceProofSchema = rootObservationV11Schema.refine(
  (proof) => proof.state === "absent",
  "a root-absence proof says absent",
);

export const DISK_OFFLOAD_FAILURE_CODES = [
  "staging_full",
  "export_interrupted",
  "not_stopped",
  "instance_missing",
  "corrupt",
  "io",
  "timeout",
  "cancelled",
] as const;
export type DiskOffloadFailureCode = (typeof DISK_OFFLOAD_FAILURE_CODES)[number];

/**
 * Presigned URLs carry bearer material: HTTPS, or HTTP only to an explicit
 * loopback host (Rust `valid_url`). Disk grants check it on encode too.
 */
export function validNodeUrl(value: string): boolean {
  if (value.length > 8192) return false;
  if (value.startsWith("https://")) return true;
  if (!value.startsWith("http://")) return false;
  const authority = value.slice("http://".length).split(/[/?#]/)[0] ?? "";
  if (authority.includes("@")) return false;
  const host = authority.startsWith("[")
    ? (authority.slice(1).split("]")[0] ?? "")
    : (authority.split(":")[0] ?? "");
  const loopbackV4 =
    /^127(\.(0|[1-9]\d{0,2})){3}$/.test(host) &&
    host.split(".").every((octet) => Number(octet) <= 255);
  return host.toLowerCase() === "localhost" || host === "::1" || loopbackV4;
}
const nodeUrlSchema = z.string().refine(validNodeUrl, "HTTPS or loopback HTTP only");

const offloadRef = { sandboxId: idSchema, offloadId: idSchema, seq: seqSchema };
const uploadedPartsSchema = z
  .array(z.strictObject({ n: partNumberSchema, etag: z.string().regex(/^[\x21-\x7e]{1,256}$/) }))
  .min(1)
  .max(IMAGE_UPLOAD_PARTS_MAX);

/** Most entries one `disk.offload.inventory` frame carries (Rust mirror). */
export const DISK_OFFLOAD_INVENTORY_PAGE_MAX = 256;

/** Daemon → server disk frames (members of the daemon discriminated union). */
export const daemonDiskMessageSchemas = [
  z.strictObject({
    type: z.literal("disk.upload.begin"),
    sandboxId: idSchema,
    generation: diskGenerationSchema,
    offloadId: idSchema,
    seq: seqSchema,
    fingerprint: imageFingerprintSchema,
    sizeBytes: sizeSchema,
    unpackedBytes: z.number().int().min(0).optional(),
    format: z.literal("unified"),
    /** `volatile.cloud-init.instance-id`, pinned at restore (§7). */
    cloudInitInstanceId: cloudInitInstanceIdSchema.optional(),
  }),
  z.strictObject({
    type: z.literal("disk.upload.parts"),
    ...offloadRef,
    sessionId: idSchema,
    parts: uploadedPartsSchema,
  }),
  z.strictObject({ type: z.literal("disk.upload.complete"), ...offloadRef, sessionId: idSchema }),
  z.strictObject({
    type: z.literal("disk.offload.failed"),
    ...offloadRef,
    code: z.enum(DISK_OFFLOAD_FAILURE_CODES),
    reportId: reportIdSchema.optional(),
  }),
  z.strictObject({ type: z.literal("disk.evict.request"), ...offloadRef }),
  /**
   * The host dropped this stored offload's alias image, export and staging;
   * only now is its export slot free.
   */
  z.strictObject({
    type: z.literal("disk.offload.released"),
    ...offloadRef,
    reportId: reportIdSchema.optional(),
  }),
  z.strictObject({
    type: z.literal("disk.evicted"),
    sandboxId: idSchema,
    offloadId: idSchema,
    grantId: idSchema,
    rootAbsenceProof: rootAbsenceProofSchema,
  }),
  z
    .strictObject({
      type: z.literal("disk.discarded"),
      sandboxId: idSchema,
      copyId: idSchema,
      rootAbsenceProof: rootAbsenceProofSchema.optional(),
      code: codeSchema.optional(),
    })
    .refine(
      (frame) => (frame.rootAbsenceProof === undefined) !== (frame.code === undefined),
      "exactly one of rootAbsenceProof and code",
    ),
  /**
   * The host's unfinished (not yet stored) offloads, sent after
   * reconciliation in pages; the server answers each entry from its row.
   */
  z.strictObject({
    type: z.literal("disk.offload.inventory"),
    entries: z
      .array(z.strictObject(offloadRef))
      .min(1)
      .max(DISK_OFFLOAD_INVENTORY_PAGE_MAX)
      .refine(
        (entries) => new Set(entries.map((entry) => entry.offloadId)).size === entries.length,
        "unique offload ids",
      ),
  }),
] as const;
export type DaemonDiskMessage = z.infer<(typeof daemonDiskMessageSchemas)[number]>;

/** Server → daemon disk frames. Encoding validates against these. */
export const serverDiskMessageSchema = z.union([
  z.strictObject({
    type: z.literal("disk.offload.request"),
    ...offloadRef,
    generation: diskGenerationSchema,
  }),
  z.strictObject({
    type: z.literal("disk.offload.stored"),
    ...offloadRef,
    fingerprint: imageFingerprintSchema,
    generation: diskGenerationSchema,
  }),
  z.strictObject({ type: z.literal("disk.offload.cancel"), ...offloadRef, reason: codeSchema }),
  z
    .strictObject({
      type: z.literal("disk.upload.grant"),
      ...offloadRef,
      sessionId: idSchema,
      transferId: idSchema,
      partSize: z.number().int().min(1),
      parts: z
        .array(z.strictObject({ n: partNumberSchema, url: nodeUrlSchema, sizeBytes: sizeSchema }))
        .max(IMAGE_UPLOAD_PARTS_MAX),
      expiresAtUnixMs: z.number().int().min(0),
      // Required (I13): a disk object is always encrypted.
      encryption: encryptionSchema,
    })
    .refine((grant) => grant.parts.every((part) => part.sizeBytes <= grant.partSize)),
  z.strictObject({ type: z.literal("disk.evict.suggest"), ...offloadRef }),
  z.strictObject({
    type: z.literal("disk.evict.grant"),
    ...offloadRef,
    grantId: idSchema,
    expiresAtUnixMs: z.number().int().min(0),
  }),
  z.strictObject({ type: z.literal("disk.evict.refused"), ...offloadRef, code: codeSchema }),
  z.strictObject({
    type: z.literal("disk.discard"),
    sandboxId: idSchema,
    copyId: idSchema,
    createKey: z
      .string()
      .min(1)
      .refine((key) => new TextEncoder().encode(key).byteLength <= DISK_CREATE_KEY_MAX_BYTES),
    baseFingerprint: imageFingerprintSchema,
    /** The sandbox's template revision: the stale instance's template tag. */
    templateFingerprint: imageFingerprintSchema,
    storagePoolName: storagePoolNameSchema,
    storageMarker: storageMarkerSchema,
  }),
]);
export type ServerDiskMessage = z.infer<typeof serverDiskMessageSchema>;
export const SERVER_DISK_MESSAGE_TYPES = new Set<string>([
  "disk.offload.request",
  "disk.offload.stored",
  "disk.offload.cancel",
  "disk.upload.grant",
  "disk.evict.suggest",
  "disk.evict.grant",
  "disk.evict.refused",
  "disk.discard",
]);
