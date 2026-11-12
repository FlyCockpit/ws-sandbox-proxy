import { z } from "zod";
import { emptyQuerySchema, resourceIdParamsSchema } from "./dto";
import { guestFilePathSchema } from "./guest-path";
import { emptyBodySchema, mutationReceiptSchema } from "./mutations";
import type { SdkRoute } from "./routes";

export const TRANSFER_CHUNK_BYTES = 1024 * 1024;
/**
 * THE per-transfer byte cap, end to end: the default of `TRANSFER_MAX_BYTES`
 * and its hard ceiling (the env schema rejects larger values), the relay's
 * upload-manifest bound, and the host's `sandbox_runtime::FILE_MAX_BYTES`.
 * Operators may configure a lower cap, never a higher one.
 */
export const TRANSFER_MAX_BYTES = 1024 ** 3;
export const TRANSFER_DEFAULT_DISK_BYTES = 10 * 1024 ** 3;
export const transferIdSchema = z.uuid();
export const transferCreateSchema = z
  .object({
    sandboxId: z.string().min(1).max(128),
    direction: z.enum(["UPLOAD", "DOWNLOAD"]),
    // Guest-only path, refused here by the guest's own rules before any
    // transfer slot or disk is reserved (E-27, E-28, TQ-N2).
    guestPath: guestFilePathSchema,
    totalBytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    idempotencyKey: z
      .string()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9._:-]+$/),
  })
  .strict();
export type TransferCreate = z.infer<typeof transferCreateSchema>;
export const transferReceiptSchema = z
  .object({
    id: transferIdSchema,
    sandboxId: z.string(),
    generation: z.number().int().positive(),
    direction: z.enum(["UPLOAD", "DOWNLOAD"]),
    state: z.enum(["ALLOCATING", "OPEN", "SEALED", "ABORTED", "EXPIRED", "FAILED"]),
    totalBytes: z.number().int().nonnegative(),
    receivedBytes: z.number().int().nonnegative(),
    chunkBytes: z.literal(TRANSFER_CHUNK_BYTES),
    idleExpiresAt: z.iso.datetime(),
    expiresAt: z.iso.datetime(),
  })
  .strict();

export const uploadCreateBodySchema = transferCreateSchema.omit({
  direction: true,
  idempotencyKey: true,
});
export const uploadCommitBodySchema = z
  .object({ sha256: z.string().regex(/^[a-f0-9]{64}$/) })
  .strict();
const base = {
  transport: "upload",
  feature: "files.upload",
  scopes: ["files:write"],
  query: emptyQuerySchema,
  params: z.object({ id: transferIdSchema }).strict(),
  response: { name: "TransferReceipt", schema: transferReceiptSchema },
  notFound: "NOT_FOUND",
  paginated: false,
  errors: ["TRANSFER_EXPIRED", "TRANSFER_QUOTA", "TRANSFER_IO"],
  successStatus: 200,
} as const;
export const UPLOAD_ROUTES = {
  createUpload: {
    ...base,
    method: "post",
    path: "/v1/transfers",
    params: null,
    body: uploadCreateBodySchema,
    successStatus: 201,
    summary: "Reserve an upload with a known total length.",
  },
  getUpload: {
    ...base,
    method: "get",
    path: "/v1/transfers/{id}",
    summary: "Read the durable received offset and transfer state.",
  },
  putUploadChunk: {
    ...base,
    method: "put",
    path: "/v1/transfers/{id}",
    binary: true,
    summary:
      "Write or replay one fixed binary chunk; Content-Range must specify the reserved total.",
  },
  commitUpload: {
    ...base,
    method: "post",
    path: "/v1/transfers/{id}/commit",
    body: uploadCommitBodySchema,
    successStatus: 202,
    response: { name: "MutationReceipt", schema: mutationReceiptSchema },
    summary:
      "Verify SHA-256 and accept one generation-bound guest replacement; poll the operation.",
  },
  abortUpload: {
    ...base,
    method: "delete",
    path: "/v1/transfers/{id}",
    body: emptyBodySchema,
    idempotency: false,
    summary:
      "Abort an uncommitted upload and release its spool; committed uploads return conflict.",
  },
} as const satisfies Record<string, SdkRoute>;

/**
 * Binary download of one completed GET_FILE capture (C30). Request the capture
 * with `POST /v1/sandboxes/{id}/files/download`, poll the operation until it
 * succeeds, then read the immutable captured bytes: whole, or one byte range
 * (`Range: bytes=a-b`, `bytes=a-`, `bytes=-n`). `ETag` is the quoted SHA-256 of
 * the whole capture, so `If-Range` resumes an interrupted download without a
 * new capture. Multi-range requests are rejected with 416.
 */
export const DOWNLOAD_ROUTES = {
  downloadFile: {
    method: "get",
    path: "/v1/operations/{id}/content",
    transport: "download",
    binaryResponse: true,
    feature: "files.download",
    scopes: ["operations:read", "files:read"],
    params: resourceIdParamsSchema,
    query: emptyQuerySchema,
    response: { name: "FileContent", schema: z.never() },
    notFound: "sandbox.operation_not_found",
    paginated: false,
    errors: ["TRANSFER_NOT_READY", "TRANSFER_EXPIRED", "RANGE_NOT_SATISFIABLE", "TRANSFER_IO"],
    summary:
      "Stream a completed file capture, whole or one byte range, with its length, SHA-256 and ETag.",
  },
} as const satisfies Record<string, SdkRoute>;
