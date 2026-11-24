import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListMultipartUploadsCommand,
  ListObjectsV2Command,
  ListPartsCommand,
  S3Client,
  UploadPartCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { readImageStoreEnv } from "@wssp/env/image-store-config";
import {
  IMAGE_ENCRYPTION_RECORD_BYTES,
  IMAGE_ENCRYPTION_SCHEME,
  IMAGE_ENCRYPTION_TAG_BYTES,
} from "@wssp/sandbox-contracts";
import { encodeHmacContext } from "../hmac-context";
import { ImageIntegrityError } from "./verification-errors";

/**
 * Template image store (S3, R2, MinIO). Presigned URLs, upload ids and data
 * keys are produced in memory for one grant and never persisted or logged.
 *
 * AWS SDK v3 adds CRC32 checksum parameters by default, which break presigned
 * UploadPart and GET on R2 and MinIO: both request and response checksums are
 * WHEN_REQUIRED.
 */
export type ImageStoreSettings = {
  endpoint: string;
  publicEndpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle: boolean;
  prefix: string;
  presignTtlSeconds: number;
};

export function imageStoreSettings(): ImageStoreSettings | null {
  const e = readImageStoreEnv();
  if (
    !e.IMAGE_S3_BUCKET ||
    !e.IMAGE_S3_ENDPOINT ||
    !e.IMAGE_S3_ACCESS_KEY_ID ||
    !e.IMAGE_S3_SECRET_ACCESS_KEY
  )
    return null;
  return {
    endpoint: e.IMAGE_S3_ENDPOINT,
    publicEndpoint: e.IMAGE_S3_PUBLIC_ENDPOINT ?? e.IMAGE_S3_ENDPOINT,
    region: e.IMAGE_S3_REGION,
    bucket: e.IMAGE_S3_BUCKET,
    accessKeyId: e.IMAGE_S3_ACCESS_KEY_ID,
    secretAccessKey: e.IMAGE_S3_SECRET_ACCESS_KEY,
    forcePathStyle: e.IMAGE_S3_FORCE_PATH_STYLE,
    prefix: e.IMAGE_S3_PREFIX,
    presignTtlSeconds: e.IMAGE_S3_PRESIGN_TTL_SECONDS,
  };
}

/**
 * Data-client timeouts: a connect that never completes, or a socket idle this
 * long, fails the call instead of stalling its caller (the relay's host frame
 * queue awaits these). `socketTimeout` is an inactivity bound, so a long
 * CompleteMultipart or a large streamed GetObject is not cut off while bytes
 * (or S3's keep-alive whitespace) flow. The SDK's `requestTimeout` is a total
 * bound and only warns unless opted in, so it is deliberately not used.
 */
export const IMAGE_S3_REQUEST_HANDLER = {
  connectionTimeout: 5_000,
  socketTimeout: 120_000,
} as const;

export function createImageS3Client(settings: ImageStoreSettings, signing = false): S3Client {
  return new S3Client({
    endpoint: signing ? settings.publicEndpoint : settings.endpoint,
    region: settings.region,
    forcePathStyle: settings.forcePathStyle,
    credentials: {
      accessKeyId: settings.accessKeyId,
      secretAccessKey: settings.secretAccessKey,
    },
    requestChecksumCalculation: "WHEN_REQUIRED",
    responseChecksumValidation: "WHEN_REQUIRED",
    // The presigning client never sends a request.
    ...(signing ? {} : { requestHandler: IMAGE_S3_REQUEST_HANDLER }),
  });
}

/**
 * `<prefix>/owners/<ownerId>/<fphex>/<sessionId>/image.tar[.wsspenc]`: per
 * owner (no dedupe) and per upload session, so two sessions never share a key.
 * Image objects are create-only (`completeMultipart`): with a key per
 * fingerprint, a stale object from an earlier session (a lost Complete
 * response, a CORRUPT object whose delete failed) would block every re-upload
 * until the sweeper removed it.
 */
export function imageObjectKey(
  prefix: string,
  ownerId: string,
  fingerprint: string,
  sessionId: string,
  encrypted: boolean,
): string {
  if (!/^sha256:[0-9a-f]{64}$/.test(fingerprint)) throw new Error("invalid image fingerprint");
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(ownerId)) throw new Error("invalid image owner");
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(sessionId)) throw new Error("invalid image upload session");
  return `${prefix}/owners/${ownerId}/${fingerprint.slice(7)}/${sessionId}/image.tar${encrypted ? ".wsspenc" : ""}`;
}

/** A template upload session id, generated in code so its object key is known
 * before the session row is written. */
export function newImageSessionId(): string {
  return `ises_${randomBytes(16).toString("hex")}`;
}

/**
 * S3 refused a create-only write: an object already exists at the key (412
 * PreconditionFailed) or a concurrent conditional write to it won the race
 * (409 ConditionalRequestConflict). The write never replaced anything and is
 * never retried as an unconditional one; the caller decides what the existing
 * object is worth (the relay hands it to the verify job, which hashes it).
 */
export class ImageObjectExistsError extends Error {
  constructor(
    readonly key: string,
    readonly status: 409 | 412,
  ) {
    super(`image object already exists (${status})`);
    this.name = "ImageObjectExistsError";
  }
}

/** 412/409 for a refused `If-None-Match: *` write, else null. */
export function createOnlyRefusal(error: unknown): 409 | 412 | null {
  const failure = error as { name?: string; $metadata?: { httpStatusCode?: number } } | null;
  if (failure?.name === "PreconditionFailed" || failure?.$metadata?.httpStatusCode === 412)
    return 412;
  if (failure?.name === "ConditionalRequestConflict") return 409;
  return null;
}

export function ownerPrefix(prefix: string, ownerId: string): string {
  return `${prefix}/owners/${ownerId}/`;
}

export class ImageStore {
  readonly settings: ImageStoreSettings;
  private readonly client: S3Client;
  private readonly signer: S3Client;

  constructor(settings: ImageStoreSettings, client?: S3Client, signer?: S3Client) {
    this.settings = settings;
    this.client = client ?? createImageS3Client(settings);
    this.signer = signer ?? createImageS3Client(settings, true);
  }

  presignGet(key: string): Promise<string> {
    return getSignedUrl(
      this.signer,
      new GetObjectCommand({ Bucket: this.settings.bucket, Key: key }),
      {
        expiresIn: this.settings.presignTtlSeconds,
      },
    );
  }

  /**
   * `ContentLength` is a signed header (M9): a node can upload exactly the
   * granted bytes for this part and nothing larger.
   */
  presignUploadPart(
    key: string,
    uploadId: string,
    partNumber: number,
    contentLength: number,
  ): Promise<string> {
    return getSignedUrl(
      this.signer,
      new UploadPartCommand({
        Bucket: this.settings.bucket,
        Key: key,
        UploadId: uploadId,
        PartNumber: partNumber,
        ContentLength: contentLength,
      }),
      { expiresIn: this.settings.presignTtlSeconds, signableHeaders: new Set(["content-length"]) },
    );
  }

  async createMultipart(key: string): Promise<string> {
    const out = await this.client.send(
      new CreateMultipartUploadCommand({
        Bucket: this.settings.bucket,
        Key: key,
        ContentType: "application/octet-stream",
      }),
    );
    if (!out.UploadId) throw new Error("image store returned no upload id");
    return out.UploadId;
  }

  /** Every listed part (bounded pages); used to check sizes before Complete. */
  async listParts(
    key: string,
    uploadId: string,
  ): Promise<{ n: number; size: number; etag: string }[]> {
    const parts: { n: number; size: number; etag: string }[] = [];
    let marker: string | undefined;
    for (let page = 0; page < 20; page++) {
      const out = await this.client.send(
        new ListPartsCommand({
          Bucket: this.settings.bucket,
          Key: key,
          UploadId: uploadId,
          MaxParts: 1000,
          PartNumberMarker: marker,
        }),
      );
      for (const part of out.Parts ?? [])
        if (part.PartNumber && part.Size !== undefined && part.ETag)
          parts.push({ n: part.PartNumber, size: part.Size, etag: part.ETag });
      if (!out.IsTruncated) return parts;
      marker = out.NextPartNumberMarker;
    }
    throw new Error("image store part listing did not terminate");
  }

  /**
   * Create-only: `If-None-Match: *` on every attempt (the SDK's own retries
   * included), so an existing object at `key` is never replaced. A refusal
   * aborts this multipart upload (best effort; the sweeper is the backstop),
   * so no orphan parts are left, and throws `ImageObjectExistsError`.
   * Presigned UploadPart URLs need no condition: a part never becomes an
   * object until this call.
   */
  async completeMultipart(key: string, uploadId: string, parts: { n: number; etag: string }[]) {
    try {
      await this.client.send(
        new CompleteMultipartUploadCommand({
          Bucket: this.settings.bucket,
          Key: key,
          UploadId: uploadId,
          IfNoneMatch: "*",
          MultipartUpload: {
            Parts: [...parts]
              .sort((a, b) => a.n - b.n)
              .map((p) => ({ PartNumber: p.n, ETag: p.etag })),
          },
        }),
      );
    } catch (error) {
      const refused = createOnlyRefusal(error);
      if (refused === null) throw error;
      await this.abortMultipart(key, uploadId).catch(() => {});
      throw new ImageObjectExistsError(key, refused);
    }
  }

  async abortMultipart(key: string, uploadId: string) {
    await this.client.send(
      new AbortMultipartUploadCommand({
        Bucket: this.settings.bucket,
        Key: key,
        UploadId: uploadId,
      }),
    );
  }

  async deleteObject(key: string) {
    await this.client.send(new DeleteObjectCommand({ Bucket: this.settings.bucket, Key: key }));
  }

  /** Whether the object exists (HEAD); false only on a definite not-found. */
  async objectExists(key: string): Promise<boolean> {
    try {
      await this.client.send(new HeadObjectCommand({ Bucket: this.settings.bucket, Key: key }));
      return true;
    } catch (error) {
      const failure = error as { name?: string; $metadata?: { httpStatusCode?: number } } | null;
      if (failure?.name === "NotFound" || failure?.$metadata?.httpStatusCode === 404) return false;
      throw error;
    }
  }

  /** The object's body; `signal` aborts the request and its stream. */
  async getObjectStream(key: string, signal?: AbortSignal): Promise<AsyncIterable<Uint8Array>> {
    const out = await this.client.send(
      new GetObjectCommand({ Bucket: this.settings.bucket, Key: key }),
      { abortSignal: signal },
    );
    if (!out.Body) throw new Error("image store returned no body");
    return out.Body as AsyncIterable<Uint8Array>;
  }

  /** One bounded page of objects under the store prefix. */
  async listObjectsPage(continuation?: string, startAfter?: string) {
    const out = await this.client.send(
      new ListObjectsV2Command({
        Bucket: this.settings.bucket,
        Prefix: `${this.settings.prefix}/`,
        MaxKeys: 500,
        ContinuationToken: continuation,
        StartAfter: continuation ? undefined : startAfter,
      }),
    );
    return {
      objects: (out.Contents ?? []).flatMap((o) =>
        o.Key ? [{ key: o.Key, lastModified: o.LastModified ?? null, size: o.Size ?? 0 }] : [],
      ),
      next: out.IsTruncated ? out.NextContinuationToken : undefined,
    };
  }

  /** One bounded page of incomplete multipart uploads under the store prefix. */
  async listUploadsPage(keyMarker?: string, uploadIdMarker?: string) {
    const out = await this.client.send(
      new ListMultipartUploadsCommand({
        Bucket: this.settings.bucket,
        Prefix: `${this.settings.prefix}/`,
        MaxUploads: 500,
        KeyMarker: keyMarker,
        UploadIdMarker: uploadIdMarker,
      }),
    );
    return {
      uploads: (out.Uploads ?? []).flatMap((u) =>
        u.Key && u.UploadId
          ? [{ key: u.Key, uploadId: u.UploadId, initiated: u.Initiated ?? null }]
          : [],
      ),
      next: out.IsTruncated
        ? { keyMarker: out.NextKeyMarker, uploadIdMarker: out.NextUploadIdMarker }
        : undefined,
    };
  }
}

let cached: ImageStore | null | undefined;
/** The configured store, or null in peer/off mode. */
export function imageStore(): ImageStore | null {
  if (cached === undefined) {
    const settings = imageStoreSettings();
    cached = settings ? new ImageStore(settings) : null;
  }
  return cached;
}

// ---------------------------------------------------------------- encryption

/** Master key from IMAGE_STORE_ENCRYPTION_KEY, or null when encryption is off. */
export function imageMasterKey(): Buffer | null {
  const e = readImageStoreEnv();
  if (e.IMAGE_STORE_ENCRYPTION !== "on" || !e.IMAGE_STORE_ENCRYPTION_KEY) return null;
  const key = Buffer.from(e.IMAGE_STORE_ENCRYPTION_KEY, "base64");
  return key.length === 32 ? key : null;
}

/** First 16 hex characters of the master key's SHA-256 (rotation evidence, never the key). */
export function masterKeyId(master: Buffer): string {
  return createHash("sha256").update(master).digest("hex").slice(0, 16);
}

function wrapAad(artifactId: string, userId: string): Buffer {
  return encodeHmacContext(["wssp-image-key-wrap-v1", artifactId, userId]);
}

export function wrapDataKey(
  master: Buffer,
  dataKey: Buffer,
  artifactId: string,
  userId: string,
): { wrappedKey: Buffer; wrappedKeyNonce: Buffer; keyId: string } {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", master, nonce);
  cipher.setAAD(wrapAad(artifactId, userId));
  const wrapped = Buffer.concat([cipher.update(dataKey), cipher.final(), cipher.getAuthTag()]);
  return { wrappedKey: wrapped, wrappedKeyNonce: nonce, keyId: masterKeyId(master) };
}

export function unwrapDataKey(
  master: Buffer,
  wrapped: { wrappedKey: Uint8Array; wrappedKeyNonce: Uint8Array },
  artifactId: string,
  userId: string,
): Buffer {
  const body = Buffer.from(wrapped.wrappedKey);
  if (body.length !== 48) throw new ImageIntegrityError("invalid wrapped key");
  const decipher = createDecipheriv("aes-256-gcm", master, Buffer.from(wrapped.wrappedKeyNonce));
  decipher.setAAD(wrapAad(artifactId, userId));
  decipher.setAuthTag(body.subarray(32));
  return Buffer.concat([decipher.update(body.subarray(0, 32)), decipher.final()]);
}

export function newDataKey(): Buffer {
  return randomBytes(32);
}

/**
 * `aes256gcm-r1` record nonce: 4 zero bytes || u64be(record index). AAD is
 * "wssp-img-r1" || u64be(index) || final-flag, so truncation, reordering and
 * record dropping all fail authentication. Mirrors `apps/cli` images/crypto.rs.
 */
export function recordNonce(index: number): Buffer {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(index), 4);
  return nonce;
}
export function recordAad(index: number, final: boolean): Buffer {
  const aad = Buffer.alloc(11 + 8 + 1);
  aad.write("wssp-img-r1", 0, "ascii");
  aad.writeBigUInt64BE(BigInt(index), 11);
  aad[19] = final ? 1 : 0;
  return aad;
}

export function encryptRecord(key: Buffer, index: number, final: boolean, plain: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, recordNonce(index));
  cipher.setAAD(recordAad(index, final));
  return Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}

export function decryptRecord(key: Buffer, index: number, final: boolean, sealed: Buffer): Buffer {
  if (sealed.length < IMAGE_ENCRYPTION_TAG_BYTES)
    throw new ImageIntegrityError("truncated image record");
  const decipher = createDecipheriv("aes-256-gcm", key, recordNonce(index));
  decipher.setAAD(recordAad(index, final));
  decipher.setAuthTag(sealed.subarray(sealed.length - IMAGE_ENCRYPTION_TAG_BYTES));
  return Buffer.concat([
    decipher.update(sealed.subarray(0, sealed.length - IMAGE_ENCRYPTION_TAG_BYTES)),
    decipher.final(),
  ]);
}

/**
 * Stream an `aes256gcm-r1` object of `plainSize` plaintext bytes into
 * plaintext chunks. Throws on any tamper, truncation or trailing bytes.
 */
export async function* decryptImageStream(
  key: Buffer,
  plainSize: number,
  source: AsyncIterable<Uint8Array>,
): AsyncGenerator<Buffer> {
  const sealedRecord = IMAGE_ENCRYPTION_RECORD_BYTES + IMAGE_ENCRYPTION_TAG_BYTES;
  const records = Math.max(1, Math.ceil(plainSize / IMAGE_ENCRYPTION_RECORD_BYTES));
  let pending = Buffer.alloc(0);
  let index = 0;
  for await (const chunk of source) {
    pending = Buffer.concat([pending, Buffer.from(chunk)]);
    while (pending.length >= sealedRecord && index < records - 1) {
      yield decryptRecord(key, index, false, pending.subarray(0, sealedRecord));
      pending = pending.subarray(sealedRecord);
      index++;
    }
  }
  if (index !== records - 1) throw new ImageIntegrityError("truncated encrypted image");
  const lastPlain = plainSize - index * IMAGE_ENCRYPTION_RECORD_BYTES;
  if (pending.length !== lastPlain + IMAGE_ENCRYPTION_TAG_BYTES)
    throw new ImageIntegrityError("encrypted image length mismatch");
  yield decryptRecord(key, index, true, pending);
}

export { IMAGE_ENCRYPTION_SCHEME };
