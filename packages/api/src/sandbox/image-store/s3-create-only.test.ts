import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import { describe, expect, it, vi } from "vitest";
import {
  createOnlyRefusal,
  ImageObjectExistsError,
  ImageStore,
  type ImageStoreSettings,
} from "./s3";

// Image objects are create-only: every Complete carries `If-None-Match: *`,
// and a refusal is a typed "already exists" that aborts the upload and is
// never retried as an overwrite. The real-S3 behaviour is in
// image-store.s3.test.ts (`pnpm test:s3`).

const settings: ImageStoreSettings = {
  endpoint: "http://127.0.0.1:9",
  publicEndpoint: "http://127.0.0.1:9",
  region: "us-east-1",
  bucket: "bucket",
  accessKeyId: "a",
  secretAccessKey: "s",
  forcePathStyle: true,
  prefix: "wssp",
  presignTtlSeconds: 600,
};

function storeWith(send: (command: unknown) => Promise<unknown>) {
  const client = { send: vi.fn(send) };
  return { client, store: new ImageStore(settings, client as unknown as S3Client, {} as S3Client) };
}

const s3Error = (name: string, status: number) =>
  Object.assign(new Error(name), { name, $metadata: { httpStatusCode: status } });

describe("create-only image completion", () => {
  it("sends If-None-Match: * with the sorted parts", async () => {
    const { client, store } = storeWith(async () => ({}));
    await store.completeMultipart("k", "u", [
      { n: 2, etag: '"b"' },
      { n: 1, etag: '"a"' },
    ]);
    expect(client.send).toHaveBeenCalledTimes(1);
    const command = client.send.mock.calls[0]![0];
    expect(command).toBeInstanceOf(CompleteMultipartUploadCommand);
    expect((command as CompleteMultipartUploadCommand).input).toEqual({
      Bucket: "bucket",
      Key: "k",
      UploadId: "u",
      IfNoneMatch: "*",
      MultipartUpload: {
        Parts: [
          { PartNumber: 1, ETag: '"a"' },
          { PartNumber: 2, ETag: '"b"' },
        ],
      },
    });
  });

  it.each([
    ["PreconditionFailed", 412, 412],
    ["Unknown", 412, 412],
    ["ConditionalRequestConflict", 409, 409],
  ] as const)(
    "maps %s (%i) to ImageObjectExistsError and aborts the upload once",
    async (name, status, expected) => {
      const { client, store } = storeWith(async (command) => {
        if (command instanceof CompleteMultipartUploadCommand) throw s3Error(name, status);
        return {};
      });
      const failure = await store
        .completeMultipart("k", "u", [{ n: 1, etag: '"a"' }])
        .catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(ImageObjectExistsError);
      expect(failure).toMatchObject({ key: "k", status: expected });
      const commands = client.send.mock.calls.map(([c]) => c);
      // One Complete (never re-sent without the condition), then one Abort.
      expect(commands.filter((c) => c instanceof CompleteMultipartUploadCommand)).toHaveLength(1);
      const aborts = commands.filter((c) => c instanceof AbortMultipartUploadCommand);
      expect(aborts.map((c) => (c as AbortMultipartUploadCommand).input)).toEqual([
        { Bucket: "bucket", Key: "k", UploadId: "u" },
      ]);
    },
  );

  it("still reports already-exists when the abort itself fails", async () => {
    const { store } = storeWith(async (command) => {
      if (command instanceof CompleteMultipartUploadCommand)
        throw s3Error("PreconditionFailed", 412);
      throw s3Error("InternalError", 500);
    });
    await expect(store.completeMultipart("k", "u", [])).rejects.toBeInstanceOf(
      ImageObjectExistsError,
    );
  });

  it("any other failure propagates unchanged and does not abort (the caller decides)", async () => {
    const outage = s3Error("InternalError", 500);
    const { client, store } = storeWith(async () => {
      throw outage;
    });
    await expect(store.completeMultipart("k", "u", [])).rejects.toBe(outage);
    expect(client.send).toHaveBeenCalledTimes(1);
  });

  it("classifies only create-only refusals", () => {
    expect(createOnlyRefusal(s3Error("PreconditionFailed", 412))).toBe(412);
    expect(createOnlyRefusal(s3Error("ConditionalRequestConflict", 409))).toBe(409);
    expect(createOnlyRefusal(s3Error("OperationAborted", 409))).toBeNull();
    expect(createOnlyRefusal(s3Error("NoSuchUpload", 404))).toBeNull();
    expect(createOnlyRefusal(null)).toBeNull();
  });
});
