import { z } from "zod";
import type { CommunityImageEntry } from "./catalog";

/**
 * The simplestreams index client (community-base I2). The control plane reads
 * exactly one URL on the fixed index host, never follows a redirect, bounds
 * time and bytes, validates the shape and fails closed on any drift. One
 * fetch is in flight at a time (single-flight), a good answer is cached for
 * an hour and a failure for a minute. It never downloads an image: builders
 * do that themselves from the pinned paths (D-B).
 */
export const COMMUNITY_INDEX_URL = "https://images.linuxcontainers.org/streams/v1/images.json";
const INDEX_TIMEOUT_MS = 15_000;
const INDEX_MAX_BYTES = 8 * 1024 * 1024;
const INDEX_CACHE_MS = 60 * 60_000;
const INDEX_NEGATIVE_CACHE_MS = 60_000;

const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
/** Relative path under `images/`, the same grammar the daemon enforces. */
const pathSchema = z
  .string()
  .max(512)
  .regex(/^images(\/[A-Za-z0-9._:+-]+)+$/)
  .refine((path) => path.split("/").every((segment) => segment !== "." && segment !== ".."));
const sizeSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const itemSchema = z.object({
  ftype: z.string(),
  sha256: z.string(),
  size: z.number(),
  path: z.string(),
  "combined_disk-kvm-img_sha256": z.string().optional(),
});
const indexSchema = z.object({
  format: z.literal("products:1.0"),
  products: z.record(
    z.string(),
    z.object({
      arch: z.string().optional(),
      versions: z.record(z.string(), z.object({ items: z.record(z.string(), itemSchema) })),
    }),
  ),
});
type Index = z.infer<typeof indexSchema>;

/** One pinnable upstream VM build: the fingerprint and both split files. */
export type UpstreamPin = {
  product: string;
  version: string;
  /** `sha256:<combined_disk-kvm-img_sha256>`. */
  fingerprint: string;
  architecture: string;
  metaPath: string;
  metaSha256: string;
  metaSize: number;
  diskPath: string;
  diskSha256: string;
  diskSize: number;
};

export type IndexFailure = "index_unreachable" | "no_tested_version";
export class CommunityIndexError extends Error {
  constructor(readonly reason: IndexFailure) {
    super(`Community image index: ${reason}.`);
    this.name = "CommunityIndexError";
  }
}

const VERSION = /^[0-9]{8}_[0-9]{2}:[0-9]{2}$/;
const UPSTREAM_META_MAX = 1024 * 1024;

/**
 * The newest VM build of `entry.product` with a complete, in-bounds split
 * pair (incus.tar.xz + disk-kvm.img in the same directory), or null.
 * Versions are tried newest first; a malformed version is skipped, never
 * repaired.
 */
export function pickNewest(index: Index, entry: CommunityImageEntry): UpstreamPin | null {
  const product = index.products[entry.product];
  if (!product) return null;
  const versions = Object.keys(product.versions)
    .filter((v) => VERSION.test(v))
    .sort()
    .reverse();
  for (const version of versions) {
    const items = Object.values(product.versions[version]?.items ?? {});
    const meta = items.find((item) => item.ftype === "incus.tar.xz");
    const disk = items.find((item) => item.ftype === "disk-kvm.img");
    if (!meta || !disk) continue;
    const combined = meta["combined_disk-kvm-img_sha256"];
    if (
      !combined ||
      !sha256.safeParse(combined).success ||
      !sha256.safeParse(meta.sha256).success ||
      !sha256.safeParse(disk.sha256).success ||
      !pathSchema.safeParse(meta.path).success ||
      !pathSchema.safeParse(disk.path).success ||
      !sizeSchema.safeParse(meta.size).success ||
      !sizeSchema.safeParse(disk.size).success
    )
      continue;
    const dir = (path: string) => path.slice(0, path.lastIndexOf("/"));
    if (
      dir(meta.path) !== dir(disk.path) ||
      !meta.path.endsWith("/incus.tar.xz") ||
      !disk.path.endsWith("/disk.qcow2") ||
      meta.size > UPSTREAM_META_MAX ||
      disk.size > entry.maxDiskBytes
    )
      continue;
    return {
      product: entry.product,
      version,
      fingerprint: `sha256:${combined}`,
      architecture: entry.architecture,
      metaPath: meta.path,
      metaSha256: meta.sha256,
      metaSize: meta.size,
      diskPath: disk.path,
      diskSha256: disk.sha256,
      diskSize: disk.size,
    };
  }
  return null;
}

type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

/** Read at most `max` bytes of a response body, refusing a larger one. */
async function boundedText(response: Response, max: number): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > max) throw new CommunityIndexError("index_unreachable");
  const reader = response.body?.getReader();
  if (!reader) throw new CommunityIndexError("index_unreachable");
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new CommunityIndexError("index_unreachable");
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

export class CommunityIndexClient {
  private cached: { index: Index; at: number } | null = null;
  private failedAt = Number.NEGATIVE_INFINITY;
  private inflight: Promise<Index> | null = null;

  constructor(
    private readonly fetcher: FetchLike = (url, init) => fetch(url, init),
    private readonly clock: () => number = Date.now,
  ) {}

  private async load(): Promise<Index> {
    const now = this.clock();
    if (this.cached && now - this.cached.at < INDEX_CACHE_MS) return this.cached.index;
    if (now - this.failedAt < INDEX_NEGATIVE_CACHE_MS)
      throw new CommunityIndexError("index_unreachable");
    this.inflight ??= (async () => {
      try {
        const response = await this.fetcher(COMMUNITY_INDEX_URL, {
          redirect: "error",
          signal: AbortSignal.timeout(INDEX_TIMEOUT_MS),
          headers: { accept: "application/json" },
        });
        if (response.status !== 200) throw new CommunityIndexError("index_unreachable");
        const parsed = indexSchema.safeParse(
          JSON.parse(await boundedText(response, INDEX_MAX_BYTES)),
        );
        if (!parsed.success) throw new CommunityIndexError("index_unreachable");
        this.cached = { index: parsed.data, at: this.clock() };
        return parsed.data;
      } catch (error) {
        this.failedAt = this.clock();
        throw error instanceof CommunityIndexError
          ? error
          : new CommunityIndexError("index_unreachable");
      } finally {
        this.inflight = null;
      }
    })();
    return this.inflight;
  }

  /** The newest pinnable build of `entry`; throws a typed reason otherwise. */
  async newest(entry: CommunityImageEntry): Promise<UpstreamPin> {
    const pin = pickNewest(await this.load(), entry);
    if (!pin) throw new CommunityIndexError("no_tested_version");
    return pin;
  }
}

let shared: CommunityIndexClient | null = null;
/** The process-wide client (one cache, one in-flight fetch). */
export function communityIndexClient(): CommunityIndexClient {
  shared ??= new CommunityIndexClient();
  return shared;
}
