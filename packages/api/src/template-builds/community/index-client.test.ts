import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { COMMUNITY_IMAGES } from "./catalog";
import { COMMUNITY_INDEX_URL, CommunityIndexClient, pickNewest } from "./index-client";

const fixture = JSON.parse(
  readFileSync(new URL("./fixtures/images.json", import.meta.url), "utf8"),
);
const entry = COMMUNITY_IMAGES[0]!;
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("pickNewest (community-base I2)", () => {
  it("pins the newest VM build: combined fingerprint, both files, same directory", () => {
    expect(pickNewest(fixture, entry)).toEqual({
      product: "ubuntu:resolute:amd64:cloud",
      version: "20261106_07:42",
      fingerprint: "sha256:370bafec5a904285398c108f6c75bd8e644abb645ffe81c1524b153cfb617aca",
      architecture: "x86_64",
      metaPath: "images/ubuntu/resolute/amd64/cloud/20261106_07:42/incus.tar.xz",
      metaSha256: "89043d5db7beb86a6fd713976321a2287c265164a50d1cbf392e06b1b8e18019",
      metaSize: 1208,
      diskPath: "images/ubuntu/resolute/amd64/cloud/20261106_07:42/disk.qcow2",
      diskSha256: "8db8e33dca06e8664bca60fa2b722c3c9038148f59f8b2ccf2f208db979aa02d",
      diskSize: 495803904,
    });
  });

  it("skips a drifted or oversized newest version and fails closed when none is left", () => {
    const copy = structuredClone(fixture);
    const versions = copy.products["ubuntu:resolute:amd64:cloud"].versions;
    versions["20261106_07:42"].items["disk.qcow2"].size = 5 * 1024 ** 3;
    expect(pickNewest(copy, entry)?.version).toBe("20261105_07:42");
    delete versions["20261105_07:42"].items["incus.tar.xz"]["combined_disk-kvm-img_sha256"];
    expect(pickNewest(copy, entry)).toBeNull();
    const traversal = structuredClone(fixture);
    traversal.products["ubuntu:resolute:amd64:cloud"].versions["20261106_07:42"].items[
      "disk.qcow2"
    ].path = "images/../etc/disk.qcow2";
    expect(pickNewest(traversal, entry)?.version).toBe("20261105_07:42");
  });
});

describe("CommunityIndexClient", () => {
  it("fetches only the fixed URL without following redirects, and caches an hour", async () => {
    let now = 0;
    const fetcher = vi.fn(async () => json(fixture));
    const client = new CommunityIndexClient(fetcher, () => now);
    await client.newest(entry);
    now = 59 * 60_000;
    await client.newest(entry);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith(
      COMMUNITY_INDEX_URL,
      expect.objectContaining({ redirect: "error" }),
    );
    now = 61 * 60_000;
    await client.newest(entry);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("single-flights concurrent reads and negative-caches a failure for a minute", async () => {
    let now = 0;
    const fetcher = vi.fn(async () => json({}, 503));
    const client = new CommunityIndexClient(fetcher, () => now);
    const reads = await Promise.allSettled([client.newest(entry), client.newest(entry)]);
    expect(reads.every((r) => r.status === "rejected")).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await expect(client.newest(entry)).rejects.toMatchObject({ reason: "index_unreachable" });
    expect(fetcher).toHaveBeenCalledTimes(1);
    now = 61_000;
    await expect(client.newest(entry)).rejects.toMatchObject({ reason: "index_unreachable" });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("refuses an oversized body and a malformed index", async () => {
    const huge = new Response("x", { headers: { "content-length": String(9 * 1024 * 1024) } });
    await expect(new CommunityIndexClient(async () => huge).newest(entry)).rejects.toMatchObject({
      reason: "index_unreachable",
    });
    await expect(
      new CommunityIndexClient(async () => json({ format: "nope" })).newest(entry),
    ).rejects.toMatchObject({ reason: "index_unreachable" });
    await expect(
      new CommunityIndexClient(async () => json({ format: "products:1.0", products: {} })).newest(
        entry,
      ),
    ).rejects.toMatchObject({ reason: "no_tested_version" });
  });
});
