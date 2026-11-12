import type { CommunityTemplateCreatedDto } from "@wssp/sandbox-contracts";
import { describe, expect, it, vi } from "vitest";
import { createWsspClient } from "./client";
import { WsspError } from "./errors";
import type { FetchLike } from "./transport";

const REQUEST_ID = "6f1c2f3a-1b2c-4d5e-8f90-123456789abc";
const NOW = "2026-11-06T00:00:00.000Z";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "x-request-id": REQUEST_ID },
  });
}

const createdBody: CommunityTemplateCreatedDto = {
  template: {
    id: "tpl_1",
    slug: "ubuntu-26-04",
    label: "Ubuntu 26.04 LTS",
    archivedAt: null,
    imagePlacement: "INHERIT",
    captureKeep: 3,
    pruneAfterDays: null,
    createdAt: NOW,
    updatedAt: NOW,
    community: { source: "ubuntu-26.04", refresh: true },
  },
  build: null,
  existing: true,
};

function harness(response: () => Response) {
  const requests: { method: string; path: string; headers: Headers; body: unknown }[] = [];
  const fetch = vi.fn<FetchLike>(async (url, init) => {
    requests.push({
      method: init.method ?? "GET",
      path: new URL(url).pathname,
      headers: new Headers(init.headers),
      body: typeof init.body === "string" ? JSON.parse(init.body) : null,
    });
    return response();
  });
  const client = createWsspClient({
    baseUrl: "https://api.example.test",
    apiKey: "wssp_sdk_test_canary",
    fetch,
  });
  return { client, requests };
}

describe("templates.createFromCommunity (community-base S11)", () => {
  it("posts the source and one target with an idempotency key", async () => {
    const { client, requests } = harness(() => json(201, createdBody));
    const created = await client.templates.createFromCommunity({
      source: "ubuntu-26.04",
      hostId: "host_1",
      label: "Base",
      idempotencyKey: "idem-1",
    });
    expect(created).toEqual(createdBody);
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      method: "POST",
      path: "/v1/templates/community",
      body: { source: "ubuntu-26.04", sandboxHostId: "host_1", label: "Base" },
    });
    expect(requests[0]?.headers.get("idempotency-key")).toBe("idem-1");
  });

  it("generates a key and targets a pool", async () => {
    const { client, requests } = harness(() => json(201, createdBody));
    await client.templates.createFromCommunity({ source: "ubuntu-26.04", poolId: "pool_1" });
    expect(requests[0]?.body).toEqual({ source: "ubuntu-26.04", poolId: "pool_1" });
    expect(requests[0]?.headers.get("idempotency-key")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("refuses zero or two targets locally", async () => {
    const { client, requests } = harness(() => json(201, createdBody));
    await expect(client.templates.createFromCommunity({ source: "x" })).rejects.toMatchObject({
      kind: "invalid_request",
    });
    await expect(
      client.templates.createFromCommunity({ source: "x", poolId: "p", hostId: "h" }),
    ).rejects.toBeInstanceOf(WsspError);
    expect(requests).toHaveLength(0);
  });

  it("surfaces the allowlist refusal as a typed authorization error", async () => {
    const { client } = harness(() =>
      json(403, {
        error: {
          code: "template.community_key_scope",
          message: "Community templates need a key that can see every template and revision.",
          requestId: REQUEST_ID,
        },
      }),
    );
    const error = await client.templates
      .createFromCommunity({ source: "ubuntu-26.04", poolId: "pool_1" })
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(WsspError);
    expect(error).toMatchObject({ kind: "authorization", code: "template.community_key_scope" });
  });
});
