import { describe, expect, it } from "vitest";
import { SDK_SCOPES } from "./dto";
import { cidrContains, parseCidr, parseIpAddress } from "./ip";
import { buildSdkOpenApiDocument } from "./openapi";
import { enabledSdkFeatures, SDK_FEATURE_ROUTES, SDK_ROUTE_IDS, SDK_ROUTES } from "./routes";
import {
  createWebhookEndpointBodySchema,
  WEBHOOK_EVENT_TYPES,
  webhookEndpointWithSecretSchema,
  webhookEventPayloadSchema,
} from "./webhooks";

describe("webhook contract", () => {
  it("adds one scope and one feature whose routes all need only that scope", () => {
    expect(SDK_SCOPES).toContain("webhooks:write");
    for (const id of SDK_FEATURE_ROUTES["webhooks.write"]) {
      expect(SDK_ROUTES[id].scopes).toEqual(["webhooks:write"]);
      expect(SDK_ROUTES[id].feature).toBe("webhooks.write");
    }
    expect(enabledSdkFeatures(SDK_ROUTE_IDS)).toContain("webhooks.write");
    expect(
      enabledSdkFeatures(SDK_ROUTE_IDS.filter((id) => id !== "redeliverWebhook")),
    ).not.toContain("webhooks.write");
  });

  it("never asks for an Idempotency-Key on webhook resource routes", () => {
    const doc = buildSdkOpenApiDocument() as {
      paths: Record<string, Record<string, { parameters: { name: string }[] }>>;
    };
    for (const id of SDK_FEATURE_ROUTES["webhooks.write"]) {
      const route = SDK_ROUTES[id];
      const params = doc.paths[route.path]?.[route.method]?.parameters ?? [];
      expect(params.map((p) => p.name)).not.toContain("Idempotency-Key");
    }
  });

  it("publishes an OpenAPI 3.1 webhooks entry with the signing headers per event type", () => {
    const doc = buildSdkOpenApiDocument() as {
      webhooks: Record<string, { post: { parameters: { name: string }[] } }>;
    };
    expect(Object.keys(doc.webhooks).sort()).toEqual(
      [...WEBHOOK_EVENT_TYPES, "webhook.test"].sort(),
    );
    for (const entry of Object.values(doc.webhooks))
      expect(entry.post.parameters.map((p) => p.name)).toEqual([
        "webhook-id",
        "webhook-timestamp",
        "webhook-signature",
      ]);
  });

  it("refuses the test event as a subscription and duplicate events", () => {
    expect(
      createWebhookEndpointBodySchema.safeParse({
        url: "https://x.example",
        events: ["webhook.test"],
      }).success,
    ).toBe(false);
    expect(
      createWebhookEndpointBodySchema.safeParse({
        url: "https://x.example",
        events: ["sandbox.ready", "sandbox.ready"],
      }).success,
    ).toBe(false);
    expect(
      createWebhookEndpointBodySchema.safeParse({
        url: "https://x.example",
        events: ["sandbox.ready"],
        operationKinds: "all",
      }).success,
    ).toBe(true);
  });

  it("accepts only the whsec_ secret shape", () => {
    const endpoint = {
      id: "ep1",
      url: "https://x.example/h",
      description: null,
      events: ["sandbox.ready"],
      operationKinds: "all",
      payloadVersion: 1,
      enabled: true,
      disabledAt: null,
      disabledReason: null,
      secretVersion: 1,
      previousSecretExpiresAt: null,
      health: {
        consecutiveFailures: 0,
        failingSince: null,
        lastSuccessAt: null,
        lastFailureAt: null,
        lastFailureClass: null,
      },
      createdAt: "2026-11-02T00:00:00.000Z",
      updatedAt: "2026-11-02T00:00:00.000Z",
    };
    const secret = `whsec_${Buffer.alloc(32, 7).toString("base64")}`;
    expect(webhookEndpointWithSecretSchema.safeParse({ endpoint, secret }).success).toBe(true);
    expect(
      webhookEndpointWithSecretSchema.safeParse({ endpoint, secret: "wssp_sdk_x" }).success,
    ).toBe(false);
  });

  it("rejects payload fields beyond the public subset", () => {
    const base = {
      id: `evt_${"a".repeat(32)}`,
      type: "operation.completed",
      schemaVersion: 1,
      occurredAt: "2026-11-02T00:00:00.000Z",
      data: {
        operation: {
          id: "op1",
          sandboxId: "sb1",
          kind: "RUN_COMMAND",
          state: "SUCCEEDED",
          outcome: "succeeded",
          errorCode: null,
          failure: null,
          completedAt: null,
        },
      },
    };
    expect(webhookEventPayloadSchema.safeParse(base).success).toBe(true);
    for (const extra of ["result", "errorDetail", "idempotencyKey", "output"])
      expect(
        webhookEventPayloadSchema.safeParse({
          ...base,
          data: { operation: { ...base.data.operation, [extra]: "x" } },
        }).success,
      ).toBe(false);
  });
});

describe("shared IP helpers", () => {
  it("parses host addresses and tests containment", () => {
    const range = parseCidr("100.64.0.0/10");
    expect(cidrContains(range, parseIpAddress("100.100.1.2")!)).toBe(true);
    expect(cidrContains(range, parseIpAddress("100.128.0.1")!)).toBe(false);
    expect(cidrContains(parseCidr("fc00::/7"), parseIpAddress("fd00:ec2::254")!)).toBe(true);
    expect(cidrContains(parseCidr("10.0.0.0/8"), parseIpAddress("::ffff:10.0.0.1")!)).toBe(false);
    expect(parseIpAddress("127.1")).toBeNull();
    expect(parseIpAddress("fe80::1%eth0")).toBeNull();
  });
});
