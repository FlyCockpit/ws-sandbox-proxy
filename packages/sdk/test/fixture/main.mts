// Consumer smoke program: import the packed tarball, type-check its surface
// and exercise one typed error, with zod as the only installed dependency.
import {
  createWsspClient,
  createWsspTransport,
  isWsspError,
  type MutationReceiptDto,
  type Sandbox,
  type SandboxDto,
  type WsspClient,
  type WsspTransport,
} from "@wssp/sdk";

const transport: WsspTransport = createWsspTransport({
  baseUrl: "https://api.example.test",
  apiKey: ["wssp", "sdk", "fixture", "key"].join("_"),
  fetch: async () =>
    Response.json(
      {
        error: {
          code: "UNAUTHORIZED",
          message: "A valid SDK bearer key is required.",
          requestId: crypto.randomUUID(),
        },
      },
      { status: 401 },
    ),
});

const rejected = await transport.request("getSandbox", { params: { id: "sbx_1" } }).then(
  () => null,
  (error: unknown) => error,
);
if (!isWsspError(rejected, "authorization") || rejected.code !== "UNAUTHORIZED") {
  throw new Error("expected a typed authorization error");
}
if (JSON.stringify(rejected).includes(["wssp", "sdk", "fixture", "key"].join("_"))) {
  throw new Error("the serialized error leaked the key");
}

const receipt: MutationReceiptDto | null = null;
const sandbox: SandboxDto | null = await transport.findSandbox("sbx_2").then(
  () => {
    throw new Error("unreachable");
  },
  () => null,
);
// The C40 lifecycle client: one fake-scripted create flow to READY.
const NOW = "2026-01-01T00:00:00.000Z";
const responses = [
  { operationId: "op_1", state: "QUEUED", location: "/v1/operations/op_1" },
  {
    id: "op_1",
    sandboxId: "sbx_9",
    kind: "CREATE_SANDBOX",
    failure: null,
    leaseIntent: {
      acceptedAt: NOW,
      timeoutMs: 300000,
      revision: 1,
      endAt: NOW,
      onTimeout: "kill",
      acknowledgedAt: NOW,
      acknowledgedAttempt: 1,
      acknowledgedEpoch: 1,
    },
    state: "SUCCEEDED",
    outcome: "succeeded",
    generation: 1,
    errorCode: null,
    createdAt: NOW,
    updatedAt: NOW,
    dispatchedAt: NOW,
    completedAt: NOW,
  },
  {
    id: "sbx_9",
    name: "quiet-otter",
    hostId: "host_1",
    storageId: "storage_1",
    storagePoolName: "default",
    storageMarker: "marker_1",
    templateId: "tpl_1",
    templateRevisionId: "tpl_1",
    originPoolId: null,
    cpuCount: 1,
    memoryMiB: 1024,
    diskGiB: 32,
    state: "READY",
    generation: 1,
    endAt: null,
    startedAt: null,
    readyAt: null,
    lifecycle: { onTimeout: "kill", autoResume: false },
    sandboxDomain: null,
    portExposure: null,
    lease: { revision: 0, expiresAt: null, onExpire: "stop", requested: null, effective: null },
    egress: { mode: "allowlist", domains: [], cidrs: [] },
    egressRequest: null,
    egressModeReason: null,
    egressDeniedGrants: [],
    guestSudo: true,
    guestSudoRequested: true,
    guestSudoReason: null,
    guestRoot: true,
    disk: {
      location: "host",
      offloadState: "none",
      offloadFailure: null,
      offloadedAt: null,
      sizeBytes: null,
      eligibility: "any_host",
      offloadPin: "ANY",
      offloadPolicy: { mode: "on_stop" },
      offloadDueAt: null,
    },
    metadata: {},
    createdAt: NOW,
    updatedAt: NOW,
  },
];
const client: WsspClient = createWsspClient({
  baseUrl: "https://api.example.test",
  apiKey: ["wssp", "sdk", "fixture", "key"].join("_"),
  fetch: async () => {
    const next = responses.shift();
    if (!next) throw new Error("unexpected call");
    return Response.json(next, { status: responses.length === 2 ? 202 : 200 });
  },
  polling: { intervalMs: 1, maxIntervalMs: 2, waitTimeoutMs: 5_000 },
});
const created: Sandbox = await client.sandboxes.create(
  { template: "revision/" + "tpl_1", sandboxHostId: "host_1" },
  { idempotencyKey: "fixture-create" },
);
if (
  created.state !== "READY" ||
  created.id !== "sbx_9" ||
  typeof created.commands.run !== "function" ||
  typeof created.files.upload !== "function"
) {
  throw new Error("expected create to resolve a READY sandbox");
}

// The C42 transfers/files surface: a tiny scripted server speaking the
// documented wire protocol, proving upload + download roundtrip from the
// packed tarball.
import { createHash } from "node:crypto";

const payload = new TextEncoder().encode("hello wssp");
// The fixture stores the ACTUAL bytes the SDK PUT on the wire and serves
// exactly those back, so the roundtrip proves wire content, not a constant.
let stored: Uint8Array | undefined;
const storedDigest = () => createHash("sha256").update(stored!).digest("hex");
const transferId = crypto.randomUUID();
const receiptJson = (over: Record<string, unknown> = {}) => ({
  id: transferId,
  sandboxId: "sbx_9",
  generation: 1,
  direction: "UPLOAD",
  state: "OPEN",
  totalBytes: payload.byteLength,
  receivedBytes: 0,
  chunkBytes: 1_048_576,
  idleExpiresAt: NOW,
  expiresAt: NOW,
  ...over,
});
const transferClient = createWsspClient({
  baseUrl: "https://api.example.test",
  apiKey: ["wssp", "sdk", "fixture", "key"].join("_"),
  polling: { intervalMs: 1, maxIntervalMs: 2, waitTimeoutMs: 5_000 },
  fetch: async (url, init) => {
    const path = new URL(String(url)).pathname;
    const headers = (init?.headers ?? {}) as Record<string, string>;
    if (path.endsWith("/v1/transfers") && init?.method === "POST") {
      return Response.json(receiptJson(), { status: 201 });
    }
    if (path.endsWith(`/v1/transfers/${transferId}`) && init?.method === "PUT") {
      stored = new Uint8Array(init?.body as Uint8Array);
      if (headers["content-range"] !== `bytes 0-${stored.byteLength - 1}/${stored.byteLength}`) {
        throw new Error("bad content-range");
      }
      return Response.json(receiptJson({ receivedBytes: stored.byteLength }));
    }
    if (path.endsWith(`/v1/transfers/${transferId}/commit`)) {
      const body = JSON.parse(String(init?.body)) as { sha256: string };
      if (body.sha256 !== storedDigest()) throw new Error("commit hash mismatch");
      return Response.json(
        { operationId: "op_put", state: "QUEUED", location: "/v1/operations/op_put" },
        { status: 202 },
      );
    }
    if (path.endsWith("/v1/operations/op_put")) {
      return Response.json({
        id: "op_put",
        sandboxId: "sbx_9",
        kind: "PUT_FILE",
        leaseIntent: null,
        failure: null,
        state: "SUCCEEDED",
        outcome: "succeeded",
        generation: 1,
        errorCode: null,
        createdAt: NOW,
        updatedAt: NOW,
        dispatchedAt: NOW,
        completedAt: NOW,
      });
    }
    if (path.endsWith("/v1/sandboxes/sbx_9/files/download")) {
      return Response.json(
        { operationId: "op_get", state: "QUEUED", location: "/v1/operations/op_get" },
        { status: 202 },
      );
    }
    if (path.endsWith("/v1/operations/op_get")) {
      return Response.json({
        id: "op_get",
        sandboxId: "sbx_9",
        kind: "GET_FILE",
        leaseIntent: null,
        failure: null,
        state: "SUCCEEDED",
        outcome: "succeeded",
        generation: 1,
        errorCode: null,
        createdAt: NOW,
        updatedAt: NOW,
        dispatchedAt: NOW,
        completedAt: NOW,
      });
    }
    if (path.endsWith("/v1/operations/op_get/content")) {
      if (stored === undefined) throw new Error("content requested before any PUT");
      return new Response(stored, {
        status: 200,
        headers: {
          etag: `"${storedDigest()}"`,
          "content-length": String(stored.byteLength),
          "accept-ranges": "bytes",
        },
      });
    }
    throw new Error(`unexpected call ${init?.method} ${path}`);
  },
});
const upload = await transferClient.files.upload("sbx_9", "/app/hi.txt", payload, {
  idempotencyKey: "fixture-upload",
});
const roundtrip = await transferClient.files.readBytes("sbx_9", "/app/hi.txt", {
  idempotencyKey: "fixture-download",
});
const uploaded = upload.sha256 === storedDigest() && upload.totalBytes === stored!.byteLength;
const roundtripped =
  roundtrip.byteLength === stored!.byteLength && roundtrip.every((b, i) => b === stored![i]);

process.stdout.write(
  `consumer ok ${receipt === null} ${sandbox === null} ${created.state === "READY"} ${uploaded} ${roundtripped}\n`,
);

// Command map types and request serialization survive packing the SDK.
import type { CommandInput } from "@wssp/sdk";

const commandInput: CommandInput = { argv: ["true"], envs: { APP_MODE: "fixture" } };
const commandClient = createWsspClient({
  baseUrl: "https://api.example.test",
  apiKey: ["wssp", "sdk", "fixture", "key"].join("_"),
  polling: { intervalMs: 1, maxIntervalMs: 2, waitTimeoutMs: 5000 },
  fetch: async (url, init) => {
    if (new URL(url).pathname === "/v1/operations/op_env/result")
      return Response.json({
        operationId: "op_env",
        sandboxId: "sbx_9",
        generation: 1,
        kind: "RUN_COMMAND",
        outcome: "pending",
        observedAt: NOW,
        expiresAt: null,
        result: {
          type: "command",
          process: {
            sandboxId: "sbx_9",
            generation: 1,
            processId: "proc_env",
            attempt: 1,
            pid: 42,
          },
          startedAt: NOW,
          exitCode: null,
        },
      });
    const body = JSON.parse(String(init?.body)) as { envs?: Record<string, string>; env?: unknown };
    if (body.envs?.APP_MODE !== "fixture" || "env" in body)
      throw new Error("invalid command envs map");
    return Response.json(
      { operationId: "op_env", state: "QUEUED", location: "/v1/operations/op_env" },
      { status: 202 },
    );
  },
});
const handle = await commandClient.commands.start("sbx_9", commandInput);
if (
  handle.process.pid !== 42 ||
  typeof handle.closeStdin !== "function" ||
  typeof handle.disconnect !== "function"
)
  throw new Error("expected a qualified handle");
handle.disconnect();
const legacyCommand: CommandInput = {
  argv: ["true"],
  // @ts-expect-error The env tuple form is not part of CommandInput.
  env: [["APP_MODE", "fixture"]],
};
void legacyCommand;

// The strict low-level transport exposes the same map input type.
import type { RouteRequest } from "@wssp/sdk";

const transportCommand: RouteRequest<"startCommand"> = {
  params: { id: "sbx_9" },
  idempotencyKey: "typed-envs",
  body: { argv: ["true"], envs: { APP_MODE: "fixture" } },
};
const invalidTransportCommand: RouteRequest<"startCommand"> = {
  params: { id: "sbx_9" },
  idempotencyKey: "typed-envs-invalid",
  body: {
    argv: ["true"],
    // @ts-expect-error Both public command entry points require a string map.
    envs: [["APP_MODE", "fixture"]],
  },
};
void transportCommand;
void invalidTransportCommand;
