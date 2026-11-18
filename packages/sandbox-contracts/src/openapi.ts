import { z } from "zod";
import {
  credentialAccountDtoSchema,
  credentialAccountPageSchema,
  credentialDefinitionCreatedDtoSchema,
  credentialDefinitionDetailDtoSchema,
  credentialDefinitionDtoSchema,
  credentialDefinitionPageSchema,
  credentialDeletedSchema,
  credentialDtoSchema,
  credentialEventPageSchema,
  credentialInstanceDtoSchema,
  credentialInstancePageSchema,
  credentialLeasePageSchema,
  credentialLeaseReleasedSchema,
  credentialPageSchema,
  credentialValueWriteResultSchema,
} from "./credentials";
import {
  API_VERSION,
  capabilitiesSchema,
  hostPageSchema,
  hostSchema,
  poolCapacitySchema,
  poolDetailSchema,
  poolMemberPageSchema,
  poolMemberSchema,
  poolPageSchema,
  poolSchema,
  sandboxCapabilitiesSchema,
  sandboxPageSchema,
  sandboxSchema,
  templateAvailabilityPageSchema,
  templateAvailabilitySchema,
  templatePageSchema,
  templateRevisionPageSchema,
  templateRevisionSchema,
  templateSchema,
} from "./dto";
import { SDK_ERRORS, sdkErrorCodesForStatus, sdkErrorEnvelopeSchema } from "./errors";
import { keyInfoSchema, keyRevokedSchema } from "./keys";
import { idempotencyKeySchema, mutationReceiptSchema } from "./mutations";
import { processConnectionSchema, processInfoSchema, processRefSchema } from "./processes";
import { entryInfoSchema, failureSchema, operationResultSchema } from "./results";
import { SDK_ROUTES, type SdkRoute, sdkRouteErrorStatuses } from "./routes";
import {
  communityTemplateCreatedSchema,
  templateBuildContextSchema,
  templateBuildCreatedSchema,
  templateBuildLogsSchema,
  templateBuildPageSchema,
  templateBuildSchema,
  templateBuildStepSchema,
} from "./template-builds";
import { TRANSFER_CHUNK_BYTES, transferReceiptSchema } from "./transfers";
import { sandboxTunnelPortsSchema, sandboxTunnelSchema, tunnelLinkSchema } from "./tunnels";
import {
  WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS,
  type WebhookEventType,
  webhookDeletedSchema,
  webhookDeliveryAcceptedSchema,
  webhookDeliveryAttemptSchema,
  webhookDeliveryDetailSchema,
  webhookDeliveryPageSchema,
  webhookDeliverySchema,
  webhookEndpointPageSchema,
  webhookEndpointSchema,
  webhookEndpointWithSecretSchema,
  webhookEventSchemas,
} from "./webhooks";

type JsonObject = Record<string, unknown>;

/** Named components, in document order. Response schemas must be listed here. */
const COMPONENTS: ReadonlyArray<readonly [string, z.ZodType]> = [
  ["EntryInfo", entryInfoSchema],
  ["ProcessRef", processRefSchema],
  ["ProcessInfo", processInfoSchema],
  ["ProcessConnection", processConnectionSchema],
  ["OperationFailure", failureSchema],
  ["OperationResult", operationResultSchema],
  ["Host", hostSchema],
  ["HostPage", hostPageSchema],
  ...(
    [
      "startHostCommand",
      "writeHostCommandStdin",
      "queueHostCommand",
      "readHostFile",
      "listHostFiles",
      "writeHostFile",
      "editHostFile",
    ] as const
  ).map((id) => {
    const route = SDK_ROUTES[id];
    return [route.response.name, route.response.schema] as const;
  }),
  ["Pool", poolSchema],
  ["PoolDetail", poolDetailSchema],
  ["PoolCapacity", poolCapacitySchema],
  ["PoolPage", poolPageSchema],
  ["PoolMember", poolMemberSchema],
  ["PoolMemberPage", poolMemberPageSchema],
  ["Template", templateSchema],
  ["TemplatePage", templatePageSchema],
  ["TemplateRevision", templateRevisionSchema],
  ["TemplateRevisionPage", templateRevisionPageSchema],
  ["TemplateAvailability", templateAvailabilitySchema],
  ["TemplateAvailabilityPage", templateAvailabilityPageSchema],
  ["Sandbox", sandboxSchema],
  ["SandboxPage", sandboxPageSchema],
  ["Operation", SDK_ROUTES.getOperation.response.schema],
  ["CommandOutputPage", SDK_ROUTES.getCommandOutput.response.schema],
  ["MutationReceipt", mutationReceiptSchema],
  ["TransferReceipt", transferReceiptSchema],
  ["Capabilities", capabilitiesSchema],
  ["SandboxCapabilities", sandboxCapabilitiesSchema],
  ["KeyInfo", keyInfoSchema],
  ["KeyRevoked", keyRevokedSchema],
  ["SandboxTunnel", sandboxTunnelSchema],
  ["SandboxTunnelPorts", sandboxTunnelPortsSchema],
  ["TunnelLink", tunnelLinkSchema],
  ["ErrorEnvelope", sdkErrorEnvelopeSchema],
  ["WebhookEndpoint", webhookEndpointSchema],
  ["WebhookEndpointPage", webhookEndpointPageSchema],
  ["WebhookEndpointWithSecret", webhookEndpointWithSecretSchema],
  ["WebhookEndpointDeleted", webhookDeletedSchema],
  ["WebhookDelivery", webhookDeliverySchema],
  ["WebhookDeliveryAttempt", webhookDeliveryAttemptSchema],
  ["WebhookDeliveryDetail", webhookDeliveryDetailSchema],
  ["WebhookDeliveryPage", webhookDeliveryPageSchema],
  ["WebhookDeliveryAccepted", webhookDeliveryAcceptedSchema],
  ["TemplateBuildStep", templateBuildStepSchema],
  ["TemplateBuild", templateBuildSchema],
  ["TemplateBuildPage", templateBuildPageSchema],
  ["TemplateBuildContext", templateBuildContextSchema],
  ["TemplateBuildCreated", templateBuildCreatedSchema],
  ["CommunityTemplateCreated", communityTemplateCreatedSchema],
  ["TemplateBuildLogs", templateBuildLogsSchema],
  ["CredentialDefinition", credentialDefinitionDtoSchema],
  ["CredentialDefinitionPage", credentialDefinitionPageSchema],
  ["CredentialDefinitionDetail", credentialDefinitionDetailDtoSchema],
  ["CredentialDefinitionCreated", credentialDefinitionCreatedDtoSchema],
  ["Credential", credentialDtoSchema],
  ["CredentialPage", credentialPageSchema],
  ["CredentialDeleted", credentialDeletedSchema],
  ["CredentialEventPage", credentialEventPageSchema],
  ["CredentialAccount", credentialAccountDtoSchema],
  ["CredentialAccountPage", credentialAccountPageSchema],
  ["CredentialInstance", credentialInstanceDtoSchema],
  ["CredentialInstancePage", credentialInstancePageSchema],
  ["CredentialLeasePage", credentialLeasePageSchema],
  ["CredentialValueWritten", credentialValueWriteResultSchema],
  ["CredentialLeaseReleased", credentialLeaseReleasedSchema],
  ...(Object.entries(webhookEventSchemas) as [WebhookEventType, z.ZodType][]).map(
    ([type, schema]) => [webhookEventComponentName(type), schema] as const,
  ),
];

/** `sandbox.create_failed` → `WebhookEventSandboxCreateFailed`. */
function webhookEventComponentName(type: WebhookEventType): string {
  return `WebhookEvent${type
    .split(/[._]/)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("")}`;
}

const webhookHeaders: JsonObject[] = [
  {
    name: "webhook-id",
    in: "header",
    required: true,
    description: "Event id. Stable across retries and redeliveries: the dedupe key.",
    schema: { type: "string", pattern: "^evt_[0-9a-f]{32}$" },
  },
  {
    name: "webhook-timestamp",
    in: "header",
    required: true,
    description: `Unix seconds when this attempt was signed. Reject values more than ${WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS} s from your clock.`,
    schema: { type: "string", pattern: "^[0-9]+$" },
  },
  {
    name: "webhook-signature",
    in: "header",
    required: true,
    description:
      "Space-separated `v1,<base64 HMAC-SHA256>` values over `<webhook-id>.<webhook-timestamp>.<raw body>`, keyed by the base64-decoded part of the `whsec_` secret. Two values during a rotation overlap.",
    schema: { type: "string" },
  },
];

/** OpenAPI 3.1 top-level `webhooks`: one outbound request per event type. */
function webhookDocuments(): Record<string, JsonObject> {
  return Object.fromEntries(
    (Object.keys(webhookEventSchemas) as WebhookEventType[]).map((type) => [
      type,
      {
        post: {
          operationId: `webhook_${type.replace(/[^A-Za-z0-9]/g, "_")}`,
          summary: `Delivered when \`${type}\` occurs. At-least-once, unordered; dedupe by webhook-id.`,
          security: [],
          parameters: webhookHeaders,
          requestBody: {
            required: true,
            content: {
              "application/json": { schema: ref(webhookEventComponentName(type)) },
            },
          },
          responses: {
            "2XX": {
              description: "Accepted. Any other status, a redirect or a timeout is retried.",
            },
          },
        },
      },
    ]),
  );
}

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });

function stripMeta(schema: JsonObject): JsonObject {
  const { $schema: _schema, $id: _id, ...rest } = schema;
  return rest;
}

function componentSchemas(): Record<string, JsonObject> {
  const registry = z.registry<{ id: string }>();
  for (const [id, schema] of COMPONENTS) registry.add(schema, { id });
  const generated = z.toJSONSchema(registry, {
    target: "draft-2020-12",
    uri: (id) => `#/components/schemas/${id}`,
  }).schemas as Record<string, JsonObject>;
  const out: Record<string, JsonObject> = {};
  for (const [id] of COMPONENTS) {
    const schema = generated[id];
    if (!schema) throw new Error(`OpenAPI component ${id} was not generated.`);
    out[id] = stripMeta(schema);
  }
  return out;
}

function parameters(route: SdkRoute): JsonObject[] {
  const out: JsonObject[] = [];
  const add = (location: "path" | "query", object: z.ZodObject | null) => {
    if (!object) return;
    for (const [name, field] of Object.entries(object.shape)) {
      const schema = field as z.ZodType;
      out.push({
        name,
        in: location,
        required: location === "path" || !schema.safeParse(undefined).success,
        schema: stripMeta(z.toJSONSchema(schema, { io: "input" }) as JsonObject),
      });
    }
  };
  add("path", route.params);
  add("query", route.query);
  if (route.body && route.idempotency !== false)
    out.push({
      name: "Idempotency-Key",
      in: "header",
      required: true,
      schema: z.toJSONSchema(idempotencyKeySchema),
    });
  if (route.binary && !route.chunkOffsetInPath)
    out.push({
      name: "Content-Range",
      in: "header",
      required: true,
      schema: { type: "string", pattern: "^bytes [0-9]+-[0-9]+/[0-9]+$" },
      description:
        "Inclusive byte range; known total must equal the reservation. Fixed 1 MiB chunks except the final chunk.",
    });
  if (route.binaryResponse) {
    out.push({
      name: "Range",
      in: "header",
      required: false,
      schema: { type: "string", pattern: "^bytes=(?:[0-9]+-[0-9]*|-[0-9]+)$" },
      description:
        "One byte range. Multiple ranges, other units and unsatisfiable ranges return 416.",
    });
    out.push({
      name: "If-Range",
      in: "header",
      required: false,
      schema: { type: "string" },
      description:
        "The strong ETag from an earlier response. On a mismatch the whole content is returned (200).",
    });
  }
  return out;
}

const requestIdHeader = {
  "X-Request-Id": {
    description: "Server-generated request ID, also echoed in error bodies.",
    schema: { type: "string", format: "uuid" },
  },
};

function errorResponse(route: SdkRoute, status: number): JsonObject {
  const codes =
    status === 404 && route.notFound
      ? [
          route.notFound,
          ...(route.errors ?? []).filter(
            (code) => code !== route.notFound && SDK_ERRORS[code][0] === 404,
          ),
        ]
      : sdkErrorCodesForStatus(status);
  const headers: JsonObject = { ...requestIdHeader };
  if (status === 401) {
    headers["WWW-Authenticate"] = { schema: { type: "string" } };
  }
  if (status === 429 || status === 503) {
    headers["Retry-After"] = { schema: { type: "integer", minimum: 1 } };
  }
  if (status === 409) {
    headers["Retry-After"] = {
      description:
        "On host.node_offline, capacity, quota and pool refusals with `retryable: true` (the deployment's `CAPACITY_RETRY_AFTER_SECONDS`). Never sent with `retryable: false`.",
      schema: { type: "integer", minimum: 1 },
    };
  }
  if (status === 416) {
    headers["Content-Range"] = {
      description: "`bytes */<size>`: the complete length of the content.",
      schema: { type: "string" },
    };
  }
  return {
    description: `Error codes: ${codes.join(", ")}.`,
    headers,
    content: { "application/json": { schema: ref("ErrorEnvelope") } },
  };
}

const binaryHeaders = {
  ...requestIdHeader,
  ETag: {
    description: "Quoted lowercase hex SHA-256 of the whole capture (strong validator).",
    schema: { type: "string", pattern: '^"[a-f0-9]{64}"$' },
  },
  "Repr-Digest": {
    description: "RFC 9530 `sha-256=:<base64>:` digest of the whole capture.",
    schema: { type: "string" },
  },
  "Accept-Ranges": { schema: { type: "string", const: "bytes" } },
  "Content-Length": { schema: { type: "integer", minimum: 0 } },
};

function binaryResponses(route: SdkRoute): Record<string, JsonObject> {
  const content = {
    "application/octet-stream": { schema: { type: "string", format: "binary" } },
  };
  return {
    "200": { description: route.summary, headers: binaryHeaders, content },
    "206": {
      description: "One requested byte range of the capture.",
      headers: {
        ...binaryHeaders,
        "Content-Range": { schema: { type: "string", pattern: "^bytes [0-9]+-[0-9]+/[0-9]+$" } },
      },
      content,
    },
  };
}

function operation(id: string, route: SdkRoute): JsonObject {
  const responses: Record<string, JsonObject> = route.binaryResponse
    ? binaryResponses(route)
    : {
        [route.successStatus ?? (route.method === "get" ? "200" : "202")]: {
          description: route.summary,
          headers: {
            ...requestIdHeader,
            ...(route.response.name === "MutationReceipt" || route.successStatus === 201
              ? { Location: { schema: { type: "string" } } }
              : {}),
          },
          content: { "application/json": { schema: ref(route.response.name) } },
        },
      };
  for (const status of sdkRouteErrorStatuses(route)) {
    responses[String(status)] = errorResponse(route, status);
  }
  return {
    ...(route.binary
      ? {
          requestBody: {
            required: true,
            content: {
              "application/octet-stream": {
                schema: { type: "string", format: "binary", maxLength: TRANSFER_CHUNK_BYTES },
              },
            },
          },
        }
      : {}),
    ...(route.body
      ? {
          requestBody: {
            required: false,
            content: {
              "application/json": { schema: z.toJSONSchema(route.body, { io: "output" }) },
            },
          },
        }
      : {}),
    operationId: id,
    summary: route.summary,
    "x-wssp-scopes": [...route.scopes],
    ...(route.feature ? { "x-wssp-feature": route.feature } : {}),
    parameters: parameters(route),
    responses,
  };
}

/**
 * The public, static OpenAPI 3.1 document for the SDK plane. It is built only
 * from this package's registry and DTO schemas, so it can contain no admin,
 * browser or internal procedures.
 */
export function buildSdkOpenApiDocument(): JsonObject {
  const paths: Record<string, Record<string, JsonObject>> = {
    "/v1/openapi.json": {
      get: {
        operationId: "getOpenApiDocument",
        summary: "This document. It is the only /v1 route that needs no bearer key.",
        security: [],
        responses: {
          "200": {
            description: "OpenAPI 3.1 document.",
            headers: requestIdHeader,
            content: { "application/json": { schema: { type: "object" } } },
          },
          "429": {
            description: `Error codes: ${sdkErrorCodesForStatus(429).join(", ")}.`,
            content: { "application/json": { schema: ref("ErrorEnvelope") } },
          },
          "503": {
            description: `Error codes: ${sdkErrorCodesForStatus(503).join(", ")}.`,
            content: { "application/json": { schema: ref("ErrorEnvelope") } },
          },
        },
      },
    },
  };
  for (const [id, route] of Object.entries(SDK_ROUTES) as [string, SdkRoute][]) {
    const entry = paths[route.path] ?? {};
    entry[route.method] = operation(id, route);
    paths[route.path] = entry;
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "wssp SDK API",
      version: API_VERSION,
      license: { name: "MIT", identifier: "MIT" },
      description:
        "Owner-scoped sandbox control plane. Send `Authorization: Bearer wssp_sdk_…`. " +
        "Errors use a fixed envelope whose codes come from a stable catalog.",
    },
    security: [{ bearerAuth: [] }],
    "x-wssp-error-catalog": Object.fromEntries(
      Object.entries(SDK_ERRORS).map(([code, [status, message]]) => [code, { status, message }]),
    ),
    paths,
    webhooks: webhookDocuments(),
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", description: "An SDK key (wssp_sdk_…)." },
      },
      schemas: componentSchemas(),
    },
  };
}
