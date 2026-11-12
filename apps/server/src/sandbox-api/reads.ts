import { ORPCError } from "@orpc/server";
import { readCredentialsAvailability } from "@wssp/api/credentials/availability";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import {
  deploymentQueuePerKey,
  deploymentQueuePerOwner,
  deploymentWaitMaxMs,
} from "@wssp/api/sandbox/capacity-limits";
import { isCapacityWaitingOperation } from "@wssp/api/sandbox/capacity-queue";
import { getPoolCapacity } from "@wssp/api/sandbox/capacity-view";
import { idempotencyKey } from "@wssp/api/sandbox/contracts";
import { accountImageQuotas, imageDistributionMode } from "@wssp/api/sandbox/image-store/config";
import { deploymentFiniteMaxMs, deploymentLeaseMaxMs } from "@wssp/api/sandbox/lease-policy";
import { getOperationResult } from "@wssp/api/sandbox/operation-results";
import { withOperationWait } from "@wssp/api/sandbox/operation-waiters";
import { connectProcess } from "@wssp/api/sandbox/process-connect";
import {
  sdkGetKeyGrant,
  sdkGetOperation,
  sdkGetPool,
  sdkGetSandbox,
  sdkListHosts,
  sdkListPoolMembers,
  sdkListPools,
  sdkListSandboxes,
  sdkListTemplateAvailability,
  sdkListTemplateRevisions,
  sdkListTemplates,
} from "@wssp/api/sandbox/sdk-reads";
import { getSandboxCapabilities } from "@wssp/api/sandbox/services/capabilities";
import { getCommandOutput } from "@wssp/api/sandbox/services/sandboxes";
import { templateBuildCapabilities } from "@wssp/api/template-builds/config";
import { webhooksConfigured } from "@wssp/api/webhooks/config";
import prisma from "@wssp/db";
import { env } from "@wssp/env/server";
import {
  API_VERSION,
  enabledSdkFeatures,
  FS_PROCESS_LIMITS,
  guestApiCapabilities,
  isSdkErrorCode,
  JSON_BODY_MAX_BYTES,
  JSON_ROUTE_IDS,
  type JsonRouteId,
  operationOutcome,
  PAGE_SIZE_DEFAULT,
  PAGE_SIZE_MAX,
  SDK_ERRORS,
  SDK_ROUTE_IDS,
  SDK_ROUTES,
  type SdkRoute,
  type SdkRouteId,
  VM_SIZE_PUBLIC_LIMITS,
} from "@wssp/sandbox-contracts";
import type { Hono } from "hono";
import type { z } from "zod";
import { ZodError } from "zod";
import type { SandboxApiEnv } from "./auth.js";
import { commandMutationHandlers } from "./commands.js";
import { credentialHandlers } from "./credentials.js";
import { fileMutationHandlers } from "./files.js";
import { sandboxMutationHandlers } from "./sandboxes.js";
import { templateBuildHandlers } from "./template-builds.js";
import { templateMutationHandlers } from "./templates.js";
import { webhookHandlers } from "./webhooks.js";

type Routes = typeof SDK_ROUTES;
type RouteParams<K extends SdkRouteId> = Routes[K]["params"] extends null
  ? Record<string, never>
  : NonNullable<Routes[K]["params"]> extends z.ZodType
    ? z.output<NonNullable<Routes[K]["params"]>>
    : Record<string, never>;
type RouteInput<K extends SdkRouteId> = {
  params: RouteParams<K>;
  query: z.output<Routes[K]["query"]>;
} & (Routes[K] extends { body: infer B extends z.ZodType }
  ? { body: z.output<B>; idempotencyKey: string }
  : { body?: never; idempotencyKey?: never });
/** Per-request context: `signal` aborts when the client disconnects. */
type RouteContext = { signal?: AbortSignal };
export type RouteHandlers = {
  [K in JsonRouteId]: (
    principal: ServicePrincipal,
    input: RouteInput<K>,
    context?: RouteContext,
  ) => Promise<
    Routes[K]["response"]["name"] extends "MutationReceipt"
      ? { operationId: string; state: import("@wssp/sandbox-contracts").OperationStateDto }
      : z.input<Routes[K]["response"]["schema"]>
  >;
};

/** Routes answered with a resource (not an operation receipt) that set `Location`. */
const CREATED_LOCATION: Partial<Record<JsonRouteId, (value: unknown) => string>> = {
  createWebhookEndpoint: (value) =>
    `/v1/webhooks/endpoints/${(value as { endpoint: { id: string } }).endpoint.id}`,
  createTemplateBuild: (value) =>
    `/v1/template-builds/${(value as { build: { id: string } }).build.id}`,
  createCredentialDefinition: (value) =>
    `/v1/credential-definitions/${(value as { id: string }).id}`,
  createCredential: (value) => `/v1/credentials/${(value as { id: string }).id}`,
};

/**
 * One handler per registry route, enforced by the mapped type: adding a route
 * to @wssp/sandbox-contracts fails type-checking here until it is served.
 * `registered` is the list the server actually mounted, so capabilities report
 * only features whose routes exist.
 */
export function sdkReadHandlers(registered: readonly SdkRouteId[]): RouteHandlers {
  return {
    getOperationResult: (owner, { params, query }, context) =>
      withOperationWait({
        ownerId: owner.ownerId,
        operationId: params.id,
        waitMs: query.waitMs,
        signal: context?.signal,
        read: () => getOperationResult(owner, { operationId: params.id }),
        ready: () => true,
        notReady: isResultNotReady,
      }),
    getSandboxCapabilities: (owner, { params }) =>
      getSandboxCapabilities(owner, { id: params.id, routes: registered }),
    connectProcess: (owner, { params, query }) =>
      connectProcess(owner, { process: { sandboxId: params.id, pid: params.pid, ...query } }),
    ...sandboxMutationHandlers,
    ...commandMutationHandlers,
    ...fileMutationHandlers,
    ...templateMutationHandlers,
    ...webhookHandlers,
    ...templateBuildHandlers,
    ...credentialHandlers,
    getCapabilities: async (principal) => ({
      apiVersion: API_VERSION,
      // Webhooks are listed only when this server can encrypt endpoint secrets.
      features: enabledSdkFeatures(registered).filter(
        (feature) =>
          (feature !== "webhooks.write" || webhooksConfigured()) &&
          (!feature.startsWith("credentials.") || readCredentialsAvailability().enabled),
      ),
      guestApi: guestApiCapabilities(enabledSdkFeatures(registered).includes("processes.signal")),
      limits: {
        ...FS_PROCESS_LIMITS,
        ...VM_SIZE_PUBLIC_LIMITS,
        commandTimeoutZero:
          FS_PROCESS_LIMITS.commandTimeoutZero &&
          enabledSdkFeatures(registered).includes("commands.execute"),
        sandboxTimeoutMinMs: 1,
        sandboxTimeoutDefaultMs: 300000,
        sandboxTimeoutMaxMs: deploymentFiniteMaxMs(),
        sandboxTimeoutZero: deploymentLeaseMaxMs() === null,
        pageSizeDefault: PAGE_SIZE_DEFAULT,
        pageSizeMax: PAGE_SIZE_MAX,
        jsonBodyMaxBytes: JSON_BODY_MAX_BYTES,
        transferMaxBytes: env.TRANSFER_MAX_BYTES,
        imageStore: {
          mode: imageDistributionMode(),
          ...(await accountImageQuotas(prisma, principal.ownerId)),
        },
        templateBuilds: await templateBuildCapabilities(prisma, principal.ownerId),
        capacityWaitMaxMs: deploymentWaitMaxMs(),
        capacityQueuePerKey: deploymentQueuePerKey(),
        capacityQueuePerOwner: deploymentQueuePerOwner(),
      },
      ports: { ingress: false, proxy: false },
      network: { egressModes: ["open", "allowlist"], defaultEgressMode: "open" },
      key: await sdkGetKeyGrant(principal),
    }),
    listPools: (principal, { query }) => sdkListPools(principal, query),
    getPool: (principal, { params }) => sdkGetPool(principal, params.id),
    listPoolMembers: (principal, { params, query }) =>
      sdkListPoolMembers(principal, params.id, query),
    getPoolCapacity: (principal, { params, query }) =>
      getPoolCapacity(principal, { ...query, id: params.id }),
    listHosts: (principal, { query }) => sdkListHosts(principal, query),
    listTemplateRevisions: (principal, { params, query }) =>
      sdkListTemplateRevisions(principal, {
        ...query,
        limit: query.limit ?? PAGE_SIZE_DEFAULT,
        templateId: params.id,
      }),
    listTemplateAvailability: (principal, { params, query }) =>
      sdkListTemplateAvailability(principal, {
        ...query,
        limit: query.limit ?? PAGE_SIZE_DEFAULT,
        templateId: params.id,
      }),
    listTemplates: (principal, { query }) => sdkListTemplates(principal, query),
    listSandboxes: (principal, { query }) => sdkListSandboxes(principal, query),
    getSandbox: (principal, { params }) => sdkGetSandbox(principal, params.id),
    getOperation: async (principal, { params, query }, context) =>
      (
        await withOperationWait({
          ownerId: principal.ownerId,
          operationId: params.id,
          waitMs: query.waitMs,
          signal: context?.signal,
          read: async () => {
            const operation = await sdkGetOperation(principal, params.id);
            // A create waiting for capacity can wait hours: answer at once
            // (no held waiter slot); the SDK polls it slowly with jitter.
            const waiting =
              operation.outcome === "pending" &&
              operation.kind === "CREATE_SANDBOX" &&
              (await isCapacityWaitingOperation(principal.ownerId, params.id));
            return { operation, waiting };
          },
          ready: ({ operation, waiting }) => waiting || operation.outcome !== "pending",
        })
      ).operation,
    getCommandOutput: (principal, { params, query }, context) =>
      withOperationWait({
        ownerId: principal.ownerId,
        operationId: params.id,
        waitMs: query.waitMs,
        signal: context?.signal,
        read: () =>
          getCommandOutput(principal, {
            operationId: params.id,
            cursor: query.cursor,
            maxBytes: query.maxBytes,
          }),
        ready: outputPageReady,
      }),
  };
}

/** A typed result read that is only "not yet": the long-poll keeps holding it. */
function isResultNotReady(error: unknown): boolean {
  if (!(error instanceof ORPCError)) return false;
  const data: unknown = error.data;
  return (
    typeof data === "object" &&
    data !== null &&
    "code" in data &&
    data.code === "OPERATION_RESULT_NOT_READY"
  );
}

/**
 * When a held output read answers. Finished (`true`): the completion
 * watermark committed, more pages are waiting (`hasMore`), or the operation
 * reached a final or UNKNOWN state (whose watermark may never commit).
 * Progress (`"progress"`): new bytes or gaps, or a cursor reset, while the
 * command still runs: held briefly for the finish. A command that has not
 * started yet (QUEUED, DISPATCHED, ACCEPTED, no bytes) is neither: it holds.
 */
export function outputPageReady(page: {
  chunks: readonly unknown[];
  gaps: readonly unknown[];
  hasMore: boolean;
  complete: boolean;
  reset: boolean;
  state: Parameters<typeof operationOutcome>[0];
}): boolean | "progress" {
  if (page.complete || page.hasMore || operationOutcome(page.state) !== "pending") return true;
  if (page.chunks.length > 0 || page.gaps.length > 0 || page.reset) return "progress";
  return false;
}

/** `/v1/sandboxes/{id}` → `/sandboxes/:id`, relative to the `/v1` mount. */
export function honoPath(path: string): string {
  return path.replace(/^\/v1/, "").replace(/\{([A-Za-z]+)\}/g, ":$1");
}

function badRequest(): never {
  throw new ORPCError("BAD_REQUEST");
}

/** Strict query parsing: repeated or undeclared parameters are rejected. */
function parseQuery(route: SdkRoute, url: string): unknown {
  const raw: Record<string, string> = Object.create(null);
  for (const [name, value] of new URL(url).searchParams) {
    if (Object.hasOwn(raw, name)) badRequest();
    raw[name] = value;
  }
  const parsed = route.query.safeParse(raw);
  return parsed.success ? parsed.data : badRequest();
}

function parseParams(route: SdkRoute, params: Record<string, string>): unknown {
  if (!route.params) return {};
  const parsed = route.params.safeParse(params);
  return parsed.success ? parsed.data : badRequest();
}

/**
 * A miss on a single-resource route always reports that route's stable code,
 * or one of the route's declared extra 404 codes (for example a template
 * selector on the pool capacity read, resolved only after the pool is
 * visible). Cross-owner and nonexistent IDs are indistinguishable (both 404).
 */
function routeError(route: SdkRoute, error: unknown): unknown {
  if (!(error instanceof ORPCError) || error.code !== "NOT_FOUND" || !route.notFound) return error;
  const data = error.data;
  const domain = data && typeof data === "object" && "code" in data ? data.code : undefined;
  if (isSdkErrorCode(domain) && domain === route.notFound) return error;
  if (isSdkErrorCode(domain) && SDK_ERRORS[domain][0] === 404 && route.errors?.includes(domain)) {
    return error;
  }
  return new ORPCError("NOT_FOUND", { data: { code: route.notFound } });
}

/** THE /v1 route chokepoint: input parse → service → response schema validation. */
export function registerSdkReadRoutes(
  app: Hono<SandboxApiEnv>,
  routeIds: readonly JsonRouteId[] = JSON_ROUTE_IDS,
  handlers: RouteHandlers = sdkReadHandlers(SDK_ROUTE_IDS),
): void {
  const paths = new Set<string>();
  for (const id of routeIds) {
    const route: SdkRoute = SDK_ROUTES[id];
    const handler = handlers[id] as (
      principal: ServicePrincipal,
      input: { params: unknown; query: unknown; body: unknown; idempotencyKey: string },
      context: RouteContext,
    ) => Promise<unknown>;
    paths.add(route.path);
    app.on(route.method.toUpperCase(), honoPath(route.path), async (c) => {
      const params = parseParams(route, c.req.param() as Record<string, string>);
      const query = parseQuery(route, c.req.url);
      let body: unknown;
      let key = "";
      const receipt = route.response.name === "MutationReceipt";
      if (route.body) {
        if (route.idempotency !== false) {
          const parsedKey = idempotencyKey.safeParse(c.req.header("Idempotency-Key"));
          if (!parsedKey.success) badRequest();
          key = parsedKey.data;
        }
        const text = await c.req.text();
        let raw: unknown;
        try {
          raw = text.length ? JSON.parse(text) : {};
        } catch {
          badRequest();
        }
        const parsed = route.body.safeParse(raw);
        if (!parsed.success) {
          // Route-scoped: a credential account's or instance's `name` keeps
          // its own error; only the sandbox create and rename routes map it.
          if (
            route.errors?.includes("sandbox.name_invalid") &&
            parsed.error.issues.some((issue) => issue.path[0] === "name")
          )
            throw new ORPCError("BAD_REQUEST", {
              message: SDK_ERRORS["sandbox.name_invalid"][1],
              data: { code: "sandbox.name_invalid" },
            });
          if (parsed.error.issues.some((issue) => issue.path[0] === "metadata"))
            throw new ORPCError("BAD_REQUEST", { data: { code: "sandbox.metadata_invalid" } });
          // Shape errors under `egress` (unknown fields, wrong types, oversized
          // arrays) are egress policy failures, not generic bad requests.
          if (parsed.error.issues.some((issue) => issue.path[0] === "egress"))
            throw new ORPCError("BAD_REQUEST", {
              data: { code: "sandbox.egress_policy_invalid" },
            });
          if (
            parsed.error.issues.some(
              (issue) =>
                issue.path[0] === "cpuCount" ||
                issue.path[0] === "memoryMiB" ||
                issue.path[0] === "diskGiB",
            )
          )
            throw new ORPCError("BAD_REQUEST", { data: { code: "sandbox.vm_size_invalid" } });
          badRequest();
        }
        body = parsed.data;
      }
      let value: unknown;
      try {
        value = await handler(
          c.var.principal,
          { params, query, body, idempotencyKey: key },
          { signal: c.req.raw.signal },
        );
        if (receipt) {
          const accepted = value as { operationId: string; state: unknown };
          value = {
            operationId: accepted.operationId,
            state: accepted.state,
            location: `/v1/operations/${accepted.operationId}`,
          };
        }
      } catch (error) {
        // Request parsing above is the only source of validation 400s. A
        // service/read parse failure is internal; never expose its issues.
        if (error instanceof ZodError) throw new ORPCError("INTERNAL_SERVER_ERROR");
        throw routeError(route, error);
      }
      const checked = route.response.schema.safeParse(value);
      if (!checked.success) {
        // Never send a body that differs from the documented contract.
        console.error(`[sandbox-api] [${c.var.requestId}] response contract violation: ${id}`);
        throw new ORPCError("INTERNAL_SERVER_ERROR");
      }
      if (receipt) {
        c.header("Location", (checked.data as { location: string }).location);
        return c.json(checked.data, 202);
      }
      const location = CREATED_LOCATION[id];
      if (location) c.header("Location", location(checked.data));
      return c.json(checked.data, route.successStatus ?? 200);
    });
  }
  for (const path of paths) {
    app.all(honoPath(path), () => {
      throw new ORPCError("METHOD_NOT_SUPPORTED");
    });
  }
}
