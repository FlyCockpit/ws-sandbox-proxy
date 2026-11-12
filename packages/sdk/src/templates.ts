import { randomUUID } from "node:crypto";
import {
  type CommunityTemplateCreatedDto,
  cursorSchema,
  PAGE_SIZE_MAX,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { WsspError } from "./errors";
import { type WaitOptions, waitTimeout } from "./polling";
import { createTemplateBuildsApi, type TemplateBuildsApi } from "./template-builds";
import type { RouteResponse, WsspTransport } from "./transport";

const page = z
  .object({
    limit: z.number().int().min(1).max(PAGE_SIZE_MAX).optional(),
    cursor: cursorSchema.optional(),
  })
  .strict();
export type TemplatePageOptions = z.input<typeof page>;
function wire(input: TemplatePageOptions = {}) {
  const parsed = page.safeParse(input);
  if (!parsed.success)
    throw new WsspError({ kind: "invalid_request", message: "Invalid template page options." });
  return { ...parsed.data, limit: parsed.data.limit?.toString() };
}
export type CommunityTemplateOptions = {
  /** A tested community image id, for example `ubuntu-26.04`. */
  source: string;
  /** Exactly one placement target for the prep build: a pool or one of your hosts. */
  poolId?: string;
  hostId?: string;
  /** Display label; defaults to the image's label. */
  label?: string;
  /** Reuse it to retry an `unknown` acceptance; generated when absent. */
  idempotencyKey?: string;
  signal?: AbortSignal;
};
export type TemplatesApi = TemplateBuildsApi & {
  /**
   * Create your template, managed by WS Sandbox Proxy, for a tested community image and accept
   * its first prep build (`POST /v1/templates/community`; scopes
   * `templates:write` and `templates:build`, not an allowlist key). A second
   * call for the same `source` returns the existing template (`existing`).
   * Follow `build` with `getBuild`; it is null when no build runs.
   */
  createFromCommunity(options: CommunityTemplateOptions): Promise<CommunityTemplateCreatedDto>;
  list(query?: TemplatePageOptions, options?: WaitOptions): Promise<RouteResponse<"listTemplates">>;
  revisions(
    templateId: string,
    query?: TemplatePageOptions,
    options?: WaitOptions,
  ): Promise<RouteResponse<"listTemplateRevisions">>;
  availability(
    templateId: string,
    revisionId: string,
    query?: TemplatePageOptions,
    options?: WaitOptions,
  ): Promise<RouteResponse<"listTemplateAvailability">>;
};
export function createTemplatesApi(transport: WsspTransport): TemplatesApi {
  return {
    ...createTemplateBuildsApi(transport),
    createFromCommunity: async (options) => {
      if ((options.poolId === undefined) === (options.hostId === undefined))
        throw new WsspError({
          kind: "invalid_request",
          message: "Pass exactly one of poolId and hostId.",
        });
      return transport.request("createCommunityTemplate", {
        idempotencyKey: options.idempotencyKey ?? randomUUID(),
        body: {
          source: options.source,
          ...(options.poolId !== undefined
            ? { poolId: options.poolId }
            : { sandboxHostId: options.hostId }),
          ...(options.label !== undefined ? { label: options.label } : {}),
        },
        signal: options.signal,
      });
    },
    list: (query, options) =>
      transport.request("listTemplates", {
        query: wire(query),
        signal: options?.signal,
        timeoutMs: waitTimeout(options),
      }),
    revisions: (id, query, options) =>
      transport.request("listTemplateRevisions", {
        params: { id },
        query: wire(query),
        signal: options?.signal,
        timeoutMs: waitTimeout(options),
      }),
    availability: (id, revisionId, query, options) =>
      transport.request("listTemplateAvailability", {
        params: { id },
        query: { ...wire(query), revisionId },
        signal: options?.signal,
        timeoutMs: waitTimeout(options),
      }),
  };
}
