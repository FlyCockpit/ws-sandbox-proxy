import { withOperationWait } from "@wssp/api/sandbox/operation-waiters";
import { createCommunityTemplateForSdk } from "@wssp/api/template-builds/community/sdk";
import {
  cancelTemplateBuild,
  createTemplateBuild,
  getTemplateBuild,
  getTemplateBuildLogs,
  isTemplateBuildTerminal,
  listTemplateBuilds,
  templateBuildInputFromBody,
  templateBuildWatchKey,
  toTemplateBuildDto,
} from "@wssp/api/template-builds/views";
import { PAGE_SIZE_DEFAULT, templateBuildContextSchema } from "@wssp/sandbox-contracts";
import { buildContextStore } from "../template-builds/runtime.js";
import { outputPageReady, type RouteHandlers } from "./reads.js";

/**
 * `/v1` template-build adapters (scope `templates:build`, checked by the
 * shared services). Acceptance commits only the build row; for a COPY build
 * this request accepted, the route then opens the staged context and returns
 * its handle. A join never gets it.
 */
export const templateBuildHandlers = {
  createTemplateBuild: async (principal, { body, idempotencyKey }) => {
    const accepted = await createTemplateBuild(
      principal,
      templateBuildInputFromBody(body, idempotencyKey),
    );
    // `needsContext` is false for joins and cache hits; an idempotent replay
    // of the accepting request re-opens (idempotently) the same upload.
    const contextUpload = accepted.needsContext
      ? templateBuildContextSchema.parse(
          await buildContextStore().open(principal, accepted.build.id),
        )
      : null;
    return {
      build: toTemplateBuildDto(accepted.build),
      joined: accepted.joined,
      cacheHit: accepted.cacheHit,
      contextUpload,
    };
  },
  /** S11: a community template and its first prep build (`templates:write` + `templates:build`). */
  createCommunityTemplate: (principal, { body, idempotencyKey }) =>
    createCommunityTemplateForSdk(principal, body, idempotencyKey),
  listTemplateBuilds: (principal, { query }) =>
    listTemplateBuilds(principal, {
      cursor: query.cursor,
      limit: query.limit ?? PAGE_SIZE_DEFAULT,
      templateId: query.templateId,
      state: query.state,
    }),
  getTemplateBuild: async (principal, { params, query }, context) => {
    // Long-poll: hold until the build row changes or is terminal. Orchestrator
    // advances, cancel and capture finalization wake the hold; other writers
    // are caught by its periodic re-read.
    let first: string | null = null;
    return withOperationWait({
      ownerId: principal.ownerId,
      operationId: templateBuildWatchKey(params.id),
      waitMs: query.waitMs,
      signal: context?.signal,
      read: async () => {
        const build = await getTemplateBuild(principal, { id: params.id });
        first ??= build.updatedAt;
        return build;
      },
      ready: (build) => isTemplateBuildTerminal(build) || build.updatedAt !== first,
    });
  },
  cancelTemplateBuild: async (principal, { params }) =>
    toTemplateBuildDto(await cancelTemplateBuild(principal, { id: params.id })),
  getTemplateBuildLogs: async (principal, { params, query }, context) => {
    const read = () =>
      getTemplateBuildLogs(principal, {
        id: params.id,
        step: query.step,
        cursor: query.cursor,
        maxBytes: query.maxBytes,
      });
    const first = await read();
    // A step without a command yet answers at once; a running step's empty
    // page is held like the operation output read.
    if (!first.output || !query.waitMs || outputPageReady(first.output) === true) return first;
    return withOperationWait({
      ownerId: principal.ownerId,
      operationId: first.output.operationId,
      waitMs: query.waitMs,
      signal: context?.signal,
      read,
      // A new blocked-name hint (B12) answers the hold too.
      ready: (logs) =>
        logs.hints.length !== first.hints.length ||
        (logs.output ? outputPageReady(logs.output) : true),
    });
  },
} satisfies Pick<
  RouteHandlers,
  | "createTemplateBuild"
  | "createCommunityTemplate"
  | "listTemplateBuilds"
  | "getTemplateBuild"
  | "cancelTemplateBuild"
  | "getTemplateBuildLogs"
>;
