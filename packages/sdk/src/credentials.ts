import {
  type createCredentialAccountBodySchema,
  type createCredentialBodySchema,
  type createCredentialDefinitionBodySchema,
  type createCredentialInstanceBodySchema,
  cursorSchema,
  PAGE_SIZE_MAX,
  type updateCredentialAccountBodySchema,
  type updateCredentialBodySchema,
  type updateCredentialInstanceBodySchema,
  type writeCredentialValueBodySchema,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { WsspError } from "./errors";
import { type WaitOptions, waitTimeout } from "./polling";
import type { RouteResponse, WsspTransport } from "./transport";

/**
 * CLI logins (scopes `credentials:read` / `credentials:write`). A login pins
 * one definition version; accounts are provider accounts (pause lives there);
 * instances are independent token sets. Values are write-only: no method
 * returns one. Delivery, copy-back, foreign-host opt-in and re-pin are
 * dashboard-only.
 */
const page = z
  .object({
    limit: z.number().int().min(1).max(PAGE_SIZE_MAX).optional(),
    cursor: cursorSchema.optional(),
  })
  .strict();
export type CredentialPageOptions = z.input<typeof page>;
export type CreateCredentialDefinitionInput = z.input<typeof createCredentialDefinitionBodySchema>;
export type CreateCredentialInput = z.input<typeof createCredentialBodySchema>;
export type UpdateCredentialInput = z.input<typeof updateCredentialBodySchema>;
export type CreateCredentialAccountInput = z.input<typeof createCredentialAccountBodySchema>;
export type UpdateCredentialAccountInput = z.input<typeof updateCredentialAccountBodySchema>;
export type CreateCredentialInstanceInput = z.input<typeof createCredentialInstanceBodySchema>;
export type UpdateCredentialInstanceInput = z.input<typeof updateCredentialInstanceBodySchema>;
export type WriteCredentialValueInput = z.input<typeof writeCredentialValueBodySchema>;

function wire(input: unknown) {
  const parsed = page.safeParse(input ?? {});
  if (!parsed.success)
    throw new WsspError({ kind: "invalid_request", message: "Invalid login page options." });
  return { ...parsed.data, limit: parsed.data.limit?.toString() };
}

export type CredentialDefinitionsApi = {
  list(
    query?: CredentialPageOptions,
    options?: WaitOptions,
  ): Promise<RouteResponse<"listCredentialDefinitions">>;
  get(id: string, options?: WaitOptions): Promise<RouteResponse<"getCredentialDefinition">>;
  /** Stores the document as the next version of its `id`. Not idempotent. */
  create(
    input: CreateCredentialDefinitionInput,
    options?: WaitOptions,
  ): Promise<RouteResponse<"createCredentialDefinition">>;
  archive(id: string, options?: WaitOptions): Promise<RouteResponse<"archiveCredentialDefinition">>;
};

export type CredentialsApi = {
  definitions: CredentialDefinitionsApi;
  list(
    query?: CredentialPageOptions,
    options?: WaitOptions,
  ): Promise<RouteResponse<"listCredentials">>;
  get(id: string, options?: WaitOptions): Promise<RouteResponse<"getCredential">>;
  create(
    input: CreateCredentialInput,
    options?: WaitOptions,
  ): Promise<RouteResponse<"createCredential">>;
  update(
    id: string,
    input: UpdateCredentialInput,
    options?: WaitOptions,
  ): Promise<RouteResponse<"updateCredential">>;
  delete(id: string, options?: WaitOptions): Promise<RouteResponse<"deleteCredential">>;
  events(
    id: string,
    query?: CredentialPageOptions,
    options?: WaitOptions,
  ): Promise<RouteResponse<"listCredentialEvents">>;
  accounts: {
    list(
      credentialId: string,
      query?: CredentialPageOptions,
      options?: WaitOptions,
    ): Promise<RouteResponse<"listCredentialAccounts">>;
    create(
      credentialId: string,
      input?: CreateCredentialAccountInput,
      options?: WaitOptions,
    ): Promise<RouteResponse<"createCredentialAccount">>;
    /** Rename or pause. Pause applies to new sandboxes; running ones keep their leases. */
    update(
      credentialId: string,
      accountId: string,
      input: UpdateCredentialAccountInput,
      options?: WaitOptions,
    ): Promise<RouteResponse<"updateCredentialAccount">>;
    delete(
      credentialId: string,
      accountId: string,
      options?: WaitOptions,
    ): Promise<RouteResponse<"deleteCredentialAccount">>;
  };
  instances: {
    list(
      credentialId: string,
      accountId: string,
      query?: CredentialPageOptions,
      options?: WaitOptions,
    ): Promise<RouteResponse<"listCredentialInstances">>;
    create(
      credentialId: string,
      accountId: string,
      input?: CreateCredentialInstanceInput,
      options?: WaitOptions,
    ): Promise<RouteResponse<"createCredentialInstance">>;
    update(
      credentialId: string,
      instanceId: string,
      input: UpdateCredentialInstanceInput,
      options?: WaitOptions,
    ): Promise<RouteResponse<"updateCredentialInstance">>;
    delete(
      credentialId: string,
      instanceId: string,
      options?: WaitOptions,
    ): Promise<RouteResponse<"deleteCredentialInstance">>;
    /** Upload a value. Write-only: the response is metadata. */
    writeValue(
      credentialId: string,
      instanceId: string,
      input: WriteCredentialValueInput,
      options?: WaitOptions,
    ): Promise<RouteResponse<"writeCredentialValue">>;
  };
  leases: {
    /**
     * An instance's live leases (holders) in creation order, each with the
     * checkpoint `forceRelease` with `promoteCheckpoint` would make current.
     */
    list(
      credentialId: string,
      instanceId: string,
      query?: CredentialPageOptions,
      options?: WaitOptions,
    ): Promise<RouteResponse<"listCredentialLeases">>;
    /**
     * Force-release one lease of an instance: its bindings close, later
     * captures of it are discarded and its host drops the env. Without
     * `promoteCheckpoint` a value the guest rotated since the last capture
     * is lost.
     */
    forceRelease(
      credentialId: string,
      instanceId: string,
      leaseId: string,
      input?: { promoteCheckpoint?: boolean },
      options?: WaitOptions,
    ): Promise<RouteResponse<"forceReleaseCredentialLease">>;
  };
};

export function createCredentialsApi(transport: WsspTransport): CredentialsApi {
  const opts = (options?: WaitOptions) => ({
    signal: options?.signal,
    timeoutMs: waitTimeout(options),
  });
  return {
    definitions: {
      list: (query, options) =>
        transport.request("listCredentialDefinitions", { query: wire(query), ...opts(options) }),
      get: (id, options) =>
        transport.request("getCredentialDefinition", { params: { id }, ...opts(options) }),
      create: (input, options) =>
        transport.request("createCredentialDefinition", { body: input, ...opts(options) }),
      archive: (id, options) =>
        transport.request("archiveCredentialDefinition", { params: { id }, ...opts(options) }),
    },
    list: (query, options) =>
      transport.request("listCredentials", { query: wire(query), ...opts(options) }),
    get: (id, options) => transport.request("getCredential", { params: { id }, ...opts(options) }),
    create: (input, options) =>
      transport.request("createCredential", { body: input, ...opts(options) }),
    update: (id, input, options) =>
      transport.request("updateCredential", { params: { id }, body: input, ...opts(options) }),
    delete: (id, options) =>
      transport.request("deleteCredential", { params: { id }, ...opts(options) }),
    events: (id, query, options) =>
      transport.request("listCredentialEvents", {
        params: { id },
        query: wire(query),
        ...opts(options),
      }),
    accounts: {
      list: (id, query, options) =>
        transport.request("listCredentialAccounts", {
          params: { id },
          query: wire(query),
          ...opts(options),
        }),
      create: (id, input, options) =>
        transport.request("createCredentialAccount", {
          params: { id },
          body: input ?? {},
          ...opts(options),
        }),
      update: (id, accountId, input, options) =>
        transport.request("updateCredentialAccount", {
          params: { id, accountId },
          body: input,
          ...opts(options),
        }),
      delete: (id, accountId, options) =>
        transport.request("deleteCredentialAccount", {
          params: { id, accountId },
          ...opts(options),
        }),
    },
    instances: {
      list: (id, accountId, query, options) =>
        transport.request("listCredentialInstances", {
          params: { id, accountId },
          query: wire(query),
          ...opts(options),
        }),
      create: (id, accountId, input, options) =>
        transport.request("createCredentialInstance", {
          params: { id, accountId },
          body: input ?? {},
          ...opts(options),
        }),
      update: (id, instanceId, input, options) =>
        transport.request("updateCredentialInstance", {
          params: { id, instanceId },
          body: input,
          ...opts(options),
        }),
      delete: (id, instanceId, options) =>
        transport.request("deleteCredentialInstance", {
          params: { id, instanceId },
          ...opts(options),
        }),
      writeValue: (id, instanceId, input, options) =>
        transport.request("writeCredentialValue", {
          params: { id, instanceId },
          body: input,
          ...opts(options),
        }),
    },
    leases: {
      list: (id, instanceId, query, options) =>
        transport.request("listCredentialLeases", {
          params: { id, instanceId },
          query: wire(query),
          ...opts(options),
        }),
      forceRelease: (id, instanceId, leaseId, input, options) =>
        transport.request("forceReleaseCredentialLease", {
          params: { id, instanceId, leaseId },
          body: input ?? {},
          ...opts(options),
        }),
    },
  };
}
