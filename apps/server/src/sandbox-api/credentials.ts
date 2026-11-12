import { attachSandboxCredential, freeSandboxCredential } from "@wssp/api/credentials/live";
import {
  archiveDefinition,
  createAccount,
  createDefinition,
  createInstance,
  createLogin,
  deleteAccount,
  deleteInstance,
  deleteLogin,
  forceRelease,
  getDefinition,
  getLogin,
  listAccounts,
  listDefinitions,
  listEvents,
  listInstanceLeases,
  listInstances,
  listLogins,
  updateAccount,
  updateInstance,
  updateLogin,
  writeValue,
} from "@wssp/api/credentials/service";
import { PAGE_SIZE_DEFAULT } from "@wssp/sandbox-contracts";
import type { RouteHandlers } from "./reads.js";

/**
 * `/v1` CLI-login adapters: each calls the shared `serviceProcedure` with the
 * SDK principal (scopes `credentials:read|write`, the per-login allowlist,
 * budgets and owner scoping all live in the service). Never a cookie session.
 */
const page = (query: { cursor?: string; limit?: number }) => ({
  cursor: query.cursor,
  limit: query.limit ?? PAGE_SIZE_DEFAULT,
});

export const credentialHandlers = {
  listCredentialDefinitions: (principal, { query }) => listDefinitions(principal, page(query)),
  createCredentialDefinition: (principal, { body }) => createDefinition(principal, body),
  getCredentialDefinition: (principal, { params }) => getDefinition(principal, { id: params.id }),
  archiveCredentialDefinition: (principal, { params }) =>
    archiveDefinition(principal, { id: params.id }),
  listCredentials: (principal, { query }) => listLogins(principal, page(query)),
  createCredential: (principal, { body }) => createLogin(principal, body),
  getCredential: (principal, { params }) => getLogin(principal, { id: params.id }),
  updateCredential: (principal, { params, body }) =>
    updateLogin(principal, { ...body, id: params.id }),
  deleteCredential: (principal, { params }) => deleteLogin(principal, { id: params.id }),
  listCredentialEvents: (principal, { params, query }) =>
    listEvents(principal, { ...page(query), credentialId: params.id }),
  listCredentialAccounts: (principal, { params, query }) =>
    listAccounts(principal, { ...page(query), credentialId: params.id }),
  createCredentialAccount: (principal, { params, body }) =>
    createAccount(principal, { ...body, credentialId: params.id }),
  updateCredentialAccount: (principal, { params, body }) =>
    updateAccount(principal, { ...body, credentialId: params.id, accountId: params.accountId }),
  deleteCredentialAccount: (principal, { params }) =>
    deleteAccount(principal, { credentialId: params.id, accountId: params.accountId }),
  listCredentialInstances: (principal, { params, query }) =>
    listInstances(principal, {
      ...page(query),
      credentialId: params.id,
      accountId: params.accountId,
    }),
  createCredentialInstance: (principal, { params, body }) =>
    createInstance(principal, { ...body, credentialId: params.id, accountId: params.accountId }),
  updateCredentialInstance: (principal, { params, body }) =>
    updateInstance(principal, {
      ...body,
      credentialId: params.id,
      instanceId: params.instanceId,
    }),
  deleteCredentialInstance: (principal, { params }) =>
    deleteInstance(principal, { credentialId: params.id, instanceId: params.instanceId }),
  writeCredentialValue: (principal, { params, body }) =>
    writeValue(principal, { ...body, credentialId: params.id, instanceId: params.instanceId }),
  listCredentialLeases: (principal, { params, query }) =>
    listInstanceLeases(principal, {
      ...page(query),
      credentialId: params.id,
      instanceId: params.instanceId,
    }),
  forceReleaseCredentialLease: (principal, { params, body }) =>
    forceRelease(principal, {
      credentialId: params.id,
      instanceId: params.instanceId,
      leaseId: params.leaseId,
      promoteCheckpoint: body.promoteCheckpoint ?? false,
    }),
  attachSandboxCredential: (principal, { params, body, idempotencyKey }) =>
    attachSandboxCredential(principal, { ...body, id: params.id, idempotencyKey }),
  freeSandboxCredential: (principal, { params, body, idempotencyKey }) =>
    freeSandboxCredential(principal, {
      ...body,
      id: params.id,
      credentialId: params.credentialId,
      idempotencyKey,
    }),
} satisfies Pick<
  RouteHandlers,
  | "listCredentialDefinitions"
  | "createCredentialDefinition"
  | "getCredentialDefinition"
  | "archiveCredentialDefinition"
  | "listCredentials"
  | "createCredential"
  | "getCredential"
  | "updateCredential"
  | "deleteCredential"
  | "listCredentialEvents"
  | "listCredentialAccounts"
  | "createCredentialAccount"
  | "updateCredentialAccount"
  | "deleteCredentialAccount"
  | "listCredentialInstances"
  | "createCredentialInstance"
  | "updateCredentialInstance"
  | "deleteCredentialInstance"
  | "writeCredentialValue"
  | "listCredentialLeases"
  | "forceReleaseCredentialLease"
  | "attachSandboxCredential"
  | "freeSandboxCredential"
>;
