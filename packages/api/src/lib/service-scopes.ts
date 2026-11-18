import type { SandboxOperationKind } from "@wssp/db";

/** Canonical SDK capability strings from PLAN shared decisions. */
export const SERVICE_SCOPES = [
  "hosts:read",
  "hosts:execute",
  "hosts:files",
  "pools:read",
  "templates:read",
  "templates:write",
  "templates:build",
  "sandboxes:read",
  "sandboxes:create",
  "sandboxes:manage",
  "sandboxes:destroy",
  "commands:read",
  "commands:execute",
  "files:read",
  "files:write",
  "operations:read",
  "operations:cancel",
  "webhooks:write",
  "credentials:read",
  "credentials:write",
  "credentials:use",
  "sandboxes:tunnel",
] as const;

export type ServiceScope = (typeof SERVICE_SCOPES)[number];

const SERVICE_SCOPE_SET = new Set<string>(SERVICE_SCOPES);

export function isKnownServiceScope(value: string): value is ServiceScope {
  return SERVICE_SCOPE_SET.has(value);
}

/**
 * Reject empty, unknown, or wildcard scope sets at mint and authentication.
 * Returns a deduplicated list in first-seen order.
 */
export function parseServiceScopeSet(scopes: readonly string[]): ServiceScope[] {
  if (scopes.length === 0) {
    throw new Error("At least one service scope is required.");
  }
  if (scopes.length > SERVICE_SCOPES.length) throw new Error("Too many service scopes.");
  const seen = new Set<string>();
  const parsed: ServiceScope[] = [];
  for (const raw of scopes) {
    const scope = raw;
    if (scope.length === 0) {
      throw new Error("Scope entries must not be empty.");
    }
    if (scope.includes("*")) {
      throw new Error("Wildcard scopes are not permitted.");
    }
    if (!isKnownServiceScope(scope)) {
      throw new Error(`Unknown service scope: ${scope}`);
    }
    if (seen.has(scope)) continue;
    seen.add(scope);
    parsed.push(scope);
  }
  return parsed;
}

/** Every SDK/HTTP service entry point. HTTP adapters must use this same set. */
export const SERVICE_ACTIONS = [
  "capabilities.get",
  "hosts.list",
  "hosts.get",
  "hostCommands.run",
  "hostCommands.get",
  "hostCommands.writeStdin",
  "hostCommands.cancel",
  "hostCommands.queue",
  "hostFiles.read",
  "hostFiles.list",
  "hostFiles.write",
  "hostFiles.edit",

  "hosts.storagePools",
  "pools.list",
  "pools.get",
  "pools.members",
  "pools.capacity",
  "templates.list",
  "templates.create",
  "templates.retire",
  "templates.revisions",
  "templates.availability",
  "templates.append",
  "templates.associate",
  "templates.build",
  "sandboxes.list",
  "sandboxes.get",
  "sandboxes.probe",
  "sandboxes.createIntent",
  "sandboxes.replayCreate",
  "sandboxes.create",
  "sandboxes.kill",
  "sandboxes.stop",
  "sandboxes.reconnect",
  "sandboxes.setTimeout",
  "sandboxes.update",
  "sandboxes.capture",
  "sandboxes.tunnelGet",
  "sandboxes.tunnelExpose",
  "sandboxes.tunnelClose",
  "sandboxes.tunnelLink",
  "operations.get",
  "operations.getFileResult",
  "operations.getFileMutationResult",
  "operations.getRenameResult",
  "operations.getCommandResult",
  "operations.getSignalResult",

  "operations.getReceipt",
  "operations.getCommandOutput",
  "operations.downloadFile",
  "operations.cancel",
  "commands.run",
  "commands.writeStdin",
  "files.read",
  "files.write",
  "files.listDir",
  "files.stat",
  "files.mkdir",
  "files.remove",
  "files.move",
  "processes.connect",
  "sandboxes.capabilities",
  "processes.list",
  "processes.signal",
  "webhooks.list",
  "webhooks.get",
  "webhooks.create",
  "webhooks.update",
  "webhooks.delete",
  "webhooks.rotateSecret",
  "webhooks.test",
  "webhooks.listDeliveries",
  "webhooks.getDelivery",
  "webhooks.redeliver",
  "credentialDefinitions.list",
  "credentialDefinitions.get",
  "credentialDefinitions.create",
  "credentialDefinitions.archive",
  "credentials.list",
  "credentials.get",
  "credentials.create",
  "credentials.update",
  "credentials.delete",
  "credentials.events",
  "credentialAccounts.list",
  "credentialAccounts.create",
  "credentialAccounts.update",
  "credentialAccounts.delete",
  "credentialInstances.list",
  "credentialInstances.create",
  "credentialInstances.update",
  "credentialInstances.delete",
  "credentialInstances.writeValue",
  "sandboxCredentials.attach",
  "sandboxCredentials.free",
  "credentialInstances.listLeases",
  "credentialInstances.forceRelease",
] as const;

export type ServiceAction = (typeof SERVICE_ACTIONS)[number];

export type ServiceActionContext = {
  /** Internal: resolved from the initial creator-owned CREATE operation. */
  authorizingKeyId?: string | null;
  /** Internal receipt lookup; never new execution or new holds. */
  retainedReplay?: true;
  sandboxHostId?: string | null;
  logicalTemplateId?: string | null;
  templateRevisionId?: string | null;
  originPoolId?: string | null;
  poolId?: string;
  sandboxId?: string | null;
  operationId?: string;
  operationKind?: SandboxOperationKind;
};

type ActionRequirement = {
  scopes: readonly ServiceScope[];
  requiresHost?: boolean;
  requiresOwnedHost?: boolean;
  requiresPool?: boolean;
  requiresTemplate?: boolean;
  requiresSandbox?: boolean;
  requiresPoolWhenPooled?: boolean;
  cancelMutationScope?: boolean;
};

const CANCEL_MUTATION_SCOPE_BY_KIND: Partial<Record<SandboxOperationKind, ServiceScope>> = {
  CREATE_SANDBOX: "sandboxes:create",
  KILL_SANDBOX: "sandboxes:destroy",
  RECONNECT_SANDBOX: "sandboxes:manage",
  STOP_SANDBOX: "sandboxes:manage",
  RENEW_SANDBOX_LEASE: "sandboxes:manage",
  RUN_COMMAND: "commands:execute",
  GET_FILE: "files:read",
  PUT_FILE: "files:write",
  LIST_DIR: "files:read",
  STAT_PATH: "files:read",
  MKDIR: "files:write",
  REMOVE_PATH: "files:write",
  MOVE_PATH: "files:write",
  LIST_PROCESSES: "commands:read",
  SIGNAL_PROCESS: "commands:execute",
  CAPTURE_TEMPLATE: "templates:write",
};

/** Scopes that can authorize a cancellation's target work (with `operations:cancel`). */
export const CANCEL_MUTATION_SCOPES: readonly ServiceScope[] = [
  ...new Set(Object.values(CANCEL_MUTATION_SCOPE_BY_KIND)),
];

export const SERVICE_ACTION_REQUIREMENTS: Record<ServiceAction, ActionRequirement> = {
  "operations.getFileResult": { scopes: ["operations:read", "files:read"], requiresSandbox: true },
  "operations.getFileMutationResult": {
    scopes: ["operations:read", "files:write"],
    requiresSandbox: true,
  },
  "operations.getRenameResult": {
    scopes: ["operations:read", "files:read", "files:write"],
    requiresSandbox: true,
  },
  "operations.getCommandResult": {
    scopes: ["operations:read", "commands:read"],
    requiresSandbox: true,
  },
  "operations.getSignalResult": {
    scopes: ["operations:read", "commands:execute", "operations:cancel"],
    requiresSandbox: true,
  },

  // Any active key may read its own grant and the server's enabled features;
  // the response discloses no owner resources (C23).
  "capabilities.get": { scopes: [] },
  "hosts.list": { scopes: ["hosts:read"] },
  "hosts.get": { scopes: ["hosts:read"], requiresHost: true },
  "hostCommands.run": { scopes: ["hosts:execute"], requiresHost: true, requiresOwnedHost: true },
  "hostCommands.get": { scopes: ["hosts:execute"], requiresHost: true, requiresOwnedHost: true },
  "hostCommands.writeStdin": {
    scopes: ["hosts:execute"],
    requiresHost: true,
    requiresOwnedHost: true,
  },
  "hostCommands.cancel": { scopes: ["hosts:execute"], requiresHost: true, requiresOwnedHost: true },
  "hostCommands.queue": { scopes: ["hosts:execute"], requiresHost: true, requiresOwnedHost: true },
  "hostFiles.read": { scopes: ["hosts:files"], requiresHost: true, requiresOwnedHost: true },
  "hostFiles.list": { scopes: ["hosts:files"], requiresHost: true, requiresOwnedHost: true },
  "hostFiles.write": { scopes: ["hosts:files"], requiresHost: true, requiresOwnedHost: true },
  "hostFiles.edit": { scopes: ["hosts:files"], requiresHost: true, requiresOwnedHost: true },

  "hosts.storagePools": { scopes: ["hosts:read"], requiresHost: true },
  "pools.list": { scopes: ["pools:read"] },
  "pools.get": { scopes: ["pools:read"], requiresPool: true },
  "pools.members": { scopes: ["pools:read", "hosts:read"], requiresPool: true },
  // Owned-host detail additionally needs hosts:read (checked in the view).
  "pools.capacity": { scopes: ["pools:read"], requiresPool: true },
  "templates.list": { scopes: ["templates:read"] },
  "templates.create": { scopes: ["templates:write"], requiresHost: true },
  "templates.revisions": { scopes: ["templates:read"] },
  "templates.availability": { scopes: ["templates:read", "hosts:read"], requiresTemplate: true },
  "templates.append": { scopes: ["templates:write"], requiresHost: true },
  "templates.associate": {
    scopes: ["templates:write"],
    requiresHost: true,
    requiresTemplate: true,
  },
  "templates.retire": { scopes: ["templates:write"], requiresTemplate: true },
  // Every template-build entry (accept, read, list, logs, cancel, context
  // upload). The build's own steps are authorized by the build action classes,
  // which re-check this scope on the accepting key.
  "templates.build": { scopes: ["templates:build"] },
  "sandboxes.list": { scopes: ["sandboxes:read"] },
  "sandboxes.get": { scopes: ["sandboxes:read"], requiresSandbox: true },
  "sandboxes.probe": { scopes: ["sandboxes:read"], requiresSandbox: true },
  "sandboxes.createIntent": { scopes: ["sandboxes:create"] },
  "sandboxes.replayCreate": {
    scopes: ["sandboxes:create"],
    requiresSandbox: true,
    requiresPoolWhenPooled: true,
  },
  "sandboxes.create": {
    scopes: ["sandboxes:create"],
    requiresHost: true,
    requiresTemplate: true,
    requiresPoolWhenPooled: true,
  },
  "sandboxes.kill": { scopes: ["sandboxes:destroy"], requiresSandbox: true },
  "sandboxes.stop": { scopes: ["sandboxes:manage"], requiresSandbox: true },
  "sandboxes.reconnect": { scopes: ["sandboxes:manage"], requiresSandbox: true },
  "sandboxes.setTimeout": { scopes: ["sandboxes:manage"], requiresSandbox: true },
  // Not an operation and not host-bound (no HOST_USABILITY_ACTIONS entry).
  "sandboxes.update": { scopes: ["sandboxes:manage"], requiresSandbox: true },
  "sandboxes.capture": { scopes: ["sandboxes:manage", "templates:write"], requiresSandbox: true },
  // Preview tunnels: not operations; the controller drives the host.
  "sandboxes.tunnelGet": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.tunnelExpose": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.tunnelClose": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.tunnelLink": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "operations.getReceipt": { scopes: ["operations:read"], requiresHost: true },
  "operations.get": { scopes: ["operations:read"], requiresSandbox: true },
  "operations.getCommandOutput": {
    scopes: ["operations:read", "commands:read"],
    requiresSandbox: true,
  },
  "operations.downloadFile": {
    scopes: ["operations:read", "files:read"],
    requiresSandbox: true,
  },
  "operations.cancel": {
    scopes: ["operations:cancel"],
    requiresSandbox: true,
    cancelMutationScope: true,
  },
  "commands.run": { scopes: ["commands:execute"], requiresSandbox: true },
  "commands.writeStdin": { scopes: ["commands:execute"], requiresSandbox: true },
  "files.read": { scopes: ["files:read"], requiresSandbox: true },
  "files.write": { scopes: ["files:write"], requiresSandbox: true },
  "files.listDir": { scopes: ["files:read"], requiresSandbox: true },
  "files.stat": { scopes: ["files:read"], requiresSandbox: true },
  "files.mkdir": { scopes: ["files:write"], requiresSandbox: true },
  "files.remove": { scopes: ["files:write"], requiresSandbox: true },
  "files.move": { scopes: ["files:write"], requiresSandbox: true },
  "processes.connect": { scopes: ["commands:read"], requiresSandbox: true },
  "sandboxes.capabilities": { scopes: ["sandboxes:read"], requiresSandbox: true },
  "processes.list": { scopes: ["commands:read"], requiresSandbox: true },
  "processes.signal": { scopes: ["commands:execute", "operations:cancel"], requiresSandbox: true },
  // Account-wide outbound feeds. The mint rule (sdk-key-rules.ts) limits the
  // scope to ALL_OWNED + ALL_USABLE keys; the services re-check it.
  "webhooks.list": { scopes: ["webhooks:write"] },
  "webhooks.get": { scopes: ["webhooks:write"] },
  "webhooks.create": { scopes: ["webhooks:write"] },
  "webhooks.update": { scopes: ["webhooks:write"] },
  "webhooks.delete": { scopes: ["webhooks:write"] },
  "webhooks.rotateSecret": { scopes: ["webhooks:write"] },
  "webhooks.test": { scopes: ["webhooks:write"] },
  "webhooks.listDeliveries": { scopes: ["webhooks:write"] },
  "webhooks.getDelivery": { scopes: ["webhooks:write"] },
  "webhooks.redeliver": { scopes: ["webhooks:write"] },
  // CLI logins. Values are write-only; reads are metadata.
  "credentialDefinitions.list": { scopes: ["credentials:read"] },
  "credentialDefinitions.get": { scopes: ["credentials:read"] },
  "credentialDefinitions.create": { scopes: ["credentials:write"] },
  "credentialDefinitions.archive": { scopes: ["credentials:write"] },
  "credentials.list": { scopes: ["credentials:read"] },
  "credentials.get": { scopes: ["credentials:read"] },
  "credentials.create": { scopes: ["credentials:write"] },
  "credentials.update": { scopes: ["credentials:write"] },
  "credentials.delete": { scopes: ["credentials:write"] },
  "credentials.events": { scopes: ["credentials:read"] },
  "credentialAccounts.list": { scopes: ["credentials:read"] },
  "credentialAccounts.create": { scopes: ["credentials:write"] },
  "credentialAccounts.update": { scopes: ["credentials:write"] },
  "credentialAccounts.delete": { scopes: ["credentials:write"] },
  "credentialInstances.list": { scopes: ["credentials:read"] },
  "credentialInstances.create": { scopes: ["credentials:write"] },
  "credentialInstances.update": { scopes: ["credentials:write"] },
  "credentialInstances.delete": { scopes: ["credentials:write"] },
  "credentialInstances.writeValue": { scopes: ["credentials:write"] },
  // Live attach / free on a sandbox (§10.1): the login's value reaches (or
  // leaves) the guest, so `credentials:use` is required on top of the
  // sandbox write scope; the per-login allowlist is checked in the service.
  "sandboxCredentials.attach": {
    scopes: ["sandboxes:manage", "credentials:use"],
    requiresSandbox: true,
  },
  "sandboxCredentials.free": {
    scopes: ["sandboxes:manage", "credentials:use"],
    requiresSandbox: true,
  },
  "credentialInstances.listLeases": { scopes: ["credentials:read"] },
  "credentialInstances.forceRelease": { scopes: ["credentials:write"] },
};

export function mutationScopeForOperationKind(kind: SandboxOperationKind): ServiceScope | null {
  return CANCEL_MUTATION_SCOPE_BY_KIND[kind] ?? null;
}

export function serviceActionForOperationKind(kind: SandboxOperationKind): ServiceAction | null {
  switch (kind) {
    case "CREATE_SANDBOX":
      return "sandboxes.create";
    case "KILL_SANDBOX":
      return "sandboxes.kill";
    case "STOP_SANDBOX":
      return "sandboxes.stop";
    case "RECONNECT_SANDBOX":
      return "sandboxes.reconnect";
    case "RENEW_SANDBOX_LEASE":
      return "sandboxes.setTimeout";
    case "RUN_COMMAND":
      return "commands.run";
    case "GET_FILE":
      return "files.read";
    case "PUT_FILE":
      return "files.write";
    case "LIST_DIR":
      return "files.listDir";
    case "STAT_PATH":
      return "files.stat";
    case "MKDIR":
      return "files.mkdir";
    case "REMOVE_PATH":
      return "files.remove";
    case "MOVE_PATH":
      return "files.move";
    case "LIST_PROCESSES":
      return "processes.list";
    case "SIGNAL_PROCESS":
      return "processes.signal";
    case "CAPTURE_TEMPLATE":
      return "sandboxes.capture";
    case "CREDENTIAL_ATTACH":
      return "sandboxCredentials.attach";
    case "CREDENTIAL_FREE":
      return "sandboxCredentials.free";
    default:
      return null;
  }
}

/** Result class comes exclusively from the owned stored operation kind. */
export function resultActionForOperationKind(kind: SandboxOperationKind): ServiceAction | null {
  switch (kind) {
    case "STAT_PATH":
    case "LIST_DIR":
      return "operations.getFileResult";
    case "MKDIR":
    case "REMOVE_PATH":
      return "operations.getFileMutationResult";
    case "MOVE_PATH":
      return "operations.getRenameResult";
    case "RUN_COMMAND":
    case "LIST_PROCESSES":
      return "operations.getCommandResult";
    case "SIGNAL_PROCESS":
      return "operations.getSignalResult";
    default:
      return null;
  }
}

export function fsProcessBudgetFamily(
  action: ServiceAction,
  targetKind?: SandboxOperationKind,
): "ordinary" | "stdin" | "termination" | null {
  switch (action) {
    case "commands.writeStdin":
      return "stdin";
    case "processes.signal":
      return "termination";
    case "operations.cancel":
      return targetKind === "RUN_COMMAND" ? "termination" : "ordinary";
    case "commands.run":
    case "files.read":
    case "files.write":
    case "files.listDir":
    case "files.stat":
    case "files.mkdir":
    case "files.remove":
    case "files.move":
    case "processes.list":
      return "ordinary";
    default:
      return null;
  }
}
