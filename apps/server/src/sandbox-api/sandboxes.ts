import {
  createSandboxInput,
  killSandboxInput,
  reconnectSandboxInput,
  setSandboxTimeoutInput,
  stopSandboxInput,
} from "@wssp/api/sandbox/contracts";
import { captureSandbox } from "@wssp/api/sandbox/image-store/captures";
import { mutationOperationReceipt, probeSandboxReceipt } from "@wssp/api/sandbox/sdk-mutations";
import { sdkUpdateSandbox } from "@wssp/api/sandbox/sdk-reads";
import {
  createSandbox,
  killSandbox,
  reconnectSandbox,
  setSandboxTimeout,
  stopSandbox,
} from "@wssp/api/sandbox/services/sandboxes";
import {
  closeSandboxTunnel,
  createSandboxTunnelLink,
  exposeSandboxTunnel,
  getSandboxTunnel,
} from "@wssp/api/sandbox/tunnels/service";
import type { RouteHandlers } from "./reads.js";

export const sandboxMutationHandlers = {
  createSandbox: async (owner, { body, idempotencyKey }) => {
    await createSandbox(owner, createSandboxInput.parse({ ...body, idempotencyKey }));
    return mutationOperationReceipt(owner, idempotencyKey, "sandboxes.create");
  },
  /** Rename: returns the fresh Sandbox (not an operation, no idempotency key). */
  updateSandbox: (owner, { params, body }) => sdkUpdateSandbox(owner, params.id, body),
  destroySandbox: async (owner, { params, body, idempotencyKey }) => {
    await killSandbox(
      owner,
      killSandboxInput.parse({ ...(body ?? {}), id: params.id, idempotencyKey }),
    );
    return mutationOperationReceipt(owner, idempotencyKey, "sandboxes.kill", {
      sandboxId: params.id,
    });
  },
  stopSandbox: (owner, { params, body, idempotencyKey }) =>
    stopSandbox(owner, stopSandboxInput.parse({ ...(body ?? {}), id: params.id, idempotencyKey })),
  reconnectSandbox: (owner, { params, body, idempotencyKey }) =>
    reconnectSandbox(
      owner,
      reconnectSandboxInput.parse({ ...body, id: params.id, idempotencyKey }),
    ),
  renewSandboxLease: async (owner, { params, body, idempotencyKey }) => {
    await setSandboxTimeout(
      owner,
      setSandboxTimeoutInput.parse({ ...body, id: params.id, idempotencyKey }),
    );
    return mutationOperationReceipt(owner, idempotencyKey, "sandboxes.setTimeout", {
      sandboxId: params.id,
    });
  },
  probeSandbox: (owner, { params, idempotencyKey }) =>
    probeSandboxReceipt(owner, { id: params.id, idempotencyKey }),
  captureSandbox: (owner, { params, body, idempotencyKey }) =>
    captureSandbox(owner, { ...body, id: params.id, idempotencyKey }),
  getSandboxTunnel: (owner, { params }) => getSandboxTunnel(owner, { id: params.id }),
  exposeSandboxTunnel: (owner, { params, body }) =>
    exposeSandboxTunnel(owner, { id: params.id, ...(body.ports ? { ports: body.ports } : {}) }),
  closeSandboxTunnel: (owner, { params }) => closeSandboxTunnel(owner, { id: params.id }),
  createSandboxTunnelLink: (owner, { params, body }) =>
    createSandboxTunnelLink(owner, { ...body, id: params.id }),
} satisfies Pick<
  RouteHandlers,
  | "createSandbox"
  | "updateSandbox"
  | "destroySandbox"
  | "stopSandbox"
  | "reconnectSandbox"
  | "renewSandboxLease"
  | "probeSandbox"
  | "captureSandbox"
  | "getSandboxTunnel"
  | "exposeSandboxTunnel"
  | "closeSandboxTunnel"
  | "createSandboxTunnelLink"
>;
