import { ORPCError } from "@orpc/server";
import type {
  HostCommandInput,
  HostCommandStatus,
  HostFileEdit,
  HostFileList,
  HostFileRead,
  HostFileWrite,
  hostCommandStdinBodySchema,
  hostFileEditBodySchema,
  hostFileListBodySchema,
  hostFileReadBodySchema,
  hostFileWriteBodySchema,
} from "@wssp/sandbox-contracts";
import type { z } from "zod";
import type { Principal } from "./contracts";
import { recordedKeyIdOf } from "./principal-kinds";
/** Host service actions reject build principals at the registered service boundary. */
export function hostCredentialId(principal: Principal): string {
  const id = recordedKeyIdOf(principal);
  if (!id) throw new ORPCError("FORBIDDEN");
  return id;
}

export type HostAgentPolicy = {
  epoch?: number;
  /** Raw authenticated node report, independent of the dashboard veto. */
  nodeHostCommands?: boolean;
  nodeHostFiles?: boolean;
  hostCommands: boolean;
  hostFiles: boolean;
  hostCommandMaxMs?: number;
  agentPolicyRevision: number;
  lowerPending: boolean;
};
export type HostCommandPoll = {
  commandId: string;
  stdoutOffset: number;
  stderrOffset: number;
  maxBytes: number;
};
export type HostFileRequest =
  | ({ op: "read" } & z.output<typeof hostFileReadBodySchema>)
  | ({ op: "list" } & z.output<typeof hostFileListBodySchema>)
  | ({ op: "write" } & z.output<typeof hostFileWriteBodySchema>)
  | ({ op: "edit" } & z.output<typeof hostFileEditBodySchema>);
type HostFileResult = HostFileRead | HostFileList | HostFileWrite | HostFileEdit;
/** Refusal-only proof for lifting a veto; never authorizes node traffic. */
export type HostNodeOffWitness = { epoch: number; isOff(): boolean };
export type HostAccessBridge = {
  offWitness?(
    hostId: string,
    ownerId: string,
    target: "hostCommands" | "hostTerminal",
  ): HostNodeOffWitness | null;
  read(hostId: string, ownerId: string): HostAgentPolicy | null;
  start(
    principal: Principal,
    hostId: string,
    input: HostCommandInput & { commandId: string },
  ): Promise<HostCommandStatus>;
  poll(principal: Principal, hostId: string, input: HostCommandPoll): Promise<HostCommandStatus>;
  stdin(
    principal: Principal,
    hostId: string,
    input: z.output<typeof hostCommandStdinBodySchema> & { commandId: string },
  ): Promise<{ commandId: string; accepted: boolean; reason?: string }>;
  cancel(principal: Principal, hostId: string, commandId: string): Promise<HostCommandStatus>;
  file(principal: Principal, hostId: string, input: HostFileRequest): Promise<HostFileResult>;
  lift?(hostId: string, ownerId: string, target: "hostCommands" | "hostTerminal"): void;
  lower(hostId: string, ownerId: string, target: "hostCommands" | "hostTerminal"): Promise<void>;
};
let bridge: HostAccessBridge | null = null;
export function bindHostAccess(value: HostAccessBridge | null) {
  bridge = value;
}
export function readHostAgentPolicy(hostId: string, ownerId: string): HostAgentPolicy | null {
  return bridge?.read(hostId, ownerId) ?? null;
}
export function hostAccess(): HostAccessBridge {
  if (!bridge) throw hostAccessError("host.node_offline");
  return bridge;
}
export function hostAccessError(
  code:
    | "host.not_owned"
    | "host.agent_access_off"
    | "host.node_offline"
    | "host.node_not_off"
    | "host.command_not_found"
    | "host_queue.limit",
  reason?: string,
) {
  return new ORPCError(
    code === "host.not_owned"
      ? "FORBIDDEN"
      : code === "host.command_not_found"
        ? "NOT_FOUND"
        : "CONFLICT",
    {
      data: {
        code,
        ...(reason ? { reason } : {}),
        ...(code === "host.node_offline"
          ? { retryable: true, retryAfterSeconds: 1 }
          : code === "host.agent_access_off"
            ? { retryable: false }
            : {}),
      },
    },
  );
}
