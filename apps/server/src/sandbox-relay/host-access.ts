import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import { authorizeServiceAction } from "@wssp/api/lib/sdk-key-access";
import type { Principal } from "@wssp/api/sandbox/contracts";
import prisma from "@wssp/db";
import { authorityTicket } from "@wssp/db/authority";
import type { HostCommandInput, HostCommandStatus } from "@wssp/sandbox-contracts";
import { hostCommandStatusSchema } from "@wssp/sandbox-contracts";
import {
  type HostAccessBridge,
  type HostCommandPoll,
  type HostFileRequest,
  type HostNodeOffWitness,
  hostAccessError,
  hostDispatchOutcomeUnknown,
} from "../../../../packages/api/src/sandbox/host-access.js";
import {
  interruptHostCommands,
  recordHostCommandStatus,
} from "../../../../packages/api/src/sandbox/host-audit.js";
import { recordedKeyIdOf } from "../../../../packages/api/src/sandbox/principal-kinds.js";
import type { HostDaemonMessage, HostServerMessage } from "./host-access-protocol.js";
import { HostAgentPolicies } from "./host-agent-policy.js";
import { encodeServerControlMessage } from "./protocol.js";
export type HostAccessLink = {
  hostId: string;
  ownerId: string;
  epoch: number;
  socket: { send(frame: string): void };
  protocolVersion: string;
  authorized(): boolean;
  connected?(): boolean;
};
type Pending = {
  link: HostAccessLink;
  expected: string[];
  commandId?: string;
  resolve(message: HostDaemonMessage): void;
  reject(error: unknown): void;
  timer: ReturnType<typeof setTimeout>;
};
/** Correlation belongs to the exact socket/epoch, with no adoption on reconnect. */
export class HostAccessRelay implements HostAccessBridge {
  readonly policies = new HostAgentPolicies();
  private pending = new Map<string, Pending>();
  constructor(
    private readonly resolveLink: (
      hostId: string,
      ownerId: string,
    ) => Promise<HostAccessLink | null>,
    private readonly lowerTerminal: (hostId: string, ownerId: string) => void,
    private readonly liftTerminal?: (hostId: string, ownerId: string) => void,
    private readonly terminalOffWitness?: (
      hostId: string,
      ownerId: string,
    ) => HostNodeOffWitness | null,
  ) {}
  read(hostId: string, ownerId: string) {
    return this.policies.read(hostId, ownerId);
  }
  offWitness(hostId: string, ownerId: string, target: "hostCommands" | "hostTerminal") {
    return target === "hostCommands"
      ? this.policies.offWitness(hostId, ownerId)
      : (this.terminalOffWitness?.(hostId, ownerId) ?? null);
  }
  lift(hostId: string, ownerId: string, target: "hostCommands" | "hostTerminal") {
    if (target === "hostCommands") this.policies.lift(hostId, ownerId);
    else this.liftTerminal?.(hostId, ownerId);
  }
  async lower(hostId: string, ownerId: string, target: "hostCommands" | "hostTerminal") {
    if (target === "hostCommands") this.policies.lower(hostId, ownerId);
    else this.lowerTerminal(hostId, ownerId);
    const link = await this.resolveLink(hostId, ownerId);
    if (!link) return;
    // Lowering must reach the node even when 64 ordinary requests are pending.
    link.socket.send(
      encodeServerControlMessage(
        { type: "host.policy.lower", connectionEpoch: link.epoch, requestId: randomUUID(), target },
        link.protocolVersion,
      ),
    );
  }
  private async checked(
    principal: Principal,
    hostId: string,
    action:
      | "hostCommands.run"
      | "hostCommands.get"
      | "hostCommands.writeStdin"
      | "hostCommands.cancel"
      | "hostFiles.read"
      | "hostFiles.list"
      | "hostFiles.write"
      | "hostFiles.edit",
    policyRequired: boolean,
  ) {
    const current = authorityTicket({
      ownerId: principal.ownerId,
      hostId,
      credentialId: recordedKeyIdOf(principal) ?? undefined,
    });
    await authorizeServiceAction(principal, action, { sandboxHostId: hostId });
    const link = await this.resolveLink(hostId, principal.ownerId);
    if (!link) throw hostAccessError("host.node_offline");
    const host = await prisma.sandboxHost.findFirst({
      where: { id: hostId, userId: principal.ownerId, deletionRequestedAt: null },
      select: { userId: true, connectionEpoch: true, agentHostCommandsVetoedAt: true },
    });
    if (!host || host.userId !== principal.ownerId || link.ownerId !== principal.ownerId)
      throw hostAccessError("host.not_owned");
    if (host.connectionEpoch !== link.epoch || !link.authorized())
      throw hostAccessError("host.node_offline");
    // Revalidate after transport/host IO, then keep a synchronous authority fence
    // through the actual socket send (including the await back to the caller).
    await authorizeServiceAction(principal, action, { sandboxHostId: hostId });
    if (!current()) throw new ORPCError("FORBIDDEN");
    const policy = this.read(hostId, principal.ownerId);
    if (
      host.agentHostCommandsVetoedAt ||
      policy?.lowerPending ||
      (policyRequired &&
        (!policy?.hostCommands || (action.startsWith("hostFiles.") && !policy.hostFiles)))
    )
      throw hostAccessError("host.agent_access_off");
    return { link: { ...link, authorized: () => current() && link.authorized() }, policy };
  }
  private request(
    link: HostAccessLink,
    frame: HostServerMessage,
    expected: string[],
    timeoutMs: number,
  ): Promise<HostDaemonMessage> {
    if (!link.authorized()) return Promise.reject(hostAccessError("host.node_offline"));
    let count = 0;
    for (const entry of this.pending.values()) if (entry.link.hostId === link.hostId) count++;
    if (count >= 64)
      return Promise.reject(new ORPCError("TOO_MANY_REQUESTS", { data: { retryAfterSeconds: 1 } }));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(frame.requestId);
        // The frame was sent: no answer is not proof that nothing happened.
        reject(hostDispatchOutcomeUnknown(hostAccessError("host.node_offline")));
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(frame.requestId, {
        link,
        expected,
        ...("commandId" in frame ? { commandId: frame.commandId } : {}),
        resolve,
        reject,
        timer,
      });
      try {
        link.socket.send(encodeServerControlMessage(frame, link.protocolVersion));
      } catch {
        this.pending.delete(frame.requestId);
        clearTimeout(timer);
        reject(hostAccessError("host.node_offline"));
      }
    });
  }
  async start(
    principal: Principal,
    hostId: string,
    input: HostCommandInput & { commandId: string },
  ): Promise<HostCommandStatus> {
    const { link, policy } = await this.checked(principal, hostId, "hostCommands.run", true);
    if (!policy) throw hostAccessError("host.agent_access_off");
    const { waitMs: _wait, ...body } = input;
    const result = await this.request(
      link,
      {
        ...body,
        type: "host.exec.start",
        connectionEpoch: link.epoch,
        requestId: randomUUID(),
        ownerId: principal.ownerId,
        agentPolicyRevision: policy.agentPolicyRevision,
        timeoutMs: Math.min(input.timeoutMs ?? 600000, policy.hostCommandMaxMs ?? 600000),
        stdin: input.stdin ?? false,
      },
      ["host.exec.started", "host.exec.rejected"],
      15000,
    );
    if (result.type === "host.exec.rejected") {
      if (result.reason === "owner_mismatch")
        throw hostAccessError("host.not_owned", result.reason);
      if (result.reason === "host_commands_off" || result.reason === "policy_changed")
        throw hostAccessError("host.agent_access_off", result.reason);
      throw new ORPCError(result.reason === "limit" ? "TOO_MANY_REQUESTS" : "BAD_REQUEST", {
        data: {
          reason: result.reason,
          ...(result.reason === "limit" ? { retryAfterSeconds: 1 } : {}),
        },
      });
    }
    if (result.type !== "host.exec.started") throw new ORPCError("INTERNAL_SERVER_ERROR");
    return {
      commandId: input.commandId,
      state: "running",
      startedAt: result.startedAt,
      endsBy: result.endsBy,
      stdout: { offset: 0, data: "", dropped: false },
      stderr: { offset: 0, data: "", dropped: false },
      stdoutBytes: 0,
      stderrBytes: 0,
    };
  }
  async poll(principal: Principal, hostId: string, input: HostCommandPoll) {
    const { link } = await this.checked(principal, hostId, "hostCommands.get", false);
    const { commandId, stdoutOffset, stderrOffset, maxBytes } = input;
    const result = await this.request(
      link,
      {
        type: "host.exec.poll",
        connectionEpoch: link.epoch,
        requestId: randomUUID(),
        commandId,
        stdoutOffset,
        stderrOffset,
        maxBytes,
      },
      ["host.exec.status"],
      5000,
    );
    if (result.type !== "host.exec.status") throw new ORPCError("INTERNAL_SERVER_ERROR");
    const { type: _type, requestId: _request, ...status } = result;
    return hostCommandStatusSchema.parse(status);
  }
  async stdin(
    principal: Principal,
    hostId: string,
    input: { commandId: string; data: string; eof: boolean },
  ) {
    const { link } = await this.checked(principal, hostId, "hostCommands.writeStdin", true);
    const result = await this.request(
      link,
      { type: "host.exec.stdin", connectionEpoch: link.epoch, requestId: randomUUID(), ...input },
      ["host.exec.stdin.result"],
      5000,
    );
    if (result.type !== "host.exec.stdin.result") throw new ORPCError("INTERNAL_SERVER_ERROR");
    const { type: _type, requestId: _request, ...body } = result;
    return body;
  }
  async cancel(principal: Principal, hostId: string, commandId: string) {
    const { link } = await this.checked(principal, hostId, "hostCommands.cancel", false);
    const result = await this.request(
      link,
      { type: "host.exec.cancel", connectionEpoch: link.epoch, requestId: randomUUID(), commandId },
      ["host.exec.status"],
      5000,
    );
    if (result.type !== "host.exec.status") throw new ORPCError("INTERNAL_SERVER_ERROR");
    const { type: _type, requestId: _request, ...status } = result;
    return status;
  }
  async file(principal: Principal, hostId: string, input: HostFileRequest) {
    const { link, policy } = await this.checked(principal, hostId, `hostFiles.${input.op}`, true);
    if (!policy) throw hostAccessError("host.agent_access_off");
    const result = await this.request(
      link,
      {
        ...input,
        type: "host.file.request",
        connectionEpoch: link.epoch,
        requestId: randomUUID(),
        ownerId: principal.ownerId,
        agentPolicyRevision: policy.agentPolicyRevision,
      },
      ["host.file.result"],
      30000,
    );
    if (result.type !== "host.file.result") throw new ORPCError("INTERNAL_SERVER_ERROR");
    if (!result.ok)
      throw new ORPCError("UNPROCESSABLE_CONTENT", {
        data: { code: "host.file_error", reason: result.error },
      });
    return result.result;
  }
  async receive(link: HostAccessLink, message: HostDaemonMessage) {
    if (!link.authorized()) return;
    if (message.type === "host.exec.status" && message.state !== "running") {
      const { type: _type, requestId: _request, ...status } = message;
      await recordHostCommandStatus(link.hostId, link.ownerId, status);
    }
    if (!("requestId" in message) || !message.requestId) return;
    const pending = this.pending.get(message.requestId);
    if (
      !pending ||
      pending.link.socket !== link.socket ||
      pending.link.epoch !== link.epoch ||
      !pending.expected.includes(message.type) ||
      (pending.commandId && (!("commandId" in message) || pending.commandId !== message.commandId))
    )
      return;
    this.pending.delete(message.requestId);
    clearTimeout(pending.timer);
    pending.resolve(message);
  }
  async disconnect(hostId: string, ownerId: string, socket: object) {
    this.policies.remove(hostId, socket);
    for (const [id, pending] of this.pending)
      if (pending.link.socket === socket) {
        this.pending.delete(id);
        clearTimeout(pending.timer);
        pending.reject(hostDispatchOutcomeUnknown(hostAccessError("host.node_offline")));
      }
    await interruptHostCommands(hostId, ownerId);
  }
}
