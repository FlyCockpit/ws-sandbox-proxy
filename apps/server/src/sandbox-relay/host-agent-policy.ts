import type { HostAgentPolicy } from "../../../../packages/api/src/sandbox/host-access.js";
import type { HostDaemonMessage } from "./host-access-protocol.js";

type Report = Extract<HostDaemonMessage, { type: "host.agent-policy" }>;
export type AgentPolicyLink = {
  hostId: string;
  ownerId: string;
  epoch: number;
  socket: object;
  authorized(): boolean;
  connected?(): boolean;
};
type Entry = { link: AgentPolicyLink; policy: HostAgentPolicy; sequence: number };
/** Authenticated live reports only. Durable dashboard vetoes veto their authority. */
export class HostAgentPolicies {
  private entries = new Map<string, Entry>();
  register(link: AgentPolicyLink, policy: HostAgentPolicy) {
    this.entries.set(link.hostId, { link, policy: { ...policy }, sequence: 0 });
  }
  read(hostId: string, ownerId: string): HostAgentPolicy | null {
    const entry = this.entries.get(hostId);
    if (!entry || entry.link.ownerId !== ownerId || !entry.link.authorized()) return null;
    return {
      ...entry.policy,
      epoch: entry.link.epoch,
      nodeHostCommands: entry.policy.hostCommands,
      nodeHostFiles: entry.policy.hostFiles,
      hostCommands: entry.policy.hostCommands && !entry.policy.lowerPending,
      hostFiles: entry.policy.hostFiles && !entry.policy.lowerPending,
    };
  }
  offWitness(hostId: string, ownerId: string) {
    const entry = this.entries.get(hostId);
    if (!entry || !this.read(hostId, ownerId) || entry.policy.hostCommands) return null;
    return {
      epoch: entry.link.epoch,
      // The authority-change fence invalidates ordinary read tickets. This
      // witness proves only that the same live node still reports off.
      isOff: () =>
        this.entries.get(hostId) === entry &&
        (entry.link.connected?.() ?? entry.link.authorized()) &&
        entry.policy.hostCommands === false,
    };
  }
  lower(hostId: string, ownerId: string) {
    const entry = this.entries.get(hostId);
    if (entry?.link.ownerId === ownerId) entry.policy.lowerPending = true;
  }
  lift(hostId: string, ownerId: string) {
    const entry = this.entries.get(hostId);
    if (entry?.link.ownerId === ownerId) entry.policy.lowerPending = false;
  }
  remove(hostId: string, socket?: object) {
    const entry = this.entries.get(hostId);
    if (entry && (!socket || entry.link.socket === socket)) this.entries.delete(hostId);
  }
  report(hostId: string, socket: object, report: Report): boolean {
    const entry = this.entries.get(hostId);
    if (
      !entry ||
      entry.link.socket !== socket ||
      entry.link.epoch !== report.connectionEpoch ||
      !entry.link.authorized() ||
      report.sequence <= entry.sequence ||
      report.agentPolicyRevision < entry.policy.agentPolicyRevision
    )
      return false;
    const old = entry.policy;
    if (
      report.agentPolicyRevision === old.agentPolicyRevision &&
      (report.hostCommands !== old.hostCommands ||
        report.hostFiles !== old.hostFiles ||
        report.hostCommandMaxMs !== old.hostCommandMaxMs)
    )
      return false;
    entry.sequence = report.sequence;
    entry.policy = {
      hostCommands: report.hostCommands,
      hostFiles: report.hostFiles,
      ...(report.hostCommandMaxMs === undefined
        ? {}
        : { hostCommandMaxMs: report.hostCommandMaxMs }),
      agentPolicyRevision: report.agentPolicyRevision,
      lowerPending: old.lowerPending,
    };
    return true;
  }
}
