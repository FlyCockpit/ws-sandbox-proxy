/** Live, authenticated current-link policy. No database/offline policy authority. */
import { randomUUID } from "node:crypto";
import { type DaemonControlMessage, encodeServerControlMessage } from "./protocol.js";

type Report = Extract<DaemonControlMessage, { type: "host.terminal-policy" }>;
export type HostTerminalPolicy = {
  hostTerminal: boolean;
  requireHostTerminalTotp: boolean;
  policyRevision: number;
};
type Link = {
  socket: { send(frame: string): void };
  hostId: string;
  ownerId: string;
  epoch: number;
  authorized(): boolean;
};
type Entry = { link: Link; policy: HostTerminalPolicy; sequence: number };
export class HostTerminalPolicies {
  private entries = new Map<string, Entry>();
  private pending = new Map<
    string,
    {
      entry: Entry;
      revision: number;
      resolve(value: boolean): void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  constructor(
    private readonly invalidate: (hostId: string, reason?: "host_terminals_disabled") => void,
  ) {}
  register(link: Link, policy: HostTerminalPolicy): void {
    this.remove(link.hostId);
    this.entries.set(link.hostId, { link, policy: { ...policy }, sequence: 0 });
  }
  remove(hostId: string, socket?: Link["socket"]): void {
    const entry = this.entries.get(hostId);
    if (!entry || (socket && entry.link.socket !== socket)) return;
    this.entries.delete(hostId);
    this.settle(hostId, false);
    this.invalidate(hostId);
  }
  read(hostId: string, ownerId: string): (HostTerminalPolicy & { epoch: number }) | undefined {
    const entry = this.entries.get(hostId);
    if (!entry || entry.link.ownerId !== ownerId || !entry.link.authorized()) return;
    return { ...entry.policy, epoch: entry.link.epoch };
  }
  report(hostId: string, socket: Link["socket"], report: Report): boolean {
    const entry = this.entries.get(hostId);
    if (
      !entry ||
      entry.link.socket !== socket ||
      entry.link.epoch !== report.connectionEpoch ||
      !entry.link.authorized() ||
      report.sequence <= entry.sequence ||
      report.policyRevision < entry.policy.policyRevision
    )
      return false;
    const old = entry.policy;
    // Same revision cannot claim different persisted policy.
    if (
      report.policyRevision === old.policyRevision &&
      (report.hostTerminal !== old.hostTerminal ||
        report.requireHostTerminalTotp !== old.requireHostTerminalTotp)
    )
      return false;
    entry.sequence = report.sequence;
    entry.policy = {
      hostTerminal: report.hostTerminal,
      requireHostTerminalTotp: report.requireHostTerminalTotp,
      policyRevision: report.policyRevision,
    };
    if (old.policyRevision !== report.policyRevision) {
      if (report.hostTerminal) this.invalidate(hostId);
      else this.invalidate(hostId, "host_terminals_disabled");
    }
    const pending = this.pending.get(hostId);
    if (
      pending?.entry === entry &&
      report.policyRevision > pending.revision &&
      report.requireHostTerminalTotp
    )
      this.settle(hostId, true);
    return true;
  }
  /** Called by the registered live-owner, host-owner, CSRF/budgeted procedure. */
  raise(hostId: string, ownerId: string, timeoutMs = 5000): Promise<boolean> {
    const entry = this.entries.get(hostId);
    if (
      !entry ||
      entry.link.ownerId !== ownerId ||
      !entry.link.authorized() ||
      this.pending.has(hostId)
    )
      return Promise.resolve(false);
    return new Promise((resolve) => {
      const timer = setTimeout(() => this.settle(hostId, false), timeoutMs);
      timer.unref?.();
      this.pending.set(hostId, { entry, revision: entry.policy.policyRevision, resolve, timer });
      try {
        entry.link.socket.send(
          encodeServerControlMessage(
            {
              type: "host.terminal-policy.raise",
              connectionEpoch: entry.link.epoch,
              requestId: `hp${randomUUID().replaceAll("-", "")}`,
            },
            "1.0",
          ),
        );
      } catch {
        this.settle(hostId, false);
      }
    });
  }
  private settle(hostId: string, confirmed: boolean): void {
    const pending = this.pending.get(hostId);
    if (!pending) return;
    this.pending.delete(hostId);
    clearTimeout(pending.timer);
    pending.resolve(confirmed);
  }
}
