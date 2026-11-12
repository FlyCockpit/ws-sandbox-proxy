import type { AppRouterClient } from "@wssp/api/routers/index";
import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
/**
 * Pure presentation rules for the Hosts dashboard (C44). Nothing here grants
 * or predicts authority: every mutation is decided by the server, and these
 * helpers only decide what to show and which controls to offer.
 */

import { HOST_HEARTBEAT_STALE_AFTER_MS } from "@wssp/config/host-status";

export { HOST_HEARTBEAT_STALE_AFTER_MS };

export type HostConnectionFields = {
  status: "DISCONNECTED" | "CONNECTED" | "STALE" | "REVOKED";
  lastConnectedAt: Date | string | null;
  lastHeartbeatAt: Date | string | null;
  deletionRequestedAt: Date | string | null;
  /** Set while the server refuses the node's inventory (absent on older views). */
  quarantinedAt?: Date | string | null;
};

/**
 * A daemon that cannot finish connecting retries at least every 30 s, and
 * every attempt records `lastConnectedAt`. A disconnected host whose last
 * attempt is this recent is still trying: it is not "offline".
 */
export const HOST_RECONNECTING_WINDOW_MS = 2 * 60_000;

/**
 * - `ready`: connected, with a heartbeat inside the stale window.
 * - `stale`: the server still has it connected but the heartbeat is old or
 *   missing (or the server marked it STALE). Never shown as ready.
 * - `quarantined`: its daemon keeps trying (within the window), and the
 *   server refuses its inventory.
 * - `reconnecting`: not connected, but its daemon tried within the window.
 * - `offline`: connected before, not now. `never`: has never connected.
 * - `revoked`: its credential was revoked. `deleting`: deletion is pending.
 */
export type HostConnectionState =
  | "ready"
  | "stale"
  | "quarantined"
  | "reconnecting"
  | "offline"
  | "never"
  | "revoked"
  | "deleting";

export function toMs(value: Date | string | null | undefined): number | null {
  if (value == null) return null;
  const ms = value instanceof Date ? value.getTime() : Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

/** DB receipts may lead the browser clock. Display tolerates that skew;
 * server admission keeps using the authoritative future-rejecting predicate. */
function isDisplayHeartbeatFresh(beat: number | null, now: number): boolean {
  return beat != null && now - beat <= HOST_HEARTBEAT_STALE_AFTER_MS;
}

export function hostConnectionState(host: HostConnectionFields, now: number): HostConnectionState {
  if (host.deletionRequestedAt != null) return "deleting";
  if (host.status === "REVOKED") return "revoked";
  if (host.status === "CONNECTED") {
    const beat = toMs(host.lastHeartbeatAt);
    return isDisplayHeartbeatFresh(beat, now) ? "ready" : "stale";
  }
  if (host.status === "STALE") return "stale";
  const connected = toMs(host.lastConnectedAt);
  if (connected == null) return "never";
  if (now - connected > HOST_RECONNECTING_WINDOW_MS) return "offline";
  return host.quarantinedAt != null ? "quarantined" : "reconnecting";
}

/**
 * The earliest moment a host's display state changes on its own (a ready
 * host turns stale; a reconnecting or quarantined one turns offline), or
 * null. The page re-renders then even when no refetch arrives (a server
 * outage leaves the last successful data on screen), so a silent host cannot
 * keep showing ready, reconnecting or quarantined.
 */
export function nextHostStateChangeAt(
  hosts: readonly (HostConnectionFields & { storagePools?: readonly { reportedAt: string }[] })[],
  now: number,
): number | null {
  let next: number | null = null;
  for (const host of hosts) {
    for (const pool of host.storagePools ?? []) {
      const report = toMs(pool.reportedAt);
      const at = report === null ? null : report + STORAGE_REPORT_STALE_MS + 1;
      if (at !== null && at > now && (next === null || at < next)) next = at;
    }
    const state = hostConnectionState(host, now);
    if (state === "reconnecting" || state === "quarantined") {
      // Both turn offline once the last attempt leaves the window.
      const at = (toMs(host.lastConnectedAt) ?? now) + HOST_RECONNECTING_WINDOW_MS + 1;
      if (next == null || at < next) next = at;
      continue;
    }
    if (state !== "ready") continue;
    const beat = toMs(host.lastHeartbeatAt);
    if (beat == null) continue;
    const at = beat + HOST_HEARTBEAT_STALE_AFTER_MS + 1;
    if (next == null || at < next) next = at;
  }
  return next;
}

/** Locale-aware "12 seconds ago" / "hace 3 minutos". */
export function formatAge(atMs: number, locale: string, now: number): string {
  const formatter = new Intl.RelativeTimeFormat(locale, { numeric: "always" });
  const diff = Math.min(0, atMs - now);
  const units: ReadonlyArray<[Intl.RelativeTimeFormatUnit, number]> = [
    ["day", 86_400_000],
    ["hour", 3_600_000],
    ["minute", 60_000],
  ];
  for (const [unit, size] of units) {
    if (-diff >= size) return formatter.format(Math.round(diff / size), unit);
  }
  // `-0` keeps "0 seconds ago" (a positive zero reads "in 0 seconds").
  return formatter.format(Math.round(diff / 1000) || -0, "second");
}

/**
 * Deletion is offered only for a host with no live sandboxes that is not
 * already pending deletion. The server still decides (retained disks,
 * transfers and unfinished work can leave the deletion pending).
 */
export function hostDeleteBlocker(host: {
  liveSandboxCount: number;
  deletionRequestedAt: Date | string | null;
}): "pending" | "live" | null {
  if (host.deletionRequestedAt != null) return "pending";
  if (host.liveSandboxCount > 0) return "live";
  return null;
}

/** The "Drained" badge: draining and nothing live left. */
export function hostDrainBadge(host: {
  draining: boolean;
  drained: boolean;
}): "draining" | "drained" | null {
  if (!host.draining) return null;
  return host.drained ? "drained" : "draining";
}

/**
 * Why a reporting host can't create sandboxes (E-06): it never advertised
 * egress enforcement, and every create carries a deny-default policy. The
 * runtime picks the explanation; an unsupported runtime has its own hint,
 * and a host that never reported has nothing to explain yet.
 */
export function hostEgressBlocker(host: {
  daemonRuntime: "FAKE" | "INCUS_KVM" | "UNSUPPORTED" | null;
  egressEnforcement: boolean;
}): "incusHint" | "fakeHint" | null {
  if (host.egressEnforcement) return null;
  if (host.daemonRuntime === "INCUS_KVM") return "incusHint";
  if (host.daemonRuntime === "FAKE") return "fakeHint";
  return null;
}

/** Reason codes the daemon reports for an unhealthy egress guard (bounded). */
const HOST_GUARD_REASONS = [
  "guard_unreachable",
  "guard_not_ok",
  "guard_quarantined",
  "guard_lease_expired",
  "guard_outdated",
  "guard_root_source",
  "guard_deployment_source",
  "host_firewall_blocks_sandboxes",
  "incus_server_shared",
] as const;
export type HostGuardState = "running" | "unknown" | (typeof HOST_GUARD_REASONS)[number];

/**
 * The node's root-owned egress guard as one display state. Only an active
 * lease is `running` (the server's schedulability rule); a host without one
 * cannot start sandboxes in either mode. An unrecognized or missing reason
 * reads as `unknown` (never reported, or a newer daemon's code).
 */
export function hostGuardState(host: {
  egressGuard: { ok: boolean; reason: string | null; leaseActive: boolean };
}): HostGuardState {
  const guard = host.egressGuard;
  if (guard.leaseActive) return "running";
  const known = HOST_GUARD_REASONS.find((reason) => reason === guard.reason);
  if (known) return known;
  return guard.ok ? "guard_lease_expired" : "unknown";
}

/**
 * The install/upgrade command the node owner runs (as root, so it is shown,
 * never run). `command -v` resolves the binary because sudo's PATH may not
 * include the user's install directory; `$USER` is the daemon's user.
 */
export const GUARD_INSTALL_COMMAND =
  'sudo "$(command -v wssp)" guard install --daemon-user "$USER"';
/**
 * The fix for `host_firewall_blocks_sandboxes`: the guard adds the minimal
 * ufw rules for the sandbox bridges (DHCP, DNS, login proxy; routing), printing each.
 */
export const GUARD_FIREWALL_COMMAND = `${GUARD_INSTALL_COMMAND} --configure-ufw`;
export const OPEN_EGRESS_FOR_OTHERS_COMMAND = "wssp config set-open-egress-for-others on|off";
/** Display-only: the node owner's guest-sudo consent for other users' sandboxes. */
export const GUEST_SUDO_FOR_OTHERS_COMMAND =
  "wssp config set-allow-guest-sudo-for-others on|off|default";

/** Report freshness is separate from the last stored budget used by offline cold boots. */
export function hostCapacityState(
  host: HostConnectionFields & { capacity: { memoryBudgetMiB: number | null; current: boolean } },
  now: number,
): "current" | "stale" | "never" {
  if (host.capacity.memoryBudgetMiB === null) return "never";
  return host.capacity.current && hostConnectionState(host, now) === "ready" ? "current" : "stale";
}

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown };

/** Stable server error code (`sandbox.host_capacity`, …) of an oRPC error, if any. */
function sandboxErrorCode(error: unknown): string | null {
  if (!error || typeof error !== "object") return null;
  const data = (error as ErrorShape).data;
  if (data && typeof data === "object" && "code" in data) {
    const code = (data as { code?: unknown }).code;
    return typeof code === "string" ? code : null;
  }
  return null;
}

export type HostMutationProblem =
  | "capacity"
  | "draining"
  | "pendingDeletion"
  | "forgetUnsafe"
  | "notFound"
  | "changed"
  | "forbidden"
  | "generic";

/** The sandboxes a refused Forget lists (`sandbox.host_forget_unsafe`), bounded. */
export function hostForgetUnsafeSandboxes(error: unknown): string[] {
  if (sandboxErrorCode(error) !== "sandbox.host_forget_unsafe") return [];
  const data = (error as ErrorShape).data;
  const ids =
    data && typeof data === "object" ? (data as { sandboxIds?: unknown }).sandboxIds : undefined;
  return Array.isArray(ids)
    ? ids.filter((id): id is string => typeof id === "string").slice(0, 50)
    : [];
}

/** Forget is offered once the host cannot be reached (or its deletion is
 * stuck): never for a connected, fresh host. */
export function hostForgettable(state: HostConnectionState): boolean {
  return state === "offline" || state === "stale" || state === "deleting" || state === "revoked";
}

/**
 * Map a failed host mutation to the explanation shown next to it. Every
 * problem except `generic` also means the list is stale, so the caller
 * refetches after showing it.
 */
export function hostMutationProblem(error: unknown): HostMutationProblem {
  const code = sandboxErrorCode(error);
  if (code === "sandbox.host_capacity") return "capacity";
  if (code === "sandbox.host_draining") return "draining";
  if (code === "sandbox.host_delete_conflict") return "pendingDeletion";
  if (code === "sandbox.host_forget_unsafe") return "forgetUnsafe";
  const shape = (error && typeof error === "object" ? error : {}) as ErrorShape;
  if (shape.code === "NOT_FOUND" || shape.status === 404) return "notFound";
  if (shape.code === "CONFLICT" || shape.status === 409) return "changed";
  if (shape.code === "FORBIDDEN" || shape.status === 403) return "forbidden";
  return "generic";
}

/**
 * POSIX single-quote a shell word unless it is plainly safe. Host slugs and
 * IDs are already restricted server-side; this keeps a copied command
 * well-formed even for an unexpected server origin.
 */
export function shellWord(value: string): string {
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Nonsecret enrollment commands use the daemon automatic resource defaults. */
export function hostCommands(serverUrl: string, host?: { id: string; slug: string }) {
  const server = shellWord(serverUrl);
  return {
    deviceLogin: `wssp login --slug ${shellWord(host?.slug ?? "my-host")} --server ${server}`,
    connect: `wssp connect`,
    tokenConnect: host
      ? `wssp connect --server ${server} --host-id ${shellWord(host.id)} --host-token-env WSSP_HOST_TOKEN`
      : null,
  };
}

// Mirrors the server's storage observation validity window, independently of heartbeat freshness.
const STORAGE_REPORT_STALE_MS = 15_000;
type HostSummary = Awaited<
  ReturnType<AppRouterClient["sandboxHosts"]["listHosts"]>
>["items"][number];
export type StorageSummary = HostSummary["storagePools"][number];

export function storageDisplayState(
  pool: StorageSummary,
  now: number,
): "healthy" | "unavailable" | "stale" {
  const at = toMs(pool.reportedAt);
  if (at === null || at > now || now - at > STORAGE_REPORT_STALE_MS) return "stale";
  return pool.health;
}

/** An estimate from discovery only; authority/source/epoch/fit are rechecked on acceptance. */
export function hostResourceFit(
  host: HostConnectionFields & Pick<HostSummary, "capacity" | "storagePools" | "retainedRootCount">,
  size: { cpuCount?: number; memoryMiB?: number; diskGiB?: number },
  now: number,
): "unknown" | "size" | "storage" | "ram" | "ceiling" | "vcpu" | "disk" | "fits" {
  if (hostCapacityState(host, now) !== "current") return "unknown";
  const { capacity } = host;
  if (
    (size.cpuCount !== undefined && size.cpuCount > (capacity.maxCpuCount ?? 0)) ||
    (size.memoryMiB !== undefined && size.memoryMiB > (capacity.maxMemoryMiB ?? 0))
  )
    return "size";
  const pools = host.storagePools.filter(
    (pool) => storageDisplayState(pool, now) === "healthy" && !pool.draining,
  );
  if (!pools.length) return "storage";
  if (
    size.memoryMiB !== undefined &&
    size.memoryMiB + VM_SIZE_LIMITS.vmHostOverheadMiB > (capacity.memoryAvailableMiB ?? 0)
  )
    return "ram";
  if (host.retainedRootCount >= VM_SIZE_LIMITS.hostManagedSandboxCeiling) return "ceiling";
  if (size.cpuCount !== undefined && size.cpuCount > (capacity.vcpuAvailable ?? 0)) return "vcpu";
  const diskGiB = size.diskGiB;
  if (
    diskGiB !== undefined &&
    !pools.some(
      (pool) =>
        pool.capacityGiB - pool.diskReservedGiB >= diskGiB + VM_SIZE_LIMITS.rootDiskOverheadGiB,
    )
  )
    return "disk";
  return [size.cpuCount, size.memoryMiB, size.diskGiB].some(
    (value) => value === undefined || !Number.isFinite(value),
  )
    ? "unknown"
    : "fits";
}
