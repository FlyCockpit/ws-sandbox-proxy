import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { useStatusClock } from "@/hooks/use-status-clock";
import {
  type HostConnectionFields,
  hostConnectionState,
  nextHostStateChangeAt,
} from "@/lib/host-status";
import { orpc } from "@/utils/orpc";

/**
 * Build pre-flight: what the chosen builder target can do before a build is
 * sent. A pool with no hosts (or only hosts switched off for it) can never
 * place the build VM, so the build would sit in "Placing" until its backstop;
 * that blocks submit. A target that is only offline right now is a warning:
 * it may reconnect, and the build waits for it. The server stays the
 * authority; this only reads what the pool and host APIs already report.
 */

/** One page of pool members is plenty to know whether any can build. */
const MEMBER_PAGE = 100;

export type BuildTargetCheck =
  | { kind: "ok" }
  | { kind: "emptyPool"; label: string }
  | { kind: "poolDisabled"; label: string }
  | { kind: "poolOffline"; label: string }
  | { kind: "hostOffline"; label: string }
  | { kind: "hostDraining"; label: string };

/** Blocking problems disable Build; the rest are warnings. */
export function blocksBuild(check: BuildTargetCheck): boolean {
  return check.kind === "emptyPool" || check.kind === "poolDisabled";
}

type MemberRead = { enabled?: boolean; Host?: { status: string } | null };

/** Pure: the verdict from what the pool read and its (owner-only) member rows say. */
function poolCheck(
  pool: { label: string; memberCount: number },
  members: readonly MemberRead[] | undefined,
): BuildTargetCheck {
  if (pool.memberCount === 0) return { kind: "emptyPool", label: pool.label };
  // Only the pool owner sees member rows with a host and an enabled flag.
  const owned = (members ?? []).filter((member) => member.Host != null);
  if (owned.length === 0 || owned.length < pool.memberCount) return { kind: "ok" };
  if (owned.every((member) => member.enabled === false))
    return { kind: "poolDisabled", label: pool.label };
  if (!owned.some((member) => member.enabled !== false && member.Host?.status === "CONNECTED"))
    return { kind: "poolOffline", label: pool.label };
  return { kind: "ok" };
}

function hostCheck(
  host: HostConnectionFields & { label: string; draining?: boolean },
  now: number,
): BuildTargetCheck {
  if (hostConnectionState(host, now) !== "ready") return { kind: "hostOffline", label: host.label };
  if (host.draining) return { kind: "hostDraining", label: host.label };
  return { kind: "ok" };
}

/**
 * The chosen host's verdict, judged exactly as the Hosts page judges it: the
 * same clock (frozen at the last fetch while the browser is offline) and a
 * re-render when the state changes on its own. The caller's host list must
 * poll (HOST_STATUS_REFETCH_MS); judged against a list fetched once, every
 * heartbeat turns stale after 30 s and a connected host read as offline.
 */
export function useHostBuildCheck(
  host: (HostConnectionFields & { label: string; draining?: boolean }) | undefined,
  dataUpdatedAt: number,
): BuildTargetCheck {
  const now = useStatusClock(dataUpdatedAt);
  useRerenderAt(nextHostStateChangeAt(host ? [host] : [], now));
  return host ? hostCheck(host, now) : { kind: "ok" };
}

/** Reads the chosen pool (and, for its owner, its members) while one is chosen. */
export function usePoolBuildCheck(poolId: string): {
  check: BuildTargetCheck;
  pending: boolean;
  label: string | null;
} {
  const pool = useQuery({
    ...orpc.sandboxPools.getUsable.queryOptions({ input: { id: poolId } }),
    enabled: poolId !== "",
    staleTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  const members = useQuery({
    ...orpc.sandboxPools.listUsableMembers.queryOptions({
      input: { poolId, limit: MEMBER_PAGE },
    }),
    enabled: poolId !== "" && (pool.data?.memberCount ?? 0) > 0,
    staleTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  if (poolId === "" || !pool.data)
    return { check: { kind: "ok" }, pending: pool.isPending, label: null };
  return {
    check: poolCheck(pool.data, members.data?.items as MemberRead[] | undefined),
    pending: false,
    label: pool.data.label,
  };
}

/** The pre-flight line under the builder picker (nothing when all is well). */
export function BuildTargetNote({ check, lang }: { check: BuildTargetCheck; lang: string }) {
  const { t } = useTranslation(["templates"]);
  if (check.kind === "ok") return null;
  const blocking = blocksBuild(check);
  return (
    <div
      role={blocking ? "alert" : "status"}
      data-build-preflight={check.kind}
      className={
        blocking
          ? "flex min-w-0 flex-col gap-1 rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive"
          : "flex min-w-0 flex-col gap-1 rounded-md border border-amber-600/40 bg-amber-600/10 p-3 text-sm text-amber-800 dark:text-amber-300"
      }
    >
      <p>{t(`templates:preflight.${check.kind}`, { label: check.label })}</p>
      <Link
        to={check.kind.startsWith("host") ? "/$lang/settings/hosts" : "/$lang/settings/pools"}
        params={{ lang }}
        className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
      >
        {t(
          check.kind.startsWith("host")
            ? "templates:preflight.openHosts"
            : "templates:preflight.openPools",
        )}
      </Link>
    </div>
  );
}
