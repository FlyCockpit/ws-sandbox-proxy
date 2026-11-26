import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { HOST_STATUS_REFETCH_MS } from "@/lib/host-status";
import { orpc } from "@/utils/orpc";
import {
  type BuildTargetCheck,
  CheckLink,
  useHostBuildCheck,
  usePoolBuildCheck,
} from "./build-target-check";

/**
 * A build still waiting for a builder host (QUEUED or PLACING) after
 * `PLACING_HINT_AFTER_MS` says why, from what the pool and host APIs report
 * about the target the owner chose: a pool with no hosts (or only hosts
 * switched off for it) can never run it, an offline or draining host waits,
 * and otherwise it waits for room. Each reason names the next step.
 */
const PLACING_HINT_AFTER_MS = 30_000;
const WAITING = new Set(["QUEUED", "PLACING"]);

type Build = {
  state: string;
  createdAt: string;
  target: { poolId: string | null; hostId: string | null };
};

export function PlacingHint({ build, lang }: { build: Build; lang: string }) {
  const waiting = WAITING.has(build.state);
  const showAt = new Date(build.createdAt).getTime() + PLACING_HINT_AFTER_MS;
  useRerenderAt(waiting ? showAt : null);
  if (!waiting || Date.now() < showAt) return null;
  return <PlacingReason target={build.target} lang={lang} />;
}

function PlacingReason({ target, lang }: { target: Build["target"]; lang: string }) {
  const { t } = useTranslation(["templates"]);
  const pool = usePoolBuildCheck(target.poolId ?? "");
  const host = useQuery({
    ...orpc.sandboxHosts.getHost.queryOptions({ input: { id: target.hostId ?? "" } }),
    enabled: target.hostId !== null,
    refetchInterval: HOST_STATUS_REFETCH_MS,
    staleTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  const hostVerdict = useHostBuildCheck(host.data, host.dataUpdatedAt);
  let reason:
    | BuildTargetCheck
    | { kind: "waitPool"; label: string }
    | { kind: "waitHost"; label: string }
    | { kind: "unknown" };
  if (target.poolId !== null) {
    reason =
      pool.check.kind !== "ok"
        ? pool.check
        : pool.label
          ? { kind: "waitPool", label: pool.label }
          : { kind: "unknown" };
  } else if (target.hostId !== null && host.data) {
    reason = hostVerdict.kind !== "ok" ? hostVerdict : { kind: "waitHost", label: host.data.label };
  } else reason = { kind: "unknown" };
  return (
    <div
      role="status"
      data-build-placing={reason.kind}
      className="flex min-w-0 flex-col gap-1 rounded-md border border-amber-600/40 bg-amber-600/10 p-3 text-sm text-amber-800 dark:text-amber-300"
    >
      <p>
        {t(`templates:placing.${reason.kind}`, { label: "label" in reason ? reason.label : "" })}
      </p>
      <CheckLink kind={reason.kind} lang={lang} />
    </div>
  );
}
