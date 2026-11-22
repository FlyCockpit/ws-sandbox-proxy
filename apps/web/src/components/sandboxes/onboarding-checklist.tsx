import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import { CheckCircle2, Circle } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { hostConnectionState, hostGuardState } from "@/lib/host-status";
import { orpc } from "@/utils/orpc";

/**
 * Shown on Sandboxes when the Active list is empty: the three steps to a first
 * sandbox. Each check is one bounded owner-scoped read. A shared pool counts
 * as "somewhere to run", so a user who only joined someone else's pool is not
 * told to enroll a host. An enrolled host counts only once it is connected
 * with a healthy egress guard: an enrolled machine that cannot take
 * sandboxes is not a finished step.
 */
/** Hosts read for the first step: enough for a personal fleet, still bounded. */
const HOSTS_CHECKED = 20;
const HOSTS_REFETCH_MS = 15_000;

export function OnboardingChecklist({
  lang,
  enabled,
  onCreate,
}: {
  lang: string;
  enabled: boolean;
  onCreate: () => void;
}) {
  const { t } = useTranslation("sandboxes");
  const hosts = useQuery({
    ...orpc.sandboxHosts.listHosts.queryOptions({ input: { limit: HOSTS_CHECKED } }),
    enabled,
    // Connection state depends on a fresh heartbeat: never judge from a cached
    // page, and follow the host while the checklist is shown (as Hosts does).
    refetchOnMount: "always",
    refetchInterval: HOSTS_REFETCH_MS,
  });
  const pools = useQuery({
    ...orpc.sandboxPools.listUsable.queryOptions({ input: { limit: 1 } }),
    enabled,
  });
  const templates = useQuery({
    ...orpc.sandboxTemplates.listTemplates.queryOptions({
      input: { limit: 1, status: "active" },
    }),
    enabled,
  });

  if (hosts.isPending || pools.isPending || templates.isPending) {
    return (
      <div data-onboarding className="flex flex-col gap-3 rounded-xl border p-4">
        <Skeleton className="h-5 w-48" />
        {[0, 1, 2].map((row) => (
          <Skeleton key={row} className="h-11 w-full" />
        ))}
      </div>
    );
  }

  // A failed check reads as "not done yet": the step's link still works.
  const now = Date.now();
  const hostItems = hosts.data?.items ?? [];
  const readyHost = hostItems.some(
    (host) => hostConnectionState(host, now) === "ready" && hostGuardState(host) === "running",
  );
  const hasPlace = readyHost || (pools.data?.items.length ?? 0) > 0;
  // Enrolled but not usable yet: point at the host, not at enrolling another.
  const hostNotReady = !hasPlace && hostItems.length > 0;
  const hasTemplate = (templates.data?.items.length ?? 0) > 0;
  const linkClass = cn(buttonVariants({ variant: "outline", size: "touch" }), "shrink-0");

  return (
    <section
      data-onboarding
      aria-labelledby="sandboxes-onboarding-title"
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="space-y-1">
        <h2 id="sandboxes-onboarding-title" className="font-heading text-base font-semibold">
          {t("onboarding.title")}
        </h2>
        <p className="text-sm text-muted-foreground">{t("onboarding.description")}</p>
      </div>
      <ol className="flex min-w-0 flex-col gap-2">
        <Step
          done={hasPlace}
          title={t("onboarding.host.title")}
          description={t(hostNotReady ? "onboarding.host.notReady" : "onboarding.host.description")}
          action={
            hasPlace ? null : (
              <div className="flex shrink-0 flex-wrap gap-2">
                <Link to="/$lang/settings/hosts" params={{ lang }} className={linkClass}>
                  {t(hostNotReady ? "onboarding.host.openHosts" : "onboarding.host.action")}
                </Link>
                <Link
                  to="/$lang/settings/pools"
                  params={{ lang }}
                  search={{ tab: "shared" }}
                  className={linkClass}
                >
                  {t("onboarding.host.poolsAction")}
                </Link>
              </div>
            )
          }
        />
        <Step
          done={hasTemplate}
          title={t("onboarding.template.title")}
          description={t("onboarding.template.description")}
          action={
            hasTemplate ? null : (
              <Link to="/$lang/dashboard/templates" params={{ lang }} className={linkClass}>
                {t("onboarding.template.action")}
              </Link>
            )
          }
        />
        <Step
          done={false}
          title={t("onboarding.sandbox.title")}
          description={t("onboarding.sandbox.description")}
          action={
            <Button
              type="button"
              size="touch"
              className="shrink-0"
              disabled={!hasPlace || !hasTemplate}
              onClick={onCreate}
            >
              {t("onboarding.sandbox.action")}
            </Button>
          }
        />
      </ol>
    </section>
  );
}

function Step({
  done,
  title,
  description,
  action,
}: {
  done: boolean;
  title: string;
  description: string;
  action: ReactNode;
}) {
  const { t } = useTranslation("sandboxes");
  const Icon = done ? CheckCircle2 : Circle;
  return (
    <li
      data-step-done={done ? "true" : "false"}
      className="flex min-w-0 flex-col gap-3 rounded-lg border p-3 sm:flex-row sm:items-center"
    >
      <div className="flex min-w-0 flex-1 items-start gap-3">
        <Icon
          aria-hidden="true"
          className={cn("mt-0.5 size-5 shrink-0", done ? "text-primary" : "text-muted-foreground")}
        />
        <div className="min-w-0 space-y-0.5">
          <p className="font-medium">
            {title}
            {done ? <span className="sr-only"> ({t("onboarding.done")})</span> : null}
          </p>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
      </div>
      {action}
    </li>
  );
}
