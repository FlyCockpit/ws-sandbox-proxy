import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { env } from "@wssp/env/web";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { cn } from "@wssp/ui/lib/utils";
import { CheckCircle2, CircleDashed, ListChecks, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { DEFAULT_OBSERVABILITY_SEARCH } from "@/lib/admin-observability-search";
import { docsUrl } from "@/lib/docs-links";
import { orpc } from "@/utils/orpc";

/** `ok`: set up; `optional`: off, and fine to leave off; `missing`: off, and something needs it; `problem`: on but not working. */
type SetupState = "ok" | "optional" | "missing" | "problem";

const STATE_ICON = {
  ok: CheckCircle2,
  optional: CircleDashed,
  missing: TriangleAlert,
  problem: TriangleAlert,
} as const;

const queryMeta = { meta: { skipGlobalErrorToast: true } };

/**
 * First-run checklist for whoever deploys this server: which deployment
 * features are configured. Read-only and built from the admin reads the
 * other admin pages already use (no values, only states). Each row says what
 * the feature enables and where it is configured. A SETUP_KEY that is still
 * set after the first admin exists gets its own row, shown only then: this
 * card is where wssp tells admins about deployment setup (there is no
 * banner), so the "remove it" reminder lives here.
 */
export function DeploymentSetupCard({ lang }: { lang: string }) {
  const { t } = useTranslation("admin");
  const appConfig = useQuery({ ...orpc.appConfig.queryOptions(), ...queryMeta });
  const settings = useQuery({ ...orpc.settings.adminGet.queryOptions(), ...queryMeta });
  const dataKey = useQuery({ ...orpc.adminDataKeys.status.queryOptions(), ...queryMeta });
  const backups = useQuery({ ...orpc.queue.backupStatus.queryOptions(), ...queryMeta });
  const tunnel = useQuery({ ...orpc.adminTunnel.get.queryOptions(), ...queryMeta });
  const docsHref = docsUrl(env.VITE_DOCS_URL, "environment");

  const observabilityLink = (
    <Link
      to="/$lang/admin/observability"
      params={{ lang }}
      search={{ ...DEFAULT_OBSERVABILITY_SEARCH, tab: "maintenance" }}
      className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
    >
      {t("setup.maintenanceLink")}
    </Link>
  );
  const settingsLink = (
    <Link
      to="/$lang/admin/settings"
      params={{ lang }}
      className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
    >
      {t("setup.settingsLink")}
    </Link>
  );

  const emailState: SetupState | null = appConfig.data
    ? appConfig.data.emailEnabled
      ? "ok"
      : "missing"
    : null;
  const imageMode = settings.data?.imageStoreMode;
  const imageState: SetupState | null = !imageMode ? null : imageMode === "s3" ? "ok" : "missing";
  // A server answer without the mode reads as unknown, never as loading forever.
  const imageUnknown = settings.isError || (settings.isSuccess && !imageMode);
  const keyState: SetupState | null = dataKey.data
    ? dataKey.data.configured
      ? "ok"
      : "missing"
    : null;
  // Only a fresh backup is healthy; a missing verdict, an empty bucket, a late
  // or failing backup all need a look in Maintenance (queue.backupStatus).
  const backupVerdict = backups.data?.configured ? (backups.data.status?.state ?? null) : undefined;
  const backupState: SetupState | null = !backups.data
    ? null
    : !backups.data.configured
      ? "optional"
      : backupVerdict === "fresh"
        ? "ok"
        : "problem";
  const tunnelState: SetupState | null = tunnel.data
    ? tunnel.data.configured
      ? "ok"
      : "optional"
    : null;

  return (
    <Card data-deployment-setup="">
      <CardHeader className="space-y-2">
        <div className="flex items-center gap-2">
          <ListChecks aria-hidden className="size-4 text-muted-foreground" />
          <CardTitle className="text-base">{t("setup.title")}</CardTitle>
        </div>
        <CardDescription>
          {t("setup.description")}{" "}
          <a
            href={docsHref}
            target="_blank"
            rel="noreferrer"
            className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
          >
            {t("setup.docsLink")}
          </a>
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex min-w-0 flex-col divide-y">
          {settings.data?.setupKeySet ? (
            <SetupRow
              id="setup-key"
              state="problem"
              failed={false}
              title={t("setup.setupKey.title")}
              status={t("setup.setupKey.set")}
            />
          ) : null}
          <SetupRow
            id="email"
            state={emailState}
            failed={appConfig.isError}
            title={t("setup.email.title")}
            status={emailState === "ok" ? t("setup.email.ok") : t("setup.email.missing")}
          />
          <SetupRow
            id="image-store"
            state={imageState}
            failed={imageUnknown}
            title={t("setup.imageStore.title")}
            status={imageMode ? t(`setup.imageStore.${imageMode}`) : ""}
          />
          <SetupRow
            id="data-key"
            state={keyState}
            failed={dataKey.isError}
            title={t("setup.dataKey.title")}
            status={keyState === "ok" ? t("setup.dataKey.ok") : t("setup.dataKey.missing")}
          />
          <SetupRow
            id="backups"
            state={backupState}
            failed={backups.isError}
            title={t("setup.backups.title")}
            status={
              backupState === "problem" && backupVerdict === null
                ? t("setup.backups.unknown")
                : backupState
                  ? t(`setup.backups.${backupState}`)
                  : ""
            }
            action={backupState === "problem" ? observabilityLink : null}
          />
          <SetupRow
            id="tunnels"
            state={tunnelState}
            failed={tunnel.isError}
            title={t("setup.tunnels.title")}
            status={
              tunnelState === "ok"
                ? t("setup.tunnels.ok", { url: tunnel.data?.apiUrl ?? "" })
                : t("setup.tunnels.optional")
            }
            action={settingsLink}
          />
        </ul>
      </CardContent>
    </Card>
  );
}

function SetupRow({
  id,
  state,
  failed,
  title,
  status,
  action = null,
}: {
  id: string;
  state: SetupState | null;
  failed: boolean;
  title: string;
  status: string;
  action?: ReactNode;
}) {
  const { t } = useTranslation("admin");
  const Icon = state ? STATE_ICON[state] : null;
  return (
    <li
      data-setup-row={id}
      data-setup-state={failed ? "unknown" : (state ?? "loading")}
      className="flex min-w-0 items-start gap-3 py-3 first:pt-0 last:pb-0"
    >
      {Icon ? (
        <Icon
          aria-hidden
          className={cn(
            "mt-0.5 size-4 shrink-0",
            state === "ok" && "text-emerald-600 dark:text-emerald-400",
            (state === "missing" || state === "problem") && "text-amber-600 dark:text-amber-400",
            state === "optional" && "text-muted-foreground",
          )}
        />
      ) : (
        <span aria-hidden className="mt-0.5 size-4 shrink-0" />
      )}
      <div className="flex min-w-0 flex-1 flex-col gap-0.5 text-sm">
        <p className="font-medium">{title}</p>
        {failed ? (
          <p className="text-muted-foreground">{t("setup.unknown")}</p>
        ) : state === null ? (
          <Skeleton className="h-4 w-full max-w-sm" />
        ) : (
          <>
            <p className="text-muted-foreground">{status}</p>
            {action ? <div>{action}</div> : null}
          </>
        )}
      </div>
    </li>
  );
}
