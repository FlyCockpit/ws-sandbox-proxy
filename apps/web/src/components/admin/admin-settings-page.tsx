import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import { toast } from "@wssp/ui/components/sileo";
import { Skeleton } from "@wssp/ui/components/skeleton";
import { TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { Archive, Gauge, Shield } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { InlineRetry } from "@/components/inline-retry";
import { PageHeader, PageShell } from "@/components/page-shell";
import { type AdminProblem, adminProblem, adminProblemKey } from "@/lib/admin-errors";
import { formatBytes } from "@/lib/format-bytes";
import { orpc } from "@/utils/orpc";

import { AdminConfirmDialog } from "./admin-confirm-dialog";

type AdminSettings = Awaited<ReturnType<AppRouterClient["settings"]["adminGet"]>>;
type PolicyKey = "signupEnabled" | "force2faInternalUsers" | "force2faPublicUsers";
type PolicyChange = { key: PolicyKey; next: boolean };

const POLICY_KEYS: readonly PolicyKey[] = [
  "force2faInternalUsers",
  "force2faPublicUsers",
  "signupEnabled",
];

/** A change that removes a safeguard (weaker security or wider access). */
export function isWeakeningChange(change: PolicyChange): boolean {
  return change.key === "signupEnabled" ? change.next : !change.next;
}

/**
 * Deployment policy: sign-up, and the two forced-2FA requirements, shown as
 * the server's effective values (`settings.adminGet`), never as local state.
 * Every change is confirmed with its consequences first; the page re-reads
 * the server after success or refusal, so it always shows the policy in force.
 * Limits are read-only: they come from deployment configuration.
 */
export function AdminSettingsPage({ lang, adminHas2FA }: { lang: string; adminHas2FA: boolean }) {
  const { t } = useTranslation(["admin", "common"]);
  const queryClient = useQueryClient();
  const settings = useQuery({
    ...orpc.settings.adminGet.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const [change, setChange] = useState<PolicyChange | null>(null);
  const [problem, setProblem] = useState<AdminProblem | null>(null);

  const refresh = () => {
    // Everything cached that renders these policies: this page, the shell nav
    // mirror and admin nudge (`settings.getAll`), and the public sign-up flag.
    // The `_auth` 2FA guard re-reads the settings on every navigation.
    void queryClient.invalidateQueries({ queryKey: orpc.settings.key() });
    void queryClient.invalidateQueries({ queryKey: orpc.appConfig.key() });
  };
  const update = useMutation({
    ...orpc.settings.update.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: (_result, variables) => {
      toast.success(
        t(`admin:settings.toast.${variables.key}.${variables.value === "true" ? "on" : "off"}`),
      );
      setChange(null);
      refresh();
    },
    onError: (error: Error) => {
      setProblem(adminProblem(error));
      refresh();
    },
  });

  return (
    <PageShell width="narrow">
      <PageHeader title={t("admin:settings.title")} description={t("admin:settings.description")} />

      {settings.isPending ? (
        <SettingsSkeleton />
      ) : settings.isError ? (
        <Card>
          <CardContent>
            <InlineRetry
              className="py-12"
              message={t("admin:settings.loadFailed")}
              onRetry={() => void settings.refetch()}
            />
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield aria-hidden className="size-5" />
                {t("admin:settings.securityTitle")}
              </CardTitle>
              <CardDescription>{t("admin:settings.securityDescription")}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {!adminHas2FA ? (
                <p className="text-sm text-destructive">
                  {t("admin:settings.force2faAdminWarning")}{" "}
                  <Link
                    to="/$lang/settings/security"
                    params={{ lang }}
                    className="font-medium underline underline-offset-2"
                  >
                    {t("admin:settings.securityLink")}
                  </Link>
                </p>
              ) : null}
              {POLICY_KEYS.map((key) => (
                <PolicyRow
                  key={key}
                  policy={key}
                  enabled={settings.data[key]}
                  // Requiring 2FA of others needs it on your own account first
                  // (the server refuses too); turning a requirement off never does.
                  enableBlocked={key !== "signupEnabled" && !adminHas2FA}
                  isUpdating={update.isPending}
                  onChange={(next) => {
                    setProblem(null);
                    setChange({ key, next });
                  }}
                />
              ))}
            </CardContent>
          </Card>
          <OffloadGraceCard seconds={settings.data.offloadConsumedGraceSeconds} onSaved={refresh} />
          <LimitsCard limits={settings.data.limits} />
          <p className="text-sm text-muted-foreground">
            {t("admin:settings.recoveryNote")}{" "}
            <Link
              to="/$lang/settings/security"
              params={{ lang }}
              className="font-medium text-foreground underline underline-offset-2"
            >
              {t("admin:settings.securityLink")}
            </Link>
          </p>
        </>
      )}

      {change ? (
        <AdminConfirmDialog
          open
          onOpenChange={(open) => {
            if (!open) {
              setChange(null);
              setProblem(null);
            }
          }}
          title={t(`admin:settings.confirm.${change.key}.${change.next ? "on" : "off"}Title`)}
          description={t(
            `admin:settings.confirm.${change.key}.${change.next ? "on" : "off"}Description`,
          )}
          confirmLabel={t(change.next ? "admin:settings.enable" : "admin:settings.disable")}
          pendingLabel={t("admin:settings.updating")}
          destructive={isWeakeningChange(change)}
          isPending={update.isPending}
          problem={problem ? t(`admin:${adminProblemKey(problem)}`) : null}
          onConfirm={() =>
            update.mutate({ key: change.key, value: change.next ? "true" : "false" })
          }
        />
      ) : null}
    </PageShell>
  );
}

function PolicyRow({
  policy,
  enabled,
  enableBlocked,
  isUpdating,
  onChange,
}: {
  policy: PolicyKey;
  enabled: boolean;
  enableBlocked: boolean;
  isUpdating: boolean;
  onChange: (next: boolean) => void;
}) {
  const { t } = useTranslation("admin");
  return (
    <div
      data-policy={policy}
      data-enabled={enabled}
      className="flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-start sm:justify-between"
    >
      <div className="min-w-0 space-y-1">
        <p className="font-medium">{t(`settings.policies.${policy}.title`)}</p>
        <p className="text-sm text-muted-foreground">
          {t(`settings.policies.${policy}.description`)}
        </p>
        <p
          className={cn(
            "text-sm font-medium",
            enabled ? "text-foreground" : "text-muted-foreground",
          )}
        >
          {t(`settings.policies.${policy}.${enabled ? "on" : "off"}`)}
        </p>
      </div>
      <Button
        variant={enabled ? "outline" : "default"}
        size="sm"
        className="min-h-[44px] shrink-0 self-start"
        disabled={isUpdating || (!enabled && enableBlocked)}
        onClick={() => onChange(!enabled)}
      >
        {enabled ? t("settings.disable") : t("settings.enable")}
      </Button>
    </div>
  );
}

/** 0 to 7 days (validated again on the server, on write and read). */
const CONSUMED_GRACE_MAX_SECONDS = 604_800;
const CONSUMED_GRACE_KEY = "sandbox.offload.consumedGraceSeconds";

/**
 * How long a started sandbox's offloaded copy is kept before it is deleted
 * (a salvage window only; never restorable). Deployment-wide, admin only.
 */
function OffloadGraceCard({ seconds, onSaved }: { seconds: number; onSaved: () => void }) {
  const { t } = useTranslation("admin");
  const [problem, setProblem] = useState<AdminProblem | null>(null);
  const save = useMutation({
    ...orpc.settings.update.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onError: (error: Error) => setProblem(adminProblem(error)),
  });
  const form = useForm({
    defaultValues: { grace: String(seconds) },
    validators: {
      onSubmit: z.object({
        grace: z
          .string()
          .refine(
            (value) =>
              /^(0|[1-9][0-9]*)$/.test(value.trim()) && Number(value) <= CONSUMED_GRACE_MAX_SECONDS,
            t("settings.offloadGrace.invalid"),
          ),
      }),
    },
    onSubmit: async ({ value }) => {
      try {
        await save.mutateAsync({ key: CONSUMED_GRACE_KEY, value: value.grace.trim() });
        toast.success(t("settings.offloadGrace.saved"));
        onSaved();
      } catch {
        // Explained inline from the typed error (see `problem`).
      }
    },
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Archive aria-hidden className="size-5" />
          {t("settings.offloadGrace.title")}
        </CardTitle>
        <CardDescription>{t("settings.offloadGrace.description")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          noValidate
          className="flex min-w-0 flex-col gap-4 sm:flex-row sm:items-end"
          onSubmit={(event) => {
            event.preventDefault();
            void form.handleSubmit();
          }}
        >
          <form.Field name="grace">
            {(field) => (
              <TextField
                field={field}
                label={t("settings.offloadGrace.label")}
                description={t("settings.offloadGrace.hint")}
                type="number"
                min={0}
                max={CONSUMED_GRACE_MAX_SECONDS}
                inputMode="numeric"
                autoComplete="off"
                inputClassName="min-h-11"
              />
            )}
          </form.Field>
          <Button type="submit" className="min-h-[44px] shrink-0" disabled={save.isPending}>
            {save.isPending ? t("settings.updating") : t("settings.offloadGrace.save")}
          </Button>
        </form>
        {problem ? (
          <p role="alert" className="mt-2 text-sm text-destructive">
            {t(adminProblemKey(problem))}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function formatDuration(ms: number, locale: string): string {
  const seconds = ms / 1000;
  const [value, unit] =
    seconds % 3600 === 0 && seconds >= 3600
      ? [seconds / 3600, "hour"]
      : seconds % 60 === 0 && seconds >= 60
        ? [seconds / 60, "minute"]
        : [seconds, "second"];
  return new Intl.NumberFormat(locale, { style: "unit", unit, unitDisplay: "long" }).format(value);
}

function LimitsCard({ limits }: { limits: AdminSettings["limits"] }) {
  const { t, i18n } = useTranslation("admin");
  const locale = i18n.language;
  const count = new Intl.NumberFormat(locale);
  const rows: { key: keyof AdminSettings["limits"]; value: string }[] = [
    {
      key: "commandPayloadMaxBytes",
      value: formatBytes(limits.commandPayloadMaxBytes, locale),
    },
    {
      key: "commandTimeoutDefaultMs",
      value: formatDuration(limits.commandTimeoutDefaultMs, locale),
    },
    { key: "commandTimeoutMaxMs", value: formatDuration(limits.commandTimeoutMaxMs, locale) },
    { key: "outputMaxBytes", value: formatBytes(limits.outputMaxBytes, locale) },
    { key: "outputRetentionMs", value: formatDuration(limits.outputRetentionMs, locale) },
    { key: "transferMaxBytes", value: formatBytes(limits.transferMaxBytes, locale) },
    { key: "transferDiskBytes", value: formatBytes(limits.transferDiskBytes, locale) },
    { key: "transferOwnerActive", value: count.format(limits.transferOwnerActive) },
    { key: "transferGlobalActive", value: count.format(limits.transferGlobalActive) },
    {
      key: "transferIdleSeconds",
      value: formatDuration(limits.transferIdleSeconds * 1000, locale),
    },
    {
      key: "transferAbsoluteSeconds",
      value: formatDuration(limits.transferAbsoluteSeconds * 1000, locale),
    },
    {
      key: "sandboxLeaseMaxMs",
      value:
        limits.sandboxLeaseMaxMs === null
          ? t("settings.unlimited")
          : formatDuration(limits.sandboxLeaseMaxMs, locale),
    },
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Gauge aria-hidden className="size-5" />
          {t("settings.limitsTitle")}
        </CardTitle>
        <CardDescription>{t("settings.limitsDescription")}</CardDescription>
      </CardHeader>
      <CardContent>
        <dl className="divide-y rounded-lg border">
          {rows.map((row) => (
            <div
              key={row.key}
              data-limit={row.key}
              className="flex flex-col gap-1 px-4 py-2 text-sm sm:flex-row sm:items-center sm:justify-between"
            >
              <dt className="text-muted-foreground">{t(`settings.limits.${row.key}`)}</dt>
              <dd className="font-medium tabular-nums">{row.value}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

function SettingsSkeleton() {
  const { t } = useTranslation("admin");
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield aria-hidden className="size-5" />
          <span className="sr-only">{t("settings.securityTitle")}</span>
          <Skeleton className="h-5 w-32" />
        </CardTitle>
        <CardDescription>
          <Skeleton className="h-4 w-64" />
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {POLICY_KEYS.map((policy) => (
          <div
            key={policy}
            className="flex items-start justify-between gap-4 rounded-lg border p-4"
          >
            <div className="flex-1 space-y-2">
              <Skeleton className="h-5 w-56" />
              <Skeleton className="h-4 w-full max-w-md" />
            </div>
            <Skeleton className="h-11 w-20" />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
