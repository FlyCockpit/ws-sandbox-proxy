import { type QueryClient, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@wssp/ui/components/alert-dialog";
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { toast } from "@wssp/ui/components/sileo";
import { useCopyToClipboard } from "@wssp/ui/hooks/use-copy-to-clipboard";
import { cn } from "@wssp/ui/lib/utils";
import { Check, Copy, Eye, EyeOff } from "lucide-react";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";
import { FormSelect } from "@/components/form-select";
import { ResourceIdentity } from "@/components/resource-identity";
import type { Orphan } from "@/hooks/use-one-time-secret";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import {
  type CredentialProblem,
  credentialProblem,
  EXPIRY_PRESETS,
  type ExpiryPreset,
  isExpiryPreset,
} from "@/lib/credential-rules";
import { dateTimeTitle } from "@/lib/format-date-time";
import { type HostConnectionState, hostConnectionState, toMs } from "@/lib/host-status";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * Shared pieces of the Host credentials and SDK keys pages (C45). The only
 * component that ever receives a raw secret is {@link OneTimeSecretPanel}; it
 * masks it by default and never logs it.
 */

const MASK = "•".repeat(24);

export function OneTimeSecretPanel({
  secret,
  label,
  onDone,
  children,
}: {
  secret: string;
  label: string;
  onDone: () => void;
  children?: ReactNode;
}) {
  const { t } = useTranslation(["credentials", "common"]);
  const [visible, setVisible] = useState(false);
  const { copied, copy } = useCopyToClipboard();
  const [copyFailed, setCopyFailed] = useState(false);

  return (
    <section
      aria-label={label}
      data-one-time-secret=""
      className="flex min-w-0 flex-col gap-3 rounded-md border bg-muted/40 p-3"
    >
      <p className="text-sm font-medium">{label}</p>
      <p role="status" className="text-sm text-muted-foreground">
        {t("credentials:reveal.onceWarning")}
      </p>
      <div className="flex min-w-0 items-center gap-2">
        <code
          data-secret-value=""
          className="min-w-0 flex-1 overflow-x-auto overscroll-x-contain whitespace-nowrap rounded-md border bg-background px-2.5 py-2 font-mono text-xs"
        >
          {visible ? secret : MASK}
        </code>
        <Button
          type="button"
          variant="outline"
          size="icon-touch"
          aria-pressed={visible}
          aria-label={visible ? t("credentials:reveal.hide") : t("credentials:reveal.show")}
          onClick={() => setVisible((current) => !current)}
        >
          {visible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
        </Button>
        <Button
          type="button"
          variant="outline"
          size="icon-touch"
          aria-label={t("credentials:reveal.copy")}
          onClick={async () => setCopyFailed(!(await copy(secret)))}
        >
          {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
        </Button>
      </div>
      {copied ? (
        <p role="status" className="text-xs text-muted-foreground">
          {t("credentials:reveal.copied")}
        </p>
      ) : null}
      {copyFailed ? (
        <p role="alert" className="text-xs text-destructive">
          {t("credentials:reveal.copyFailed")}
        </p>
      ) : null}
      {children}
      <Button type="button" size="touch" onClick={onDone}>
        {t("credentials:reveal.done")}
      </Button>
    </section>
  );
}

/**
 * Credentials minted after their dialog was cancelled whose automatic revoke
 * failed. Nobody saw their secret, but they stay usable until revoked, so the
 * page says so and offers the revoke again.
 */
export function OrphanedCredentialsAlert({
  orphans,
  onRetry,
}: {
  orphans: readonly Orphan[];
  onRetry: (id: string) => Promise<boolean>;
}) {
  const { t } = useTranslation(["credentials"]);
  const [busy, setBusy] = useState<ReadonlySet<string>>(new Set());
  if (orphans.length === 0) return null;
  const retry = async (id: string) => {
    setBusy((current) => new Set(current).add(id));
    try {
      await onRetry(id);
    } finally {
      setBusy((current) => {
        const next = new Set(current);
        next.delete(id);
        return next;
      });
    }
  };
  return (
    <ul
      role="alert"
      data-orphaned-credentials=""
      className="flex min-w-0 flex-col gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm"
    >
      {orphans.map((orphan) => (
        <li
          key={orphan.id}
          data-orphan-id={orphan.id}
          className="flex min-w-0 flex-wrap items-center gap-2"
        >
          <span className="min-w-0 flex-1 text-destructive">
            {t("credentials:orphan.failed", { label: orphan.label })}
          </span>
          <Button
            type="button"
            variant="outline"
            size="touch"
            disabled={busy.has(orphan.id)}
            onClick={() => void retry(orphan.id)}
          >
            {busy.has(orphan.id) ? t("credentials:revoke.pending") : t("credentials:orphan.retry")}
          </Button>
        </li>
      ))}
    </ul>
  );
}

/** Plain confirmation for a revoke (no typed token: a revoke is not a data deletion). */
export function RevokeCredentialDialog({
  open,
  onOpenChange,
  title,
  description,
  isPending,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  isPending: boolean;
  onConfirm: () => void;
}) {
  const { t } = useTranslation(["credentials", "common"]);
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter className="sm:flex-wrap">
          <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
            {t("common:actions.cancel")}
          </AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            className="min-h-[44px] w-full sm:w-auto"
            disabled={isPending}
            onClick={onConfirm}
          >
            {isPending ? t("credentials:revoke.pending") : t("credentials:revoke.confirm")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

type Timestamp = Date | string | null;

/** Created / last used / expires, locale-relative. */
export function CredentialDates({
  createdAt,
  lastUsedAt,
  expiresAt,
  lastConnectAt,
  now,
  locale,
}: {
  createdAt: Timestamp;
  lastUsedAt: Timestamp;
  expiresAt?: Timestamp;
  /** The newest CLI connection (`sandboxes:connect`); omitted, the row is not shown. */
  lastConnectAt?: Timestamp;
  now: number;
  locale: string;
}) {
  const { t } = useTranslation(["credentials"]);
  const created = toMs(createdAt);
  const used = toMs(lastUsedAt);
  const expires = expiresAt === undefined ? undefined : toMs(expiresAt);
  const connected = lastConnectAt === undefined ? undefined : toMs(lastConnectAt);
  return (
    <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-3">
      <div className="min-w-0">
        <dt className="text-xs text-muted-foreground">{t("credentials:dates.created")}</dt>
        <dd title={dateTimeTitle(created, locale)}>
          {created == null ? "—" : formatRelativeTime(created, locale, now)}
        </dd>
      </div>
      <div className="min-w-0">
        <dt className="text-xs text-muted-foreground">{t("credentials:dates.lastUsed")}</dt>
        <dd data-last-used="" title={dateTimeTitle(used, locale)}>
          {used == null ? t("credentials:dates.neverUsed") : formatRelativeTime(used, locale, now)}
        </dd>
      </div>
      {expires === undefined ? null : (
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t("credentials:dates.expires")}</dt>
          <dd data-expiry="" title={dateTimeTitle(expires, locale)}>
            {expires == null
              ? t("credentials:dates.noExpiry")
              : expires <= now
                ? t("credentials:dates.expired")
                : formatRelativeTime(expires, locale, now)}
          </dd>
        </div>
      )}
      {connected === undefined ? null : (
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">{t("credentials:dates.lastConnect")}</dt>
          <dd data-last-connect="" title={dateTimeTitle(connected, locale)}>
            {/* No retained record: rows are purged after the server-side
                CONNECT_SESSION_RETENTION_DAYS (90, literal in the string). */}
            {connected == null
              ? t("credentials:dates.noRecentConnect")
              : formatRelativeTime(connected, locale, now)}
          </dd>
        </div>
      )}
    </dl>
  );
}

const STATE_TONE: Record<HostConnectionState, string> = {
  ready: "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400",
  stale: "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
  quarantined: "border-destructive/40 bg-destructive/10 text-destructive",
  reconnecting: "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
  offline: "border-border bg-muted text-muted-foreground",
  never: "border-border bg-muted text-muted-foreground",
  revoked: "border-destructive/40 bg-destructive/10 text-destructive",
  deleting: "border-destructive/40 bg-destructive/10 text-destructive",
};

export type CredentialHost = {
  id: string;
  slug: string;
  label: string;
  status: "DISCONNECTED" | "CONNECTED" | "STALE" | "REVOKED";
  lastConnectedAt: Timestamp;
  lastHeartbeatAt: Timestamp;
  deletionRequestedAt: Timestamp;
};

/** The credential's host and its connection state (same rule as the Hosts page). */
export function CredentialHostLine({ host, now }: { host: CredentialHost | null; now: number }) {
  const { t } = useTranslation(["credentials", "hosts"]);
  if (!host) {
    return <p className="text-sm text-muted-foreground">{t("credentials:host.none")}</p>;
  }
  const state = hostConnectionState(host, now);
  return (
    <p className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
      <span className="min-w-0 truncate">
        <ResourceIdentity label={host.label} slug={host.slug} />
      </span>
      <Badge
        data-host-status={state}
        className={cn(
          "inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium",
          STATE_TONE[state],
        )}
      >
        {t(`hosts:status.${state}`)}
      </Badge>
    </p>
  );
}

/** Revoke mutation shared by both lists: confirmation, problem, 2FA redirect, refetch. */
export function useRevoke(
  lang: string,
  revoke: (id: string) => Promise<unknown>,
  doneMessage: string,
  invalidate: (queryClient: QueryClient) => void,
) {
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [confirming, setConfirming] = useState(false);
  const [problem, setProblem] = useState<CredentialProblem | null>(null);
  const mutation = useMutation({
    mutationFn: revoke,
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: () => {
      setConfirming(false);
      toast.success(doneMessage);
    },
    onError: (error) => {
      setConfirming(false);
      if (!redirect(error)) setProblem(credentialProblem(error));
    },
    onSettled: () => invalidate(queryClient),
  });
  return { mutation, confirming, setConfirming, problem };
}

export function ExpirySelect({
  id,
  value,
  onChange,
  presets = EXPIRY_PRESETS,
}: {
  presets?: readonly ExpiryPreset[];
  id: string;
  value: ExpiryPreset;
  onChange: (value: ExpiryPreset) => void;
}) {
  const { t } = useTranslation(["credentials"]);
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <Label htmlFor={id}>{t("credentials:form.expiry")}</Label>
      <FormSelect
        id={id}
        value={value}
        onValueChange={(value) => {
          if (isExpiryPreset(value)) onChange(value);
        }}
      >
        {presets.map((preset) => (
          <SelectItem key={preset} value={preset}>
            {t(`credentials:expiry.${preset}`)}
          </SelectItem>
        ))}
      </FormSelect>
    </div>
  );
}
