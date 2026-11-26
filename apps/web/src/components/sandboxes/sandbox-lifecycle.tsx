import { type QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
import { Button } from "@wssp/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { toast } from "@wssp/ui/components/sileo";
import { type ReactNode, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { InlineRetry } from "@/components/inline-retry";
import { OffloadPolicyText } from "@/components/sandboxes/sandbox-disk";
import { LifetimeFields, type SandboxView } from "@/components/sandboxes/sandbox-parts";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  hasStoredCopy,
  IntentKeys,
  KEEP_LIFETIME,
  type LifetimeLimit,
  lifetimeMs,
  renewalInput,
  type SandboxProblem,
  sandboxProblem,
  startLeaseInput,
} from "@/lib/sandbox-rules";
import {
  finiteDeadline,
  formatClock,
  renewDefaultMinutes,
  renewPreview,
} from "@/lib/sandbox-status";
import { orpc } from "@/utils/orpc";

/**
 * Lifecycle requests of the sandbox detail page (C47) and their dialogs:
 * stop, start/restore (and the creator-key override), reconnect, renew and
 * destroy. Every action is a request: the page shows the server's answer and
 * then whatever the next read reports, never an assumed state.
 */

export type LifecycleDialog =
  | "stop"
  | "startCold"
  | "restoreOverride"
  | "reconnectWarm"
  | "destroy"
  | "renew";

/** Problems after which the same request cannot succeed: the next click gets a new key. */
const DEFINITE: ReadonlySet<SandboxProblem> = new Set([
  "notFound",
  "stateChanged",
  "keyReused",
  "hostCapacity",
  "sizeInvalid",
  "diskBelowImage",
  "sizeUnsupported",
  "sizeMismatch",
  "hostUnavailable",
  "hostDraining",
  "restoreNoAllowedHost",
  "diskUnavailable",
  "hostDeleting",
  "templateMissing",
  "hostNoEgress",
  "egressGuardUnavailable",
  "openEgressNotPermitted",
  "labels",
  "invalid",
  "forbidden",
]);

function invalidateSandboxes(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
}

/** The lifecycle mutations, the open dialog and the last problem, for one sandbox. */
export function useSandboxLifecycle(sandbox: SandboxView, lang: string) {
  const { t, i18n } = useTranslation(["sandboxes"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const intents = useRef(new IntentKeys());
  const [open, setOpen] = useState<LifecycleDialog | null>(null);
  const [problem, setProblem] = useState<SandboxProblem | null>(null);
  // The destroy confirmation types the name shown when the dialog opened (F8):
  // a rename refetched while it is open never changes the token under the user.
  const [destroyToken, setDestroyToken] = useState(sandbox.name);
  const offloaded = sandbox.state === "OFFLOADED";

  const handlers = (done: () => string) => ({
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: () => {
      intents.current.settle();
      setOpen(null);
      toast.success(done());
    },
    onError: (error: unknown) => {
      setOpen(null);
      if (redirect(error)) return;
      const next = sandboxProblem(error);
      setProblem(next);
      if (DEFINITE.has(next)) intents.current.settle();
    },
    onSettled: () => invalidateSandboxes(queryClient),
  });
  const stop = useMutation({
    ...orpc.sandboxes.stopSandbox.mutationOptions(),
    ...handlers(() => t("sandboxes:stop.done")),
  });
  const reconnect = useMutation({
    ...orpc.sandboxes.reconnectSandbox.mutationOptions(),
    ...handlers(() => t("sandboxes:reconnect.done")),
  });
  const start = useMutation({
    ...orpc.sandboxes.reconnectSandbox.mutationOptions(),
    ...handlers(() => t(offloaded ? "sandboxes:start.restoreDone" : "sandboxes:start.done")),
  });
  const destroy = useMutation({
    ...orpc.sandboxes.killSandbox.mutationOptions(),
    ...handlers(() => t("sandboxes:destroy.done")),
  });
  // The renewal's toast names the new end: counted from acceptance, so "now".
  const renewedFor = useRef(0);
  // The last renewal sent. While its intent is still held (the outcome is
  // uncertain), reopening Renew starts from this choice, so a retry replays
  // that request instead of a recomputed default with a new key.
  const renewSent = useRef<{ sandboxId: string; minutes: string } | null>(null);
  const renew = useMutation({
    ...orpc.sandboxes.setSandboxTimeout.mutationOptions(),
    ...handlers(() =>
      renewedFor.current === 0
        ? t("sandboxes:renew.doneUnlimited")
        : t(
            sandbox.leaseExpireAction === "DESTROY"
              ? "sandboxes:renew.doneDestroy"
              : "sandboxes:renew.doneStop",
            {
              time: formatClock(Date.now() + renewedFor.current, i18n.language, Date.now()),
            },
          ),
    ),
  });
  // Re-queue the cleanup of a failed restore.
  const retryCleanup = useMutation({
    ...orpc.sandboxes.retryCleanup.mutationOptions(),
    ...handlers(() => t("sandboxes:retryCleanup.done")),
  });
  const pending =
    stop.isPending ||
    reconnect.isPending ||
    start.isPending ||
    destroy.isPending ||
    renew.isPending ||
    retryCleanup.isPending;
  // An intent is kept only while its outcome is uncertain (success and every
  // definite refusal settle it), so a retry must replay it even though the
  // refetch after a lost response shows the generation or lease revision that
  // request itself produced. Binding the key to those would mint a second
  // request instead. The sandbox ID stays in it: this component survives
  // navigation to another cached sandbox, and A's intent must never replay on B.
  const signature = (body: unknown) => JSON.stringify({ sandboxId: sandbox.id, body });

  return {
    open,
    setOpen,
    problem,
    pending,
    intents,
    signature,
    destroyToken,
    openDestroy: () => {
      setDestroyToken(sandbox.name);
      setOpen("destroy");
    },
    mutations: { stop, reconnect, start, destroy, renew, retryCleanup },
    renewedFor,
    renewSent,
  };
}

export type SandboxLifecycle = ReturnType<typeof useSandboxLifecycle>;

const ALERT_WIDTH =
  "max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!";
const DIALOG_CLASS = "sm:max-w-md";

export function SandboxLifecycleDialogs({
  sandbox,
  lang,
  lifecycle,
  waiting,
}: {
  sandbox: SandboxView;
  lang: string;
  lifecycle: SandboxLifecycle;
  waiting: boolean;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const { open, setOpen, problem, intents, signature, mutations } = lifecycle;
  const { stop, reconnect, start, destroy } = mutations;
  const limits = useQuery({
    ...orpc.sandboxes.getLimits.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [limits.error]);
  // This sandbox's own lease path (deployment, host, pool and membership),
  // read for display; the server re-checks it under its locks.
  const lifetimeLimit: LifetimeLimit = {
    maxTimeoutMs: sandbox.leaseLimit.finiteMaxMs,
    allowUnlimited: sandbox.leaseLimit.unlimited,
  };
  // Start/Restore keeps the sandbox's remembered lease unless the user picks
  // one. The pick belongs to the sandbox it was made on: this component
  // survives navigation to another cached sandbox, which starts at "keep".
  const [startChoice, setStartChoice] = useState({ sandboxId: sandbox.id, minutes: KEEP_LIFETIME });
  const startMinutes = startChoice.sandboxId === sandbox.id ? startChoice.minutes : KEEP_LIFETIME;
  const setStartMinutes = (minutes: string) => setStartChoice({ sandboxId: sandbox.id, minutes });
  const onExpire = sandbox.leaseExpireAction === "DESTROY" ? "destroy" : "stop";
  const offloaded = sandbox.state === "OFFLOADED";
  const startLease = startLeaseInput(startMinutes, lifetimeLimit);
  const limitsRetry = limits.isError ? (
    <InlineRetry
      message={t("sandboxes:lifetime.limitsFailed")}
      onRetry={() => void limits.refetch()}
    />
  ) : null;

  return (
    <>
      <AlertDialog open={open === "stop"} onOpenChange={(next) => setOpen(next ? "stop" : null)}>
        <AlertDialogContent className={ALERT_WIDTH}>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("sandboxes:stop.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t(
                ["REQUESTED", "SCHEDULED", "PROVISIONING"].includes(sandbox.state)
                  ? "sandboxes:stop.bootDescription"
                  : "sandboxes:stop.description",
              )}
            </AlertDialogDescription>
            {sandbox.disk && sandbox.disk.eligibility !== "never" ? (
              <p data-stop-offload-policy="" className="text-sm text-muted-foreground">
                {t("sandboxes:stop.offloadPolicy")}{" "}
                <OffloadPolicyText policy={sandbox.disk.offloadPolicy} />
              </p>
            ) : null}
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="min-h-[44px] w-full sm:w-auto"
              disabled={stop.isPending}
              onClick={() =>
                stop.mutate(
                  intents.current.for("stop", signature("stop"), (idempotencyKey) => ({
                    id: sandbox.id,
                    idempotencyKey,
                  })),
                )
              }
            >
              {stop.isPending ? t("sandboxes:stop.pending") : t("sandboxes:stop.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={open === "reconnectWarm"}
        onOpenChange={(next) => setOpen(next ? "reconnectWarm" : null)}
      >
        <AlertDialogContent className={ALERT_WIDTH}>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("sandboxes:reconnect.title")}</AlertDialogTitle>
            <AlertDialogDescription>{t("sandboxes:reconnect.description")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              data-reconnect-confirm=""
              className="min-h-[44px] w-full sm:w-auto"
              disabled={reconnect.isPending}
              onClick={() =>
                reconnect.mutate(
                  intents.current.for("reconnect", signature("warm"), (idempotencyKey) => ({
                    id: sandbox.id,
                    mode: "warm" as const,
                    idempotencyKey,
                  })),
                )
              }
            >
              {reconnect.isPending
                ? t("sandboxes:reconnect.pending")
                : t("sandboxes:reconnect.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <Dialog
        open={open === "startCold"}
        onOpenChange={(next) => setOpen(next ? "startCold" : null)}
      >
        <DialogContent closeLabel={t("common:actions.close")} className={DIALOG_CLASS}>
          <DialogHeader>
            <DialogTitle>
              {t(offloaded ? "sandboxes:start.restoreTitle" : "sandboxes:start.title")}
            </DialogTitle>
            <DialogDescription>
              {t(offloaded ? "sandboxes:start.restoreDescription" : "sandboxes:start.description")}
            </DialogDescription>
          </DialogHeader>
          {limitsRetry}
          <LifetimeFields
            maxTimeoutMs={lifetimeLimit.maxTimeoutMs}
            allowUnlimited={lifetimeLimit.allowUnlimited}
            minutes={startMinutes}
            onMinutes={setStartMinutes}
            onExpire={onExpire}
            keepTimeoutMs={sandbox.rememberedLeaseTimeoutMs}
            disabled={start.isPending}
          />
          <div className="flex flex-wrap justify-end gap-2">
            <Button type="button" variant="outline" size="touch" onClick={() => setOpen(null)}>
              {t("common:actions.cancel")}
            </Button>
            <Button
              type="button"
              size="touch"
              disabled={start.isPending || (startLease === null && problem !== "generic")}
              onClick={() =>
                start.mutate(
                  intents.current.for(
                    "start",
                    signature({ minutes: startMinutes, onExpire }),
                    (idempotencyKey) => ({
                      id: sandbox.id,
                      mode: "cold" as const,
                      ...(startLease ?? {}),
                      idempotencyKey,
                    }),
                  ),
                )
              }
            >
              {start.isPending
                ? t(offloaded ? "sandboxes:start.restorePending" : "sandboxes:start.pending")
                : t(offloaded ? "sandboxes:start.restoreConfirm" : "sandboxes:start.confirm")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={open === "restoreOverride"}
        onOpenChange={(next) => setOpen(next ? "restoreOverride" : null)}
      >
        <AlertDialogContent className={ALERT_WIDTH}>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("sandboxes:restoreOverride.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("sandboxes:restoreOverride.description")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              data-restore-override-confirm=""
              className="min-h-[44px] w-full sm:w-auto"
              disabled={start.isPending}
              onClick={() =>
                start.mutate(
                  intents.current.for(
                    "restoreOverride",
                    signature({ minutes: startMinutes, onExpire, override: true }),
                    (idempotencyKey) => ({
                      id: sandbox.id,
                      mode: "cold" as const,
                      ...(startLease ?? {}),
                      overrideCreatorAllowlist: true,
                      idempotencyKey,
                    }),
                  ),
                )
              }
            >
              {start.isPending
                ? t("sandboxes:restoreOverride.pending")
                : t("sandboxes:restoreOverride.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {open === "renew" ? (
        <RenewDialog
          sandbox={sandbox}
          lifecycle={lifecycle}
          lifetimeLimit={lifetimeLimit}
          limitsRetry={limitsRetry}
        />
      ) : null}

      <ConfirmDeleteDialog
        open={open === "destroy"}
        onOpenChange={(next) => setOpen(next ? "destroy" : null)}
        title={t(waiting ? "sandboxes:destroy.waitingTitle" : "sandboxes:destroy.title")}
        description={
          <>
            {t(
              waiting
                ? "sandboxes:destroy.waitingDescription"
                : sandbox.state === "STOPPING"
                  ? "sandboxes:destroy.recoveryDescription"
                  : "sandboxes:destroy.description",
            )}
            {hasStoredCopy(sandbox.disk) ? (
              <span data-destroy-stored-copy="" className="mt-2 block">
                {t("sandboxes:destroy.storedCopy")}
              </span>
            ) : null}
          </>
        }
        confirmToken={lifecycle.destroyToken}
        typePrompt={t("sandboxes:destroy.prompt", { name: lifecycle.destroyToken })}
        confirmLabel={t(waiting ? "sandboxes:destroy.waitingConfirm" : "sandboxes:destroy.confirm")}
        pendingLabel={t("sandboxes:destroy.pending")}
        isPending={destroy.isPending}
        onConfirm={() =>
          destroy.mutate(
            intents.current.for(
              "destroy",
              signature({
                action: "destroy",
                recoveryOperationId:
                  sandbox.state === "STOPPING" ? sandbox.lastLifecycleOperation?.id : null,
              }),
              (idempotencyKey) => ({ id: sandbox.id, idempotencyKey }),
            ),
          )
        }
      />
    </>
  );
}

/**
 * Renew (design review #2): starts at the current lifetime or the next step
 * up (never shorter than what is left), shows "Now → New", and asks again
 * before a choice that ends the lifetime earlier. Mounted only while open,
 * so every opening starts from the sandbox's current lease, except after a
 * renewal whose outcome is uncertain: then it starts from that renewal's
 * choice, and submitting replays it with the same key.
 */
function RenewDialog({
  sandbox,
  lifecycle,
  lifetimeLimit,
  limitsRetry,
}: {
  sandbox: SandboxView;
  lifecycle: SandboxLifecycle;
  lifetimeLimit: LifetimeLimit;
  limitsRetry: ReactNode;
}) {
  const { t, i18n } = useTranslation(["sandboxes", "common"]);
  const locale = i18n.language;
  const { setOpen, problem, intents, signature, mutations, renewedFor, renewSent } = lifecycle;
  const { renew } = mutations;
  const onExpire = sandbox.leaseExpireAction === "DESTROY" ? "destroy" : "stop";
  const [opened] = useState(() => Date.now());
  const current = finiteDeadline(sandbox.leaseExpiresAt);
  const [minutes, setMinutes] = useState(() => {
    const sent = renewSent.current;
    if (
      sent?.sandboxId === sandbox.id &&
      intents.current.holds("renew", signature({ minutes: sent.minutes, onExpire }))
    )
      return sent.minutes;
    return renewDefaultMinutes({
      ...lifetimeLimit,
      remainingMs: current === null ? null : Math.max(0, current - opened),
      rememberedMs: sandbox.rememberedLeaseTimeoutMs || null,
    });
  });
  const [confirming, setConfirming] = useState(false);
  const now = Date.now();
  const timeoutMs = lifetimeMs(minutes, lifetimeLimit);
  const preview = renewPreview(minutes, current, now);
  const term = (deadline: number | null) =>
    deadline === null
      ? t("sandboxes:renew.termUnlimited")
      : t(onExpire === "destroy" ? "sandboxes:renew.termDestroy" : "sandboxes:renew.termStop", {
          time: formatClock(deadline, locale, now),
        });
  const submit = () => {
    renewedFor.current = timeoutMs ?? 0;
    renewSent.current = { sandboxId: sandbox.id, minutes };
    renew.mutate(
      intents.current.for("renew", signature({ minutes, onExpire }), (idempotencyKey) =>
        renewalInput(sandbox.id, minutes, idempotencyKey, lifetimeLimit),
      ),
    );
  };
  const disabled = renew.isPending || (timeoutMs === null && problem !== "generic");
  return (
    <Dialog open onOpenChange={(next) => (next ? undefined : setOpen(null))}>
      <DialogContent closeLabel={t("common:actions.close")} className={DIALOG_CLASS}>
        <DialogHeader>
          <DialogTitle>
            {t(confirming ? "sandboxes:renew.shortenTitle" : "sandboxes:renew.title")}
          </DialogTitle>
          <DialogDescription>
            {confirming && preview
              ? t("sandboxes:renew.shortenDescription", {
                  from: term(current),
                  to: term(preview.newDeadline),
                })
              : t("sandboxes:renew.description")}
          </DialogDescription>
        </DialogHeader>
        {confirming ? null : (
          <>
            {limitsRetry}
            <LifetimeFields
              maxTimeoutMs={lifetimeLimit.maxTimeoutMs}
              allowUnlimited={lifetimeLimit.allowUnlimited}
              minutes={minutes}
              onMinutes={setMinutes}
              onExpire={onExpire}
              disabled={renew.isPending}
            />
            <dl data-renew-preview="" className="grid min-w-0 gap-1 text-sm">
              <div className="flex min-w-0 flex-wrap gap-x-2">
                <dt className="text-muted-foreground">{t("sandboxes:renew.now")}</dt>
                <dd data-renew-now="">{term(current)}</dd>
              </div>
              <div className="flex min-w-0 flex-wrap gap-x-2">
                <dt className="text-muted-foreground">{t("sandboxes:renew.next")}</dt>
                <dd
                  data-renew-next=""
                  className={preview?.shortens ? "font-medium text-destructive" : "font-medium"}
                >
                  {preview ? term(preview.newDeadline) : "—"}
                </dd>
              </div>
            </dl>
          </>
        )}
        <div className="flex flex-wrap justify-end gap-2">
          <Button
            type="button"
            variant="outline"
            size="touch"
            onClick={() => (confirming ? setConfirming(false) : setOpen(null))}
          >
            {confirming ? t("common:actions.back") : t("common:actions.cancel")}
          </Button>
          {confirming ? (
            <Button
              type="button"
              size="touch"
              variant="destructive"
              data-renew-shorten-confirm=""
              disabled={disabled}
              onClick={submit}
            >
              {renew.isPending ? t("sandboxes:renew.pending") : t("sandboxes:renew.shortenConfirm")}
            </Button>
          ) : (
            <Button
              type="button"
              size="touch"
              disabled={disabled}
              onClick={() => (preview?.shortens ? setConfirming(true) : submit())}
            >
              {renew.isPending ? t("sandboxes:renew.pending") : t("sandboxes:renew.submit")}
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
