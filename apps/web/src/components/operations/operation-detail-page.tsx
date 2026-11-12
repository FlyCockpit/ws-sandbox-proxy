import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
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
import { ArrowLeft } from "lucide-react";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";
import { AdvancedDetails } from "@/components/advanced-details";
import { CopyableId, shortId } from "@/components/copyable-id";
import { EmptyState } from "@/components/empty-state";
import { InlineRetry } from "@/components/inline-retry";
import { CommandOutputView } from "@/components/operations/command-output-view";
import {
  OperationResultText,
  OperationStatePill,
  type OperationView,
} from "@/components/operations/operation-parts";
import { PageHeader } from "@/components/page-shell";
import { StatePill } from "@/components/sandboxes/sandbox-parts";
import { SkeletonList } from "@/components/skeleton-list";
import type { OutputTiming } from "@/hooks/use-command-output";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { useSensitiveAccessUnavailable } from "@/hooks/use-sensitive-access-unavailable";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { hostConnectionState, nextHostStateChangeAt } from "@/lib/host-status";
import {
  type CancelAnswer,
  type CancelProblem,
  canCancelOperation,
  cancelAnswer,
  cancelProblem,
  durationMs,
  formatDuration,
  formatTimestamp,
  isOperationPending,
  operationTone,
} from "@/lib/operation-rules";
import { isQueryAccessError } from "@/lib/query-access-error";
import { isNotFound, sandboxHostView, sandboxTitle } from "@/lib/sandbox-rules";
import { revisionLabel } from "@/lib/template-rules";
import { orpc } from "@/utils/orpc";

/**
 * One operation (C48): its server-reported status, timestamps, typed error
 * and exit code, the sandbox it ran in (a deleted sandbox stays shown as
 * deleted), and — for commands — the output, read incrementally while the
 * command runs. The status query polls fast while the operation is in
 * flight, slower while its outcome is uncertain (a host receipt can still
 * reconcile it), and rarely once final (only the host's heartbeat changes);
 * the output view follows its own completion watermark.
 *
 * Cancel is a request: the page shows the server's answer (queued work is
 * cancelled at once; running work becomes CANCEL_REQUESTED) and then waits
 * for the host's acknowledgement through the next reads. It never shows
 * CANCELLED on its own, and an operation that finished first says so.
 * Another owner's operation is a plain "not found" (the server's NOT_FOUND).
 */

export const OPERATION_PENDING_REFETCH_MS = 2_000;

export type OperationRefetchTiming = {
  /** `UNKNOWN_OUTCOME` may still be reconciled by an exact host receipt. */
  uncertainMs: number;
  /** A final receipt is immutable, but its host's heartbeat is not. */
  settledMs: number;
};

export const OPERATION_REFETCH_TIMING: OperationRefetchTiming = {
  uncertainMs: 5_000,
  // Under HOST_HEARTBEAT_STALE_AFTER_MS, so a live host never ages into "stale".
  settledMs: 15_000,
};

export function OperationDetailPage({
  lang,
  operationId,
  outputTiming,
  refetchTiming = OPERATION_REFETCH_TIMING,
}: {
  lang: string;
  operationId: string;
  /** Test-only override of the output poll cadence. */
  outputTiming?: OutputTiming;
  /** Test-only override of the settled status cadence. */
  refetchTiming?: OperationRefetchTiming;
}) {
  const { t, i18n } = useTranslation(["operations", "dashboard", "common"]);
  const query = useQuery({
    ...orpc.sandboxes.getOperationView.queryOptions({ input: { operationId } }),
    // In flight: fast. Uncertain: slower, until reconciled. Final: only for
    // the host metadata; the output view handles the watermark.
    refetchInterval: (current) => {
      const state = current.state.data?.state;
      if (state === undefined) return false;
      if (isOperationPending(state)) return OPERATION_PENDING_REFETCH_MS;
      return state === "UNKNOWN_OUTCOME" ? refetchTiming.uncertainMs : refetchTiming.settledMs;
    },
    retry: (count, error) => !isNotFound(error) && count < 1,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const now = Date.now();
  const host = query.data?.sandbox.host ?? null;
  useRerenderAt(nextHostStateChangeAt(host ? [host] : [], now));

  const back = (
    <Link
      to="/$lang/dashboard/operations"
      params={{ lang }}
      className="inline-flex min-h-11 items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft aria-hidden="true" className="size-4" />
      {t("operations:detail.back")}
    </Link>
  );

  if (query.isPending)
    return (
      <section className="flex min-w-0 flex-col gap-6">
        {back}
        <SkeletonList count={3} className="rounded-xl border" />
      </section>
    );
  if (query.data === undefined || (query.isError && isQueryAccessError(query.error)))
    return (
      <section className="flex min-w-0 flex-col gap-6">
        {back}
        {isNotFound(query.error) ? (
          <div role="status" data-operation-missing="">
            <EmptyState
              className="rounded-xl border px-4"
              title={t("operations:detail.notFoundTitle")}
              description={t("operations:detail.notFoundDescription")}
            />
          </div>
        ) : (
          <InlineRetry
            message={t("operations:detail.loadFailed")}
            onRetry={() => void query.refetch()}
          />
        )}
      </section>
    );
  return (
    <section className="flex min-w-0 max-w-full flex-col gap-6">
      {back}
      {query.isError && !isNotFound(query.error) ? (
        <InlineRetry
          message={t("operations:detail.loadFailed")}
          onRetry={() => void query.refetch()}
        />
      ) : null}
      <OperationDetail
        operation={query.data}
        lang={lang}
        locale={i18n.language}
        now={now}
        outputTiming={outputTiming}
      />
    </section>
  );
}

function OperationDetail({
  operation,
  lang,
  locale,
  now,
  outputTiming,
}: {
  operation: OperationView;
  lang: string;
  locale: string;
  now: number;
  outputTiming?: OutputTiming;
}) {
  const { t } = useTranslation(["operations", "sandboxes", "hosts", "common"]);
  const unavailable = useSensitiveAccessUnavailable();
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [confirming, setConfirming] = useState(false);
  const [answer, setAnswer] = useState<CancelAnswer | null>(null);
  const [problem, setProblem] = useState<CancelProblem | null>(null);
  const cancel = useMutation({
    ...orpc.sandboxes.cancelOperation.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      setProblem(null);
      setAnswer(null);
    },
    onSuccess: (result) => {
      setConfirming(false);
      setAnswer(cancelAnswer(result.state));
    },
    onError: (error) => {
      setConfirming(false);
      if (redirect(error)) return;
      setProblem(cancelProblem(error));
    },
    // The page's state comes from the next read, never from this answer.
    onSettled: () => void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() }),
  });

  const pending = isOperationPending(operation.state);
  const tone = operationTone(operation.state);
  const sandboxDeleted = operation.sandbox.state === "DELETED";
  const hostOffline = !sandboxDeleted && sandboxHostView(operation.sandbox.host, now) === "offline";
  const took = durationMs(operation.dispatchedAt ?? operation.createdAt, operation.completedAt);
  // Waiting for the host: the read says CANCEL_REQUESTED, or our request was
  // just answered with it and the read has not caught up. Never CANCELLED
  // until a read reports it.
  const waiting = operation.state === "CANCEL_REQUESTED" || (answer === "pending" && pending);
  // How our cancel ended, once the read has settled too (e.g. it finished first).
  const settled =
    pending || answer === null
      ? null
      : answer === "pending"
        ? cancelAnswer(operation.state)
        : answer;
  // Never dispatched: the server cancelled it from the queue, so no host was
  // involved and the copy must not claim one confirmed anything (M7-S9).
  const outcome =
    settled === "cancelled" && operation.dispatchedAt == null ? "cancelledQueued" : settled;

  return (
    <>
      <PageHeader
        title={t(`operations:kind.${operation.kind}`)}
        actions={
          canCancelOperation(operation.kind, operation.state) && !waiting ? (
            <Button
              type="button"
              size="touch"
              variant="outline"
              disabled={unavailable || cancel.isPending}
              onClick={() => {
                if (!unavailable) setConfirming(true);
              }}
            >
              {cancel.isPending ? t("operations:cancel.pending") : t("operations:cancel.action")}
            </Button>
          ) : null
        }
      />
      {unavailable && operation.kind !== "RUN_COMMAND" ? (
        <p role="status" data-sensitive-unavailable="">
          {t("operations:sensitiveAccessUnavailable")}
        </p>
      ) : null}
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <OperationStatePill state={operation.state} />
        {/* CANCEL_REQUESTED has no hint here: the cancel-waiting line below
            says it (and whether the host is offline) exactly once (M7-S8). */}
        {tone === "pending" || tone === "unknown" ? (
          <p className="text-sm text-muted-foreground">
            {t(
              operation.kind === "CREATE_SANDBOX" &&
                operation.sandbox.state === "WAITING_FOR_CAPACITY"
                ? "operations:stateHint.waitingForCapacity"
                : // A queued restore of an OFFLOADED sandbox waits for an allowed host.
                  tone === "pending" &&
                    operation.kind === "RECONNECT_SANDBOX" &&
                    operation.sandbox.state === "OFFLOADED"
                  ? "operations:stateHint.waitingForRestoreHost"
                  : operation.kind === "RUN_COMMAND" && tone === "unknown"
                    ? "operations:stateHint.commandUnknown"
                    : `operations:stateHint.${tone}`,
            )}
          </p>
        ) : null}
      </div>
      {sandboxDeleted ? (
        <p
          role="status"
          data-sandbox-deleted=""
          className="rounded-md border bg-muted/50 p-3 text-sm text-muted-foreground"
        >
          {t("operations:detail.sandboxDeleted")}
        </p>
      ) : null}
      {hostOffline && operation.sandbox.host ? (
        <p
          role="status"
          data-host-offline=""
          className="rounded-md border border-amber-600/40 bg-amber-600/10 p-3 text-sm text-amber-800 dark:text-amber-300"
        >
          {translateText(t, "operations:detail.hostOffline", {
            host: operation.sandbox.host.label,
            state: t(`hosts:status.${hostConnectionState(operation.sandbox.host, now)}`),
          })}
        </p>
      ) : null}
      {waiting ? (
        <p role="status" data-cancel-waiting="" className="text-sm">
          {t(hostOffline ? "operations:cancel.waitingOffline" : "operations:cancel.waiting")}
        </p>
      ) : null}
      {outcome ? (
        <p role="status" data-cancel-answer={outcome} className="text-sm">
          {t(`operations:cancel.answer.${outcome}`)}
        </p>
      ) : null}
      {problem ? (
        <p role="alert" data-cancel-problem={problem} className="text-sm text-destructive">
          {t(`operations:cancel.problem.${problem}`)}
        </p>
      ) : null}

      <section
        aria-labelledby="operation-overview"
        className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
      >
        <h2 id="operation-overview" className="text-sm font-medium">
          {t("operations:detail.overview")}
        </h2>
        <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
          <Field label={t("operations:detail.fields.id")}>
            <CopyableId value={operation.id} label={t("operations:detail.fields.id")} />
          </Field>
          {operation.kind === "RUN_COMMAND" ? (
            <Field label={t("operations:detail.fields.command")}>
              <span data-command-not-stored="" className="text-muted-foreground">
                {t("operations:detail.commandNotStored")}
              </span>
            </Field>
          ) : null}
          <Field label={t("operations:detail.fields.sandbox")}>
            <span className="flex min-w-0 flex-wrap items-center gap-2">
              <Link
                to="/$lang/dashboard/sandboxes/$sandboxId"
                params={{ lang, sandboxId: operation.sandbox.id }}
                className="break-all font-mono text-xs underline-offset-4 hover:underline"
              >
                {sandboxTitle(operation.sandbox)}
              </Link>
              <span data-operation-sandbox-state="">
                <StatePill state={operation.sandbox.state} />
              </span>
            </span>
          </Field>
          <Field label={t("operations:detail.fields.host")}>
            {operation.sandbox.host ? (
              <>
                {translateText(t, "sandboxes:hostLabel", {
                  label: operation.sandbox.host.label,
                  slug: operation.sandbox.host.slug,
                })}
                {" · "}
                {t(`hosts:status.${hostConnectionState(operation.sandbox.host, now)}`)}
              </>
            ) : (
              <span className="text-muted-foreground">{t("sandboxes:fields.noHost")}</span>
            )}
          </Field>
          <Field label={t("operations:detail.fields.created")}>
            {formatTimestamp(operation.createdAt, locale)}
          </Field>
          <Field label={t("operations:detail.fields.dispatched")}>
            {operation.dispatchedAt ? (
              formatTimestamp(operation.dispatchedAt, locale)
            ) : (
              <span className="text-muted-foreground">{t("operations:detail.notDispatched")}</span>
            )}
          </Field>
          <Field label={t("operations:detail.fields.completed")}>
            {operation.completedAt ? (
              formatTimestamp(operation.completedAt, locale)
            ) : (
              <span className="text-muted-foreground">{t("operations:detail.notCompleted")}</span>
            )}
          </Field>
          <Field label={t("operations:detail.fields.duration")}>
            {took === null ? "—" : formatDuration(took, locale)}
          </Field>
          {operation.progress && operation.completedAt === null ? (
            <Field label={t("operations:detail.fields.progress")}>
              <span data-detail-progress={operation.progress.phase}>
                {t(`operations:progress.${operation.progress.phase}`, {
                  defaultValue: operation.progress.phase,
                })}
                {operation.progress.bytesDone != null && operation.progress.bytesTotal
                  ? ` ${Math.min(
                      100,
                      Math.floor(
                        (operation.progress.bytesDone / operation.progress.bytesTotal) * 100,
                      ),
                    )}%`
                  : ""}
              </span>
            </Field>
          ) : null}
          {operation.capturedRevisionId ? (
            <Field label={t("operations:detail.fields.capturedRevision")}>
              <span data-detail-captured-revision="">
                {operation.capturedRevision
                  ? revisionLabel(operation.capturedRevision)
                  : shortId(operation.capturedRevisionId)}
              </span>
              <AdvancedDetails>
                <CopyableId
                  value={operation.capturedRevisionId}
                  label={t("operations:detail.fields.capturedRevisionId")}
                />
              </AdvancedDetails>
            </Field>
          ) : null}
          {operation.kind === "RUN_COMMAND" ? (
            <Field label={t("operations:detail.fields.exitCode")}>
              <span data-detail-exit-code="" className="font-mono">
                {operation.exitCode === null ? "—" : operation.exitCode}
              </span>
            </Field>
          ) : null}
          {operation.errorCode !== null ? (
            <Field label={t("operations:detail.fields.error")} wide>
              <OperationResultText exitCode={null} errorCode={operation.errorCode} />
              <span className="ml-2 font-mono text-xs text-muted-foreground">
                {operation.errorCode}
              </span>
              {operation.errorMessage ? (
                <span
                  data-error-message=""
                  className="mt-1 block whitespace-pre-wrap break-words font-mono text-xs"
                >
                  {operation.errorMessage}
                </span>
              ) : null}
            </Field>
          ) : null}
        </dl>
      </section>

      {operation.kind === "RUN_COMMAND" ? (
        <CommandOutputView
          operationId={operation.id}
          settled={!pending}
          receipt={`${operation.state}|${operation.exitCode}|${operation.errorCode}`}
          locale={locale}
          timing={outputTiming}
        />
      ) : null}

      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
          <AlertDialogHeader>
            <AlertDialogTitle>{t("operations:cancel.title")}</AlertDialogTitle>
            <AlertDialogDescription>{t("operations:cancel.description")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("operations:cancel.keep")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="min-h-[44px] w-full sm:w-auto"
              disabled={unavailable || cancel.isPending}
              onClick={() => {
                if (!unavailable) cancel.mutate({ operationId: operation.id });
              }}
            >
              {cancel.isPending ? t("operations:cancel.pending") : t("operations:cancel.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function Field({ label, wide, children }: { label: string; wide?: boolean; children: ReactNode }) {
  return (
    <div className={wide ? "min-w-0 sm:col-span-2" : "min-w-0"}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}
