import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button } from "@wssp/ui/components/button";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import { toast } from "@wssp/ui/components/sileo";
import { ArrowLeft } from "lucide-react";
import { type ReactNode, useState } from "react";
import { useTranslation } from "react-i18next";
import { AdvancedDetails } from "@/components/advanced-details";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { CopyableId } from "@/components/copyable-id";
import { EmptyState } from "@/components/empty-state";
import { InlineRetry } from "@/components/inline-retry";
import { CommandOutputView } from "@/components/operations/command-output-view";
import { PageHeader } from "@/components/page-shell";
import { SkeletonList } from "@/components/skeleton-list";
import type { FetchOutputPage, OutputTiming } from "@/hooks/use-command-output";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatBytes } from "@/lib/format-bytes";
import { formatDateTime } from "@/lib/format-date-time";
import { isQueryAccessError } from "@/lib/query-access-error";
import { isNotFound } from "@/lib/sandbox-rules";
import {
  BUILD_ACTIVE_REFETCH_MS,
  type BuildProblem,
  buildProblem,
  canCancelBuild,
  isBuildActive,
  plainTail,
  shownStepState,
} from "@/lib/template-build-rules";
import { orpc } from "@/utils/orpc";
import {
  BuildErrorDetailText,
  BuildErrorText,
  BuildFailureNextStep,
  BuildPhaseText,
  BuildStatePill,
  buildName,
  buildResultRevision,
  type TemplateBuild,
  useBuildProblemText,
} from "./build-parts";
import { PlacingHint } from "./placing-hint";

/**
 * One template build: state and progress phase, the
 * executed steps with their exit codes and live output (read through the
 * build's own logs route, so no `operations:read` is needed), the typed
 * failure with the owner-only output tail kept beyond output retention, the
 * captured revision, and Cancel (type-to-confirm). The build polls while it
 * is active and stops once terminal. Another owner's build is not found.
 */
export function TemplateBuildDetailPage({
  lang,
  buildId,
  outputTiming,
}: {
  lang: string;
  buildId: string;
  /** Test-only override of the output poll cadence. */
  outputTiming?: OutputTiming;
}) {
  const { t, i18n } = useTranslation(["templates"]);
  const query = useQuery({
    ...orpc.templateBuilds.get.queryOptions({ input: { id: buildId } }),
    refetchInterval: (current) => {
      const state = current.state.data?.state;
      if (state === undefined) return false;
      // A terminal build still mirrors cleanup; poll slowly until it is done.
      if (!isBuildActive(state))
        return current.state.data?.cleanupState === "PENDING" ? BUILD_ACTIVE_REFETCH_MS * 5 : false;
      return BUILD_ACTIVE_REFETCH_MS;
    },
    retry: (count, error) => !isNotFound(error) && count < 1,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);

  const back = (
    <Link
      to="/$lang/dashboard/templates/builds"
      params={{ lang }}
      className="inline-flex min-h-11 items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft aria-hidden="true" className="size-4" />
      {t("templates:builds.detail.back")}
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
          <div role="status" data-build-missing="">
            <EmptyState
              className="rounded-xl border px-4"
              title={t("templates:builds.detail.notFoundTitle")}
              description={t("templates:builds.detail.notFoundDescription")}
            />
          </div>
        ) : (
          <InlineRetry
            message={t("templates:builds.detail.loadFailed")}
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
          message={t("templates:builds.detail.loadFailed")}
          onRetry={() => void query.refetch()}
        />
      ) : null}
      <BuildDetail
        build={query.data}
        lang={lang}
        locale={i18n.language}
        outputTiming={outputTiming}
      />
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="break-words">{children}</dd>
    </div>
  );
}

function BuildDetail({
  build,
  lang,
  locale,
  outputTiming,
}: {
  build: TemplateBuild;
  lang: string;
  locale: string;
  outputTiming?: OutputTiming;
}) {
  const { t } = useTranslation(["templates", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const problemText = useBuildProblemText();
  const [confirming, setConfirming] = useState(false);
  const [problem, setProblem] = useState<BuildProblem | null>(null);
  const cancel = useMutation({
    ...orpc.templateBuilds.cancel.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: (updated) => {
      setConfirming(false);
      // Cancel answers without the browser-only target; keep the loaded one.
      queryClient.setQueryData(
        orpc.templateBuilds.get.queryKey({ input: { id: build.id } }),
        (current) => (current ? { ...updated, target: current.target } : current),
      );
      toast.success(t("templates:builds.detail.cancel.done"));
    },
    onError: (error) => {
      setConfirming(false);
      if (!redirect(error)) setProblem(buildProblem(error));
    },
    onSettled: () => void queryClient.invalidateQueries({ queryKey: orpc.templateBuilds.key() }),
  });
  const failed = build.state === "FAILED";
  const tail = useQuery({
    ...orpc.templateBuilds.failureTail.queryOptions({ input: { id: build.id } }),
    enabled: failed,
    staleTime: Number.POSITIVE_INFINITY,
    meta: { skipGlobalErrorToast: true },
  });
  const minutes =
    build.chargedMinutes !== null
      ? t("templates:builds.detail.minutesCharged", {
          charged: build.chargedMinutes,
          limit: build.timeoutMinutes,
        })
      : t("templates:builds.detail.minutesReserved", {
          reserved: build.reservedMinutes,
          limit: build.timeoutMinutes,
        });
  const failureStep = build.failureStepIndex;

  return (
    <>
      <PageHeader
        title={t("templates:builds.detail.title", { name: buildName(build) })}
        actions={
          canCancelBuild(build.state) ? (
            <Button
              type="button"
              size="touch"
              variant="destructive"
              disabled={cancel.isPending}
              onClick={() => setConfirming(true)}
            >
              {t("templates:builds.detail.cancel.action")}
            </Button>
          ) : null
        }
      />
      <div className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
        <BuildStatePill state={build.state} />
        <BuildPhaseText build={build} />
        {build.cancelRequestedAt && build.state !== "CANCELLED" ? (
          <span className="text-muted-foreground">
            {t("templates:builds.detail.cancelRequested")}
          </span>
        ) : null}
      </div>
      <PlacingHint build={build} lang={lang} />
      {build.state === "AWAITING_CONTEXT" ? (
        <p role="status" className="text-sm text-muted-foreground">
          {t("templates:builds.detail.awaitingContext")}
        </p>
      ) : null}
      {!isBuildActive(build.state) && build.cleanupState === "PENDING" ? (
        <p role="status" data-build-cleanup="" className="text-sm text-muted-foreground">
          {t("templates:builds.detail.cleanupPending")}
        </p>
      ) : null}
      {build.egressModeReason ? (
        <p role="status" data-build-egress-reason={build.egressModeReason} className="text-sm">
          {t(`templates:builds.detail.egressDowngraded.${build.egressModeReason}`)}
        </p>
      ) : null}
      {problem ? (
        <p role="alert" data-build-problem={problem.kind} className="text-sm text-destructive">
          {problemText(problem)}
        </p>
      ) : null}
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
        <Field label={t("templates:builds.detail.template")}>
          {build.templateName ? (
            <span className="break-all">{build.templateName}</span>
          ) : (
            <span className="break-all font-mono text-xs">{build.templateId}</span>
          )}
        </Field>
        <Field label={t("templates:builds.detail.tag")}>
          <span className="font-mono">{build.tag}</span>
        </Field>
        <Field label={t("templates:builds.detail.acceptedBy")}>
          {t(`templates:builds.acceptedBy.${build.acceptedBy}`)}
        </Field>
        <Field label={t("templates:builds.detail.created")}>
          {formatDateTime(build.createdAt, locale, { seconds: true })}
        </Field>
        <Field label={t("templates:builds.detail.completed")}>
          {build.completedAt ? formatDateTime(build.completedAt, locale, { seconds: true }) : "—"}
        </Field>
        <Field label={t("templates:builds.detail.minutes")}>{minutes}</Field>
        <Field label={t("templates:builds.detail.context")}>
          {build.contextBytes !== null
            ? t("templates:builds.detail.contextSize", {
                size: formatBytes(build.contextBytes, lang),
              })
            : t("templates:builds.detail.noContext")}
        </Field>
      </dl>
      <AdvancedDetails>
        <IdRow label={t("templates:builds.detail.buildId")} value={build.id} />
        <IdRow label={t("templates:builds.detail.buildDigest")} value={build.buildDigest} />
        <IdRow label={t("templates:builds.detail.recipeDigest")} value={build.recipeDigest} />
        {build.contextSha256 !== null ? (
          <IdRow label={t("templates:builds.detail.contextDigest")} value={build.contextSha256} />
        ) : null}
        <IdRow
          label={t("templates:builds.detail.resultRevisionId")}
          value={build.revisionId ?? build.cacheHitRevisionId}
        />
      </AdvancedDetails>
      {build.revisionId || build.cacheHitRevisionId ? (
        <section data-build-result="" className="flex min-w-0 flex-col gap-2">
          <h2 className="text-sm font-medium">{t("templates:builds.detail.result")}</h2>
          <p className="break-all text-sm">
            {build.revisionId
              ? t("templates:builds.detail.revision", {
                  revision: buildResultRevision(build, build.revisionId),
                })
              : t("templates:builds.detail.cacheHit", {
                  revision: buildResultRevision(build, build.cacheHitRevisionId ?? ""),
                })}
          </p>
          <Link
            to="/$lang/dashboard/templates"
            params={{ lang }}
            className="inline-flex min-h-11 items-center text-sm font-medium underline underline-offset-4"
          >
            {t("templates:builds.detail.viewTemplates")}
          </Link>
        </section>
      ) : null}
      {build.errorCode ? (
        <section
          data-build-failure=""
          className="flex min-w-0 flex-col gap-2 rounded-xl border border-destructive/40 p-4"
        >
          <h2 className="text-sm font-medium">{t("templates:builds.detail.failure")}</h2>
          <p className="text-sm">
            <BuildErrorText build={build} />
          </p>
          <BuildFailureNextStep build={build} lang={lang} />
          {failureStep !== null ? (
            <p className="text-sm">
              {build.failureExitCode !== null
                ? t("templates:builds.detail.failureStep", {
                    step: failureStep + 1,
                    code: build.failureExitCode,
                  })
                : t("templates:builds.detail.failureStepNoCode", { step: failureStep + 1 })}
            </p>
          ) : null}
          {build.errorDetail ? (
            <p className="text-xs text-muted-foreground">
              <BuildErrorDetailText build={build} />
            </p>
          ) : null}
          {failed && tail.isError ? (
            <InlineRetry
              message={t("templates:builds.detail.failureTailFailed")}
              onRetry={() => void tail.refetch()}
            />
          ) : null}
          {tail.data?.tail ? (
            <div className="flex min-w-0 flex-col gap-1">
              <p className="text-xs text-muted-foreground">
                {t("templates:builds.detail.failureTail")}
              </p>
              <CodeSnippet
                data-build-failure-tail=""
                code={plainTail(tail.data.tail)}
                copyLabel={t("templates:builds.detail.copyTail")}
                preClassName="max-h-80 overflow-y-auto whitespace-pre-wrap break-all"
              />
            </div>
          ) : null}
        </section>
      ) : null}
      <BuildSteps build={build} locale={locale} outputTiming={outputTiming} />
      <ConfirmDeleteDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={t("templates:builds.detail.cancel.title", { name: buildName(build) })}
        description={t("templates:builds.detail.cancel.description")}
        confirmToken={build.id}
        typePrompt={t("templates:builds.detail.cancel.typePrompt")}
        copyAriaLabel={t("templates:builds.detail.cancel.copy")}
        confirmLabel={t("templates:builds.detail.cancel.confirm")}
        pendingLabel={t("templates:builds.detail.cancel.pending")}
        isPending={cancel.isPending}
        onConfirm={() => cancel.mutate({ id: build.id })}
      />
    </>
  );
}

function BuildSteps({
  build,
  locale,
  outputTiming,
}: {
  build: TemplateBuild;
  locale: string;
  outputTiming?: OutputTiming;
}) {
  const { t } = useTranslation(["templates"]);
  const [open, setOpen] = useState<ReadonlySet<number>>(new Set());
  // The running step's output is shown without asking; others on demand.
  const running = build.steps.find((step) => step.state === "running")?.n;
  const toggle = (n: number) =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(n)) next.delete(n);
      else next.add(n);
      return next;
    });
  return (
    <section className="flex min-w-0 flex-col gap-3">
      <h2 className="text-sm font-medium">{t("templates:builds.detail.steps")}</h2>
      {build.steps.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("templates:builds.detail.noSteps")}</p>
      ) : null}
      <ol className="flex min-w-0 flex-col gap-3">
        {build.steps.map((step) => {
          const shown = open.has(step.n) !== (step.n === running);
          const state = shownStepState(build.state, step.state);
          return (
            <li
              key={step.n}
              data-build-step={step.n}
              data-step-state={state}
              className="flex min-w-0 flex-col gap-2 rounded-xl border p-3"
            >
              <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                <p className="min-w-0 text-sm">
                  {t("templates:builds.detail.stepTitle", {
                    n: step.n + 1,
                    kind: t(`templates:builds.stepKind.${step.kind}`),
                    index: step.stepIndex + 1,
                  })}
                </p>
                <span className="flex flex-wrap items-center gap-2 text-xs">
                  <span data-step-state-label="">{t(`templates:builds.stepState.${state}`)}</span>
                  {step.exitCode !== null ? (
                    <span className="font-mono">
                      {t("templates:builds.detail.exitCode", { code: step.exitCode })}
                    </span>
                  ) : null}
                </span>
              </div>
              {step.operationId ? (
                <>
                  <Button
                    type="button"
                    size="touch"
                    variant="outline"
                    className="self-start"
                    aria-expanded={shown}
                    onClick={() => toggle(step.n)}
                  >
                    {shown
                      ? t("templates:builds.detail.hideLogs")
                      : t("templates:builds.detail.showLogs")}
                  </Button>
                  {shown ? (
                    <CommandOutputView
                      operationId={step.operationId}
                      fetchPage={stepOutputReader(build.id, step.n)}
                      settled={step.state === "succeeded" || step.state === "failed"}
                      locale={locale}
                      timing={outputTiming}
                    />
                  ) : null}
                </>
              ) : (
                <p className="text-xs text-muted-foreground">
                  {t(
                    state === "notRun"
                      ? "templates:builds.detail.notRun"
                      : "templates:builds.detail.noOutput",
                  )}
                </p>
              )}
            </li>
          );
        })}
      </ol>
    </section>
  );
}

/** One executed step's output pages, through the build's logs route. */
function stepOutputReader(buildId: string, step: number): FetchOutputPage {
  return async (input, { signal }) => {
    const result = await orpc.templateBuilds.logs.call(
      { id: buildId, step, ...(input.cursor === undefined ? {} : { cursor: input.cursor }) },
      { signal },
    );
    if (result.output === null) throw new Error("Step output is not available yet.");
    return result.output;
  };
}

/** A labelled opaque ID inside Advanced: short form, full value on copy. */
function IdRow({ label, value }: { label: string; value: string | null }) {
  if (!value) return null;
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <CopyableId value={value} label={label} />
    </div>
  );
}
