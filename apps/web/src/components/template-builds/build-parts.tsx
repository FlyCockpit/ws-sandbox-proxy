import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { Badge } from "@wssp/ui/components/badge";
import { cn } from "@wssp/ui/lib/utils";
import { useTranslation } from "react-i18next";
import { shortId } from "@/components/copyable-id";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { dateTimeTitle } from "@/lib/format-date-time";
import {
  type BaseProblem,
  BUILD_LIST_REFETCH_MS,
  type BuildPhase,
  type BuildProblem,
  type BuildState,
  type BuildTone,
  buildErrorCode,
  buildPhase,
  buildTone,
  carriesCaptureDetail,
  disabledReasonKey,
  failureDetailKey,
  isBuildActive,
  recipeCodeKey,
  type SourceProblem,
  storeDetailMessage,
} from "@/lib/template-build-rules";
import { revisionLabel } from "@/lib/template-rules";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/** Shared pieces of the template-build pages. */

export type TemplateBuild = Awaited<ReturnType<AppRouterClient["templateBuilds"]["get"]>>;

const TONE_CLASS: Record<BuildTone, string> = {
  pending: "border-sky-600/40 bg-sky-600/10 text-sky-700 dark:text-sky-400",
  cancelling: "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
  succeeded: "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400",
  failed: "border-destructive/40 bg-destructive/10 text-destructive",
  cancelled: "border-border bg-muted text-muted-foreground",
};

export function BuildStatePill({ state }: { state: BuildState }) {
  const { t } = useTranslation(["templates"]);
  return (
    <Badge
      data-build-state={state}
      className={cn(
        "inline-flex items-center whitespace-nowrap rounded-sm border px-2 py-0.5 text-xs font-medium",
        TONE_CLASS[buildTone(state)],
      )}
    >
      {t(`templates:builds.state.${state}`)}
    </Badge>
  );
}

/** The fine-grained progress line ("Running step 3 of 7"), or nothing when terminal. */
export function BuildPhaseText({
  build,
}: {
  build: Pick<TemplateBuild, "phase" | "stepIndex" | "steps">;
}) {
  const { t } = useTranslation(["templates"]);
  const phase: BuildPhase | null = buildPhase(build.phase);
  if (phase === null) return null;
  return (
    <span data-build-phase={phase}>
      {phase === "step"
        ? t("templates:builds.phase.step", {
            step: Math.max(build.stepIndex, 0) + 1,
            total: build.steps.length,
          })
        : t(`templates:builds.phase.${phase}`)}
    </span>
  );
}

/** The build's typed failure, when it failed. */
export function BuildErrorText({ build }: { build: Pick<TemplateBuild, "errorCode"> }) {
  const { t } = useTranslation(["templates"]);
  const code = buildErrorCode(build.errorCode);
  if (code === null) return null;
  return (
    <span data-build-error={code} className="text-destructive">
      {t(`templates:builds.error.${code}`)}
    </span>
  );
}

/**
 * The failure's detail: a known storage cause as its translated sentence,
 * anything else as the raw code ("Detail: x").
 */
export function BuildErrorDetailText({
  build,
}: {
  build: Pick<TemplateBuild, "errorCode" | "errorDetail">;
}) {
  const { t } = useTranslation(["templates"]);
  if (!build.errorDetail) return null;
  // A known cause is said in words by BuildFailureNextStep instead.
  if (failureDetailKey(build.errorDetail) !== null) return null;
  if (!carriesCaptureDetail(build.errorCode))
    return (
      <span className="break-all font-mono">
        {t("templates:builds.errorDetail", { detail: build.errorDetail })}
      </span>
    );
  return <StoreDetailText detail={build.errorDetail} />;
}

/**
 * What a known failure cause means and what to do next, in words (with a
 * link where the fix lives). Nothing for causes without a sentence; their
 * code stays secondary text (BuildErrorDetailText).
 */
export function BuildFailureNextStep({
  build,
  lang,
}: {
  build: Pick<TemplateBuild, "errorDetail">;
  lang: string;
}) {
  const { t } = useTranslation(["templates"]);
  const key = failureDetailKey(build.errorDetail);
  if (key === null) return null;
  return (
    <div data-build-next-step={key} className="flex min-w-0 flex-col gap-1 text-sm">
      <p>{t(`templates:builds.nextStep.${key}`)}</p>
      {key === "noBuilder" ? (
        <Link
          to="/$lang/settings/images"
          params={{ lang }}
          className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
        >
          {t("templates:builds.nextStep.openImageSettings")}
        </Link>
      ) : key === "hostCapacity" || key === "hostUnavailable" ? (
        <Link
          to="/$lang/settings/hosts"
          params={{ lang }}
          className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
        >
          {t("templates:preflight.openHosts")}
        </Link>
      ) : null}
    </div>
  );
}

/** A capture's storage cause (a build's or a "Save as template"
 * operation's) as its sentence; an unknown one is shown raw. */
export function StoreDetailText({ detail }: { detail: string }) {
  const { t } = useTranslation(["templates"]);
  const message = storeDetailMessage(detail);
  if (message === null)
    return (
      <span className="break-all font-mono">{t("templates:builds.errorDetail", { detail })}</span>
    );
  return (
    <span data-store-detail={message.key}>
      {message.key === "upload_http"
        ? t("templates:builds.storeDetail.upload_http", { status: message.status })
        : message.key === "upload_refused"
          ? t("templates:builds.storeDetail.upload_refused", { reason: message.reason })
          : t(`templates:builds.storeDetail.${message.key}`)}
    </span>
  );
}

/** A recipe refusal (from the editor check or the server) as one translated line. */
export function useRecipeProblemText() {
  const { t } = useTranslation(["templates"]);
  return (problem: Extract<SourceProblem | BuildProblem, { kind: "recipe" }>) => {
    // An undeclared build arg is named, with the line that fixes it.
    const message =
      problem.code === "recipe_arg_undeclared" && problem.names && problem.names.length > 0
        ? t("templates:builds.recipe.argUndeclared", {
            count: problem.names.length,
            names: problem.names.join(", "),
            fix: problem.names.map((name) => `ARG ${name}`).join(", "),
          })
        : t(`templates:builds.recipe.code.${recipeCodeKey(problem.code)}`);
    if (problem.line !== undefined && problem.column !== undefined)
      return t("templates:builds.recipe.position", {
        line: problem.line,
        column: problem.column,
        message,
      });
    if (problem.line !== undefined)
      return t("templates:builds.recipe.line", { line: problem.line, message });
    if (problem.stepIndex !== undefined)
      return t("templates:builds.recipe.step", { step: problem.stepIndex + 1, message });
    return message;
  };
}

/**
 * A FROM that names no template you can build from, with what to write
 * instead ("FROM ubuntu-base") when you have a ready template.
 */
export function useBaseProblemText() {
  const { t } = useTranslation(["templates"]);
  return (problem: BaseProblem) => {
    const main = t(`templates:builds.base.${problem.kind}`, { from: problem.from });
    const next =
      problem.examples.length > 0
        ? t("templates:builds.base.example", {
            examples: problem.examples.map((slug) => `FROM ${slug}`).join(", "),
          })
        : t("templates:builds.base.none");
    return `${main} ${next}`;
  };
}

/** Any typed build refusal as one translated line. */
export function useBuildProblemText() {
  const { t } = useTranslation(["templates"]);
  const recipe = useRecipeProblemText();
  return (problem: BuildProblem) => {
    switch (problem.kind) {
      case "recipe":
        return recipe(problem);
      case "disabled":
        return t(`templates:builds.disabled.${disabledReasonKey(problem.reason)}`);
      case "concurrency":
        return problem.max === null
          ? t("templates:builds.problem.concurrencyUnknown")
          : t("templates:builds.problem.concurrency", { max: problem.max });
      case "communityUnavailable":
        return t(`templates:community.unavailable.${problem.reason}`);
      case "minutes":
        return problem.max === null
          ? t("templates:builds.problem.minutesUnknown")
          : t("templates:builds.problem.minutes", { max: problem.max });
      default:
        return t(`templates:builds.problem.${problem.kind}`);
    }
  };
}

/** A build as people name it: `slug:tag` (the short template id if the template is gone). */
export function buildName(build: Pick<TemplateBuild, "templateSlug" | "templateId" | "tag">) {
  return `${build.templateSlug ?? shortId(build.templateId)}:${build.tag}`;
}

/** The build's result revision as `slug vN`, else its short id. */
export function buildResultRevision(
  build: Pick<TemplateBuild, "templateSlug" | "revisionNumber">,
  revisionId: string,
) {
  return build.templateSlug && build.revisionNumber !== null
    ? revisionLabel({ slug: build.templateSlug, revision: build.revisionNumber })
    : shortId(revisionId);
}

/** One build as a list row linking to its detail page. */
export function BuildRow({
  build,
  lang,
  locale,
  now,
  showTemplate,
}: {
  build: Omit<TemplateBuild, "target">;
  lang: string;
  locale: string;
  now: number;
  showTemplate: boolean;
}) {
  const { t } = useTranslation(["templates"]);
  const created = new Date(build.createdAt).getTime();
  return (
    <li data-build-id={build.id} className="min-w-0">
      <Link
        to="/$lang/dashboard/templates/builds/$buildId"
        params={{ lang, buildId: build.id }}
        aria-label={t("templates:builds.row.open", { name: buildName(build) })}
        className="flex min-h-11 min-w-0 flex-col gap-1 rounded-lg border p-3 hover:bg-muted/50"
      >
        <span className="flex min-w-0 flex-wrap items-center gap-2">
          <BuildStatePill state={build.state} />
          <span className="min-w-0 truncate text-sm font-medium">
            {showTemplate ? (build.templateSlug ?? shortId(build.templateId)) : null}
            {showTemplate ? " · " : null}
            {build.tag}
            {" · "}
            <span
              className="font-normal text-muted-foreground"
              title={dateTimeTitle(created, locale)}
            >
              {formatRelativeTime(created, locale, now)}
            </span>
          </span>
        </span>
        <span className="flex min-w-0 flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
          <BuildPhaseText build={build} />
          <BuildErrorText build={build} />
        </span>
      </Link>
    </li>
  );
}

/**
 * A template with no version yet says why, from its latest build: running
 * (with a link to watch it) or failed (with its reason, a link to the build
 * and Build again). Nothing is removed: the template stays, ready to build.
 * `buildAgain` is false for community templates (only their own Try again
 * writes them; it is on the build page).
 */
export function EmptyTemplateNote({
  templateId,
  lang,
  buildAgain,
}: {
  templateId: string;
  lang: string;
  buildAgain: boolean;
}) {
  const { t } = useTranslation(["templates"]);
  const latest = useQuery({
    ...orpc.templateBuilds.list.queryOptions({ input: { templateId, limit: 1 } }),
    refetchInterval: (current) =>
      current.state.data?.items.some((build) => isBuildActive(build.state))
        ? BUILD_LIST_REFETCH_MS
        : false,
    meta: { skipGlobalErrorToast: true },
  });
  const build = latest.data?.items[0];
  const active = build ? isBuildActive(build.state) : false;
  const linkClass = "inline-flex min-h-11 items-center font-medium underline underline-offset-4";
  return (
    <div
      data-empty-template={build ? (active ? "building" : build.state) : "none"}
      className="flex min-w-0 flex-col gap-1 rounded-md border border-dashed p-3 text-sm"
    >
      <p>
        {active
          ? t("templates:card.noVersionsBuilding")
          : build?.state === "FAILED"
            ? t("templates:card.noVersionsLastBuild")
            : build?.state === "CANCELLED"
              ? t("templates:card.noVersionsCancelled")
              : t("templates:card.noVersionsHint")}{" "}
        {build?.state === "FAILED" ? <BuildErrorText build={build} /> : null}
      </p>
      <div className="flex min-w-0 flex-wrap gap-x-4">
        {build ? (
          <Link
            to="/$lang/dashboard/templates/builds/$buildId"
            params={{ lang, buildId: build.id }}
            className={linkClass}
          >
            {t(active ? "templates:card.watchBuild" : "templates:card.viewBuild")}
          </Link>
        ) : null}
        {buildAgain && !active ? (
          <Link
            to="/$lang/dashboard/templates/new/build"
            params={{ lang }}
            search={{ template: templateId }}
            className={linkClass}
          >
            {t(build ? "templates:card.buildAgain" : "templates:builds.action")}
          </Link>
        ) : null}
      </div>
    </div>
  );
}

const cursorPages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

/** A template's most recent builds (templates page), with a link to all of them. */
export function TemplateBuildsSection({ templateId, lang }: { templateId: string; lang: string }) {
  const { t, i18n } = useTranslation(["templates"]);
  const query = useInfiniteQuery({
    ...orpc.templateBuilds.list.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ templateId, cursor, limit: 5 }),
    }),
    // Poll only while a listed build is still running.
    refetchInterval: (current) =>
      current.state.data?.pages.some((page) =>
        page.items.some((build) => isBuildActive(build.state)),
      )
        ? BUILD_LIST_REFETCH_MS
        : false,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const builds = query.data?.pages.flatMap((page) => page.items) ?? [];
  const now = Date.now();
  return (
    <section data-template-builds="" className="flex min-w-0 flex-col gap-2">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium">{t("templates:builds.recent")}</p>
        <Link
          to="/$lang/dashboard/templates/builds"
          params={{ lang }}
          search={{ templateId }}
          className="inline-flex min-h-11 items-center text-sm font-medium underline underline-offset-4"
        >
          {t("templates:builds.viewAll")}
        </Link>
      </div>
      {query.isPending ? <SkeletonList count={1} className="rounded-xl border" /> : null}
      {query.isError ? (
        <InlineRetry
          message={t("templates:builds.loadFailed")}
          onRetry={() => void query.refetch()}
        />
      ) : null}
      {query.isSuccess && builds.length === 0 ? (
        <p className="text-xs text-muted-foreground">{t("templates:builds.emptyForTemplate")}</p>
      ) : null}
      {builds.length > 0 ? (
        <ul aria-label={t("templates:builds.listRegion")} className="flex min-w-0 flex-col gap-2">
          {builds.map((build) => (
            <BuildRow
              key={build.id}
              build={build}
              lang={lang}
              locale={i18n.language}
              now={now}
              showTemplate={false}
            />
          ))}
        </ul>
      ) : null}
      <LoadMore
        hasNextPage={query.hasNextPage}
        isFetchingNextPage={query.isFetchingNextPage}
        onLoadMore={() => void query.fetchNextPage()}
        label={t("templates:builds.more")}
      />
    </section>
  );
}
