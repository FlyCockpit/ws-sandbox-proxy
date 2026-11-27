import { useInfiniteQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { Hammer } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { FormSelect } from "@/components/form-select";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  BUILD_LIST_REFETCH_MS,
  type BuildState,
  buildsListInput,
  isBuildActive,
  TEMPLATE_BUILD_STATES,
  type TemplateBuildsSearch,
} from "@/lib/template-build-rules";
import { orpc } from "@/utils/orpc";
import { BuildRow } from "./build-parts";

/**
 * Template builds: every build of the owner, newest first, with
 * the state and template filters kept in the URL. Rows link to the build
 * detail page; the list polls only while a listed build is still running.
 */
export function TemplateBuildsPage({
  lang,
  search,
  onSearchChange,
}: {
  lang: string;
  search: TemplateBuildsSearch;
  onSearchChange: (next: TemplateBuildsSearch) => void;
}) {
  const { t, i18n } = useTranslation(["templates", "dashboard"]);
  const stateId = useId();
  const query = useInfiniteQuery({
    ...orpc.templateBuilds.list.infiniteOptions({
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
      input: (cursor: string | undefined) => buildsListInput(search, DASHBOARD_PAGE_LIMIT, cursor),
    }),
    refetchInterval: (current) =>
      current.state.data?.pages.some((page) =>
        page.items.some((build) => isBuildActive(build.state)),
      )
        ? BUILD_LIST_REFETCH_MS
        : false,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const builds = query.data?.pages.flatMap((page) => page.items);
  // The filtered template's name, from any listed build of it (else its id).
  const filterName = builds?.find((build) => build.templateId === search.templateId)?.templateName;
  const now = Date.now();

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        title={t("templates:builds.title")}
        description={t("templates:builds.description")}
        actions={
          <Link
            to="/$lang/dashboard/templates/new/build"
            params={{ lang }}
            className={buttonVariants({ size: "touch" })}
          >
            <Hammer aria-hidden="true" />
            {t("templates:builds.newAction")}
          </Link>
        }
      />
      <div className="flex min-w-0 flex-wrap items-end gap-4">
        <div className="flex min-w-0 flex-col gap-2">
          <Label htmlFor={stateId}>{t("templates:builds.filter.state")}</Label>
          <FormSelect
            id={stateId}
            autoComplete="off"
            value={search.state ?? ""}
            onValueChange={(value) =>
              onSearchChange({
                ...search,
                state: value === "" ? undefined : (value as BuildState),
              })
            }
          >
            <SelectItem value="">{t("templates:builds.filter.allStates")}</SelectItem>
            {TEMPLATE_BUILD_STATES.map((state) => (
              <SelectItem key={state} value={state}>
                {t(`templates:builds.state.${state}`)}
              </SelectItem>
            ))}
          </FormSelect>
        </div>
        {search.templateId ? (
          <div className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
            <span className="break-all" data-build-template-filter={search.templateId}>
              {t("templates:builds.filter.template", { id: filterName ?? search.templateId })}
            </span>
            <Button
              type="button"
              size="touch"
              variant="outline"
              onClick={() => onSearchChange({ ...search, templateId: undefined })}
            >
              {t("templates:builds.filter.allTemplates")}
            </Button>
          </div>
        ) : null}
      </div>
      <QueryBoundary
        query={{
          data: builds,
          isPending: query.isPending,
          isError: query.isError,
          fetchStatus: query.fetchStatus,
          error: query.error,
          refetch: query.refetch,
        }}
        skeleton={<SkeletonList layout="resource" count={3} className="rounded-xl border" />}
        errorMessage={t("templates:builds.loadFailed")}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            className="rounded-xl border px-4"
            title={t("templates:builds.empty.title")}
            description={t("templates:builds.empty.description")}
          />
        }
      >
        {(rows) => (
          <>
            <ul
              aria-label={t("templates:builds.listRegion")}
              className="flex min-w-0 flex-col gap-2"
            >
              {rows.map((build) => (
                <BuildRow
                  key={build.id}
                  build={build}
                  lang={lang}
                  locale={i18n.language}
                  now={now}
                  showTemplate={search.templateId === undefined}
                />
              ))}
            </ul>
            <LoadMore
              hasNextPage={query.hasNextPage}
              isFetchingNextPage={query.isFetchingNextPage}
              onLoadMore={() => void query.fetchNextPage()}
              label={t("templates:builds.more")}
            />
          </>
        )}
      </QueryBoundary>
    </div>
  );
}
