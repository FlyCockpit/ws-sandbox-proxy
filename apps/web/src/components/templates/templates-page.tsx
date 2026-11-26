import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { env } from "@wssp/env/web";
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
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { AdvancedSection } from "@wssp/ui/components/form-page";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { toast } from "@wssp/ui/components/sileo";
import { TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { Archive, ChevronDown, Hammer, HardDrive, Plus } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { AdvancedDetails } from "@/components/advanced-details";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { CopyableId } from "@/components/copyable-id";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { type OverflowAction, PageActions } from "@/components/page-actions";
import { PageHeader } from "@/components/page-shell";
import { PoolImageTarget } from "@/components/pools/pool-image-target";
import { QueryBoundary } from "@/components/query-boundary";
import { ResourceIdentity } from "@/components/resource-identity";
import { SegmentedControl } from "@/components/segmented-control";
import { SkeletonList } from "@/components/skeleton-list";
import { EmptyTemplateNote, TemplateBuildsSection } from "@/components/template-builds/build-parts";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { docsUrl } from "@/lib/docs-links";
import { dateTimeTitle } from "@/lib/format-date-time";
import { toMs } from "@/lib/host-status";
import { isLaunchableRevision } from "@/lib/template-build-rules";
import {
  registrableHosts,
  revisionLabel,
  type TemplateProblem,
  templateProblem,
} from "@/lib/template-rules";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";
import {
  CommunityBadge,
  CommunityTemplateControls,
  CreateCommunityTemplateDialog,
} from "./community-template";
import { NewTemplateChooser } from "./new-template-chooser";
import {
  PublishRevisionButton,
  RevisionImageBadges,
  useTemplateImageActions,
} from "./template-image-controls";
import { invalidateTemplates } from "./template-queries";

/**
 * Templates dashboard (C46): the images sandboxes start from. One "New
 * template" action opens a chooser (community image, recipe build, register
 * an existing image); the list is compact cards (name, status, versions
 * summary, one visible action and an overflow menu) whose versions, host
 * evidence and builds open on demand. A template is "Ready" only with a
 * launchable live version; archiving keeps its versions (and every sandbox's
 * reference to them) but cannot be undone.
 */

/** Refetch cadence of the list. */
const TEMPLATES_REFETCH_MS = 15_000;
/** The revision sheet's host picker pages with Load more (procedure maximum per page). */
const HOST_PICKER_LIMIT = 100;

type TemplatePage = Awaited<ReturnType<AppRouterClient["sandboxTemplates"]["listTemplates"]>>;
type TemplateItem = TemplatePage["items"][number];
type StatusFilter = "active" | "retired" | "all";
type TemplateStatus = "archived" | "ready" | "noVersions";

const cursorPages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

/** Ready needs at least one launchable live version; archived wins over both. */
function templateStatus(template: {
  archivedAt: unknown;
  versions: { count: number };
}): TemplateStatus {
  if (template.archivedAt !== null) return "archived";
  return template.versions.count > 0 ? "ready" : "noVersions";
}

export function TemplatesPage({
  lang,
  initialChoosing = false,
}: {
  lang: string;
  /** `?new=true`: open the New template chooser (linked from Create sandbox). */
  initialChoosing?: boolean;
}) {
  const { t, i18n } = useTranslation(["templates", "dashboard", "common"]);
  const [status, setStatus] = useState<StatusFilter>("active");
  const [choosing, setChoosing] = useState(initialChoosing);
  const [fromCommunity, setFromCommunity] = useState(false);
  const query = useInfiniteQuery({
    ...orpc.sandboxTemplates.listTemplates.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: DASHBOARD_PAGE_LIMIT, cursor, status }),
    }),
    refetchInterval: TEMPLATES_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [query.error]);
  const templates = query.data?.pages.flatMap((page) => page.items);
  const now = Date.now();

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        title={t("templates:title")}
        description={t("templates:subtitle")}
        actions={
          <PageActions
            primary={
              <Button type="button" size="touch" onClick={() => setChoosing(true)}>
                <Plus aria-hidden="true" />
                {t("templates:chooser.action")}
              </Button>
            }
            secondary={
              <Link
                to="/$lang/dashboard/templates/builds"
                params={{ lang }}
                className={buttonVariants({ variant: "outline", size: "touch" })}
              >
                {t("templates:builds.viewAll")}
              </Link>
            }
          />
        }
      />
      <AboutTemplates />
      <SegmentedControl
        value={status}
        onChange={setStatus}
        ariaLabel={t("templates:filter.label")}
        items={[
          { value: "active", label: t("templates:filter.active") },
          { value: "retired", label: t("templates:filter.retired") },
          { value: "all", label: t("templates:filter.all") },
        ]}
      />
      <QueryBoundary
        query={{
          data: templates,
          isPending: query.isPending,
          isError: query.isError,
          error: query.error,
          refetch: query.refetch,
        }}
        skeleton={<SkeletonList layout="resource" count={3} className="rounded-xl border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            className="rounded-xl border px-4"
            title={t(
              status === "retired" ? "templates:empty.retiredTitle" : "templates:empty.title",
            )}
            description={t(
              status === "retired"
                ? "templates:empty.retiredDescription"
                : "templates:empty.description",
            )}
            action={
              status === "retired" ? null : (
                <Button
                  type="button"
                  size="touch"
                  className="mt-2"
                  data-empty-new-template=""
                  onClick={() => setChoosing(true)}
                >
                  <Plus aria-hidden="true" />
                  {t("templates:chooser.action")}
                </Button>
              )
            }
          />
        }
      >
        {(rows) => (
          <>
            <ul aria-label={t("templates:listRegion")} className="flex min-w-0 flex-col gap-2">
              {rows.map((template) => (
                <TemplateCard
                  key={template.id}
                  template={template}
                  now={now}
                  lang={lang}
                  locale={i18n.language}
                />
              ))}
            </ul>
            <LoadMore
              hasNextPage={query.hasNextPage}
              isFetchingNextPage={query.isFetchingNextPage}
              onLoadMore={() => void query.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      {choosing ? (
        <NewTemplateChooser
          lang={lang}
          onClose={() => setChoosing(false)}
          onCommunity={() => {
            setChoosing(false);
            setFromCommunity(true);
          }}
        />
      ) : null}
      {fromCommunity ? (
        <CreateCommunityTemplateDialog lang={lang} onClose={() => setFromCommunity(false)} />
      ) : null}
    </div>
  );
}

/** The old subtitle and the image requirements, behind one collapsed disclosure. */
function AboutTemplates() {
  const { t } = useTranslation(["templates"]);
  const items = ["image", "architecture", "agent", "identity", "tools"] as const;
  const docsHref = docsUrl(env.VITE_DOCS_URL, "templates");
  return (
    <AdvancedSection
      title={t("templates:requirements.about")}
      data-templates-about=""
      // A boxed disclosure on the list page, not a form section.
      className="rounded-lg border bg-card px-3 text-card-foreground"
      gridClassName="lg:grid-cols-1"
    >
      <p className="text-sm text-muted-foreground">{t("templates:description")}</p>
      <h2 className="text-sm font-medium">{t("templates:requirements.title")}</h2>
      <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{t(`templates:requirements.${item}`)}</li>
        ))}
      </ul>
      <p className="text-sm text-muted-foreground">
        {t("templates:requirements.readiness")}{" "}
        <a
          href={docsHref}
          target="_blank"
          rel="noreferrer"
          data-docs-link=""
          className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
        >
          {t("templates:requirements.docsLink")}
        </a>
      </p>
    </AdvancedSection>
  );
}

const STATUS_TONE: Record<TemplateStatus, string> = {
  ready: "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-400",
  noVersions: "border-amber-600/40 bg-amber-600/10 text-amber-700 dark:text-amber-400",
  archived: "border-border bg-muted text-muted-foreground",
};

function TemplateCard({
  template,
  now,
  lang,
  locale,
}: {
  template: TemplateItem;
  now: number;
  lang: string;
  locale: string;
}) {
  const { t } = useTranslation(["templates", "hosts", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const redirect = useTwoFactorRedirect(lang);
  const detailsId = useId();
  const [confirming, setConfirming] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [problem, setProblem] = useState<TemplateProblem | null>(null);
  const archived = template.archivedAt !== null;
  const community = template.communitySource ? { refresh: template.communityRefresh } : null;
  const status = templateStatus(template);
  const created = toMs(template.createdAt);
  const retired = toMs(template.archivedAt);
  const when = retired ?? created;
  const image = useTemplateImageActions(template, lang);
  const archive = useMutation({
    ...orpc.sandboxTemplates.retireTemplate.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: () => {
      setConfirming(false);
      toast.success(t("templates:archive.done", { label: template.label }));
    },
    onError: (error) => {
      setConfirming(false);
      if (!redirect(error)) setProblem(templateProblem(error));
    },
    onSettled: () => invalidateTemplates(queryClient),
  });
  const overflow: OverflowAction[] = [
    // A community template is wssp-managed: only Refresh now and Try again write it.
    ...(community
      ? []
      : [
          {
            id: "register-version",
            label: t("templates:card.registerVersion"),
            icon: HardDrive,
            onSelect: () =>
              void navigate({
                to: "/$lang/dashboard/templates/new/register",
                params: { lang },
                search: { template: template.id },
              }),
          },
        ]),
    ...image.actions,
    {
      id: "archive",
      label: t("templates:archive.action"),
      icon: Archive,
      destructive: true,
      disabled: archive.isPending,
      onSelect: () => setConfirming(true),
    },
  ];
  const versionsText =
    template.versions.count === 0
      ? t("templates:card.noVersions")
      : t("templates:card.versions", {
          count: template.versions.count,
          latest: template.versions.latest ?? "—",
        });

  return (
    <li
      data-template-id={template.id}
      data-usability={archived ? "archived" : "active"}
      className="flex min-w-0 flex-col gap-2 rounded-xl border bg-card p-3 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <h2 className="min-w-0 truncate text-sm font-medium">{template.label}</h2>
            {community ? <CommunityBadge /> : null}
            <span
              data-template-status={status}
              className={cn(
                "inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium",
                STATUS_TONE[status],
              )}
            >
              {t(`templates:status.${status}`)}
            </span>
          </div>
          {template.slug !== template.label ? (
            <p className="truncate font-mono text-xs text-muted-foreground">{template.slug}</p>
          ) : null}
          <p data-template-summary="" className="text-xs text-muted-foreground">
            {versionsText}
            {when == null ? null : (
              <>
                {" · "}
                <span title={dateTimeTitle(when, locale)}>
                  {t(retired == null ? "templates:card.created" : "templates:card.archived", {
                    when: formatRelativeTime(when, locale, now),
                  })}
                </span>
              </>
            )}
          </p>
        </div>
        {archived ? null : (
          <PageActions
            secondary={
              community ? null : (
                <Link
                  to="/$lang/dashboard/templates/new/build"
                  params={{ lang }}
                  search={{ template: template.id }}
                  className={buttonVariants({ variant: "secondary", size: "touch" })}
                >
                  <Hammer aria-hidden="true" />
                  {t("templates:builds.action")}
                </Link>
              )
            }
            overflow={overflow}
            overflowLabel={t("templates:card.more", { label: template.label })}
          />
        )}
      </div>
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`templates:problem.${problem}`)}
        </p>
      ) : null}
      {status === "noVersions" ? (
        <EmptyTemplateNote templateId={template.id} lang={lang} buildAgain={community === null} />
      ) : null}
      <Button
        type="button"
        variant="ghost"
        size="touch"
        className="self-start"
        aria-expanded={expanded}
        aria-controls={detailsId}
        onClick={() => setExpanded((open) => !open)}
      >
        <ChevronDown
          aria-hidden="true"
          className={cn("size-4 transition-transform", expanded ? "rotate-0" : "-rotate-90")}
        />
        {t(expanded ? "templates:card.hideDetails" : "templates:card.showDetails")}
      </Button>
      {expanded ? (
        <div id={detailsId} className="flex min-w-0 flex-col gap-3">
          {community ? (
            <CommunityTemplateControls template={{ ...template, community }} lang={lang} />
          ) : null}
          <TemplateRevisionList template={template} lang={lang} />
          <TemplateBuildsSection templateId={template.id} lang={lang} />
        </div>
      ) : null}
      {image.dialogs}
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("templates:archive.title", { label: template.label })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("templates:archive.description", { label: template.label })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              className="min-h-[44px] w-full sm:w-auto"
              disabled={archive.isPending}
              onClick={() => archive.mutate({ id: template.id })}
            >
              {archive.isPending ? t("templates:archive.pending") : t("templates:archive.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </li>
  );
}

function TemplateRevisionList({ template, lang }: { template: TemplateItem; lang: string }) {
  const templateId = template.id;
  const { t } = useTranslation("templates");
  const revisions = useInfiniteQuery({
    ...orpc.sandboxTemplates.listRevisions.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ templateId, cursor, limit: DASHBOARD_PAGE_LIMIT }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [revisions.error]);
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <p className="text-sm font-medium">{t("revisions")}</p>
      {revisions.isError ? (
        <InlineRetry message={t("revisionsFailed")} onRetry={() => void revisions.refetch()} />
      ) : null}
      {revisions.data?.pages[0]?.items.length === 0 ? (
        <p data-no-versions="" className="text-xs text-muted-foreground">
          {t("card.noVersionsHint")}
        </p>
      ) : null}
      {revisions.data?.pages
        .flatMap((page) => page.items)
        .map((revision) => (
          <div key={revision.id} data-revision={revision.id} className="min-w-0 rounded border p-3">
            <p data-revision-label="" className="text-sm font-medium">
              {revisionLabel({ slug: template.slug, revision: revision.revision })}
              <span className="text-xs font-normal text-muted-foreground">
                {" · "}
                {revision.architecture}
              </span>
            </p>
            <p data-revision-size="" className="text-xs tabular-nums">
              {t("revisionSize", {
                cpuCount: revision.cpuCount,
                memoryMiB: revision.memoryMiB,
                defaultDiskGiB: revision.defaultDiskGiB,
              })}
            </p>
            <p data-revision-min-disk="" className="text-xs tabular-nums text-muted-foreground">
              {t("revisionMinDisk", { minDiskGiB: revision.minDiskGiB })}
            </p>
            <RevisionImageBadges revision={revision} lang={lang} />
            {template.archivedAt === null ? (
              <PublishRevisionButton revision={revision} lang={lang} />
            ) : null}
            {template.archivedAt === null && !template.communitySource ? (
              <Link
                to="/$lang/dashboard/templates/new/register"
                params={{ lang }}
                search={{ template: template.id, from: revision.id }}
                className={cn(buttonVariants({ variant: "secondary", size: "touch" }), "mt-2")}
              >
                {t("appendWithSize")}
              </Link>
            ) : null}
            <RevisionAvailability
              templateId={templateId}
              revisionId={revision.id}
              upstream={revision.sourceKind === "UPSTREAM"}
              lang={lang}
            />
            <AdvancedDetails>
              <div className="flex min-w-0 flex-col gap-1">
                <span className="text-xs text-muted-foreground">{t("revisionId")}</span>
                <CopyableId value={revision.id} label={t("revisionId")} />
              </div>
              <div data-fingerprint="" className="flex min-w-0 flex-col gap-1">
                <span className="text-xs text-muted-foreground">{t("fingerprint")}</span>
                <CopyableId value={revision.incusFingerprint} label={t("fingerprint")} />
              </div>
            </AdvancedDetails>
            {revision.retiredAt === null ? (
              <RevisionActions
                templateId={templateId}
                revisionId={revision.id}
                title={revisionLabel({ slug: template.slug, revision: revision.revision })}
                lang={lang}
                launchable={isLaunchableRevision(revision)}
                taggable={!template.communitySource}
              />
            ) : (
              <p className="text-xs">{t("usability.archived")}</p>
            )}
          </div>
        ))}
      {revisions.isPending ? <SkeletonList count={1} className="rounded-xl border" /> : null}
      <LoadMore
        hasNextPage={revisions.hasNextPage}
        isFetchingNextPage={revisions.isFetchingNextPage}
        onLoadMore={() => void revisions.fetchNextPage()}
        label={t("moreRevisions")}
      />
    </div>
  );
}

/**
 * Host evidence for one revision. An UPSTREAM pin's AVAILABLE row only says the
 * host holds the pinned community image (a build input it downloaded); it was
 * never registered, recipe-built or verified as a launchable template image, so
 * it never reads as "Verified image".
 */
function RevisionAvailability({
  templateId,
  revisionId,
  upstream,
  lang,
}: {
  templateId: string;
  revisionId: string;
  upstream: boolean;
  lang: string;
}) {
  const { t } = useTranslation("templates");
  const available = useInfiniteQuery({
    ...orpc.sandboxTemplates.listAvailability.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({
        templateId,
        revisionId,
        cursor,
        limit: DASHBOARD_PAGE_LIMIT,
      }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [available.error]);
  return (
    <div className="mt-2 flex min-w-0 flex-col gap-1">
      {available.isPending ? <SkeletonList count={1} className="rounded-xl border" /> : null}
      {available.data?.pages[0]?.items.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t(upstream ? "upstreamAvailability.none" : "noAvailability")}
        </p>
      ) : null}
      {available.isError ? (
        <InlineRetry message={t("availabilityFailed")} onRetry={() => void available.refetch()} />
      ) : null}
      {available.data?.pages.flatMap((page) =>
        page.items.map((entry) => (
          <div key={entry.id} data-availability={entry.status} className="min-w-0 text-xs">
            <p className="break-words">
              <ResourceIdentity label={entry.Host.label} slug={entry.Host.slug} />
              {" · "}
              {upstream && entry.status === "AVAILABLE" ? (
                <span data-upstream-availability="" title={t("upstreamAvailability.hint")}>
                  {t("upstreamAvailability.AVAILABLE")}
                </span>
              ) : (
                <span>{t(`availability.${entry.status}`)}</span>
              )}
            </p>
          </div>
        )),
      )}
      <LoadMore
        hasNextPage={available.hasNextPage}
        isFetchingNextPage={available.isFetchingNextPage}
        onLoadMore={() => void available.fetchNextPage()}
        label={t("moreHosts")}
      />
    </div>
  );
}

function RevisionActions({
  templateId,
  revisionId,
  title,
  lang,
  launchable,
  taggable,
}: {
  templateId: string;
  revisionId: string;
  /** `slug vN`, the revision as people read it. */
  title: string;
  lang: string;
  /** UPSTREAM pins and revisions awaiting verify: no tag, association or publish (S12). */
  launchable: boolean;
  /** Community templates refuse tag moves (`template.community_managed`). */
  taggable: boolean;
}) {
  const { t } = useTranslation(["templates", "hosts", "common"]);
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [retiring, setRetiring] = useState(false);
  const [problem, setProblem] = useState<TemplateProblem | null>(null);
  const hostId = useId();
  const [poolTarget, setPoolTarget] = useState({ poolId: "", memberId: "" });
  const redirect = useTwoFactorRedirect(lang);
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listRevisions.key() });
    void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listAvailability.key() });
    void queryClient.invalidateQueries({
      queryKey: orpc.sandboxTemplates.listRevisionChoices.key(),
    });
    setOpen(false);
    setRetiring(false);
  };
  const tag = useMutation({
    ...orpc.sandboxTemplates.setTag.mutationOptions(),
    onSuccess: refresh,
    onError: (error) => {
      if (!redirect(error)) setProblem(templateProblem(error));
    },
    meta: { skipGlobalErrorToast: true },
  });
  const associate = useMutation({
    ...orpc.sandboxTemplates.associateAvailability.mutationOptions(),
    onSuccess: refresh,
    onError: (error) => {
      if (!redirect(error)) setProblem(templateProblem(error));
    },
    meta: { skipGlobalErrorToast: true },
  });
  const retire = useMutation({
    ...orpc.sandboxTemplates.retireRevision.mutationOptions(),
    onSuccess: refresh,
    onError: (error) => {
      if (!redirect(error)) setProblem(templateProblem(error));
    },
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { tag: "latest", hostId: "" },
    validators: {
      onSubmit: z.object({
        tag: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/, t("templates:invalidTag")),
        hostId: z.string(),
      }),
    },
    onSubmit: ({ value }) => tag.mutate({ templateId, revisionId, tag: value.tag }),
  });
  const value = useStore(form.store, (state) => state.values);
  const hosts = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: HOST_PICKER_LIMIT, cursor }),
    }),
    enabled: open && launchable,
    staleTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [hosts.error]);
  const busy = tag.isPending || associate.isPending || retire.isPending;
  return (
    <>
      <Button
        type="button"
        size="touch"
        variant="secondary"
        onClick={() => {
          setProblem(null);
          setOpen(true);
        }}
      >
        {t("templates:manageRevision")}
      </Button>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent showCloseButton={false}>
          <SheetHeader>
            <SheetTitle>{t("templates:manageRevisionTitle", { revision: title })}</SheetTitle>
            <SheetDescription>{t("templates:manageRevisionDescription")}</SheetDescription>
          </SheetHeader>
          <SheetBody className="flex min-w-0 flex-col gap-4">
            <form
              className="flex min-w-0 flex-col gap-4 pb-4"
              onSubmit={(event) => {
                event.preventDefault();
                event.stopPropagation();
                void form.handleSubmit();
              }}
            >
              {launchable && taggable ? (
                <>
                  <form.Field name="tag">
                    {(field) => (
                      <TextField
                        inputClassName="min-h-11"
                        field={field}
                        autoComplete="off"
                        inputMode="text"
                        maxLength={64}
                        label={t("templates:tagLabel")}
                      />
                    )}
                  </form.Field>
                  <Button
                    type="submit"
                    size="touch"
                    disabled={busy || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(value.tag)}
                  >
                    {t("templates:setTag")}
                  </Button>
                </>
              ) : null}
              {launchable ? (
                <>
                  <PoolImageTarget {...poolTarget} onChange={setPoolTarget} />
                  <Button
                    type="button"
                    size="touch"
                    disabled={busy || !poolTarget.poolId || !poolTarget.memberId}
                    onClick={() => associate.mutate({ templateId, revisionId, ...poolTarget })}
                  >
                    {t("hosts:sharing.verifyImage")}
                  </Button>
                  <Label htmlFor={hostId}>{t("templates:form.host")}</Label>
                  <FormSelect
                    id={hostId}
                    optionsSettled={hosts.isSuccess && !hosts.isFetching && !hosts.hasNextPage}
                    autoComplete="off"
                    value={value.hostId}
                    onValueChange={(value) => form.setFieldValue("hostId", value)}
                    disabled={busy}
                  >
                    <SelectItem value="">{t("templates:form.chooseHost")}</SelectItem>
                    {registrableHosts(hosts.data?.pages.flatMap((page) => page.items) ?? []).map(
                      (host) => (
                        <SelectItem key={host.id} value={host.id}>
                          <ResourceIdentity label={host.label} slug={host.slug} />
                        </SelectItem>
                      ),
                    )}
                  </FormSelect>
                  {hosts.isPending ? (
                    <SkeletonList count={1} className="rounded-xl border" />
                  ) : null}
                  {hosts.isError ? (
                    <InlineRetry
                      message={t("templates:form.hostsFailed")}
                      onRetry={() => void hosts.refetch()}
                    />
                  ) : null}
                  <LoadMore
                    hasNextPage={hosts.hasNextPage}
                    isFetchingNextPage={hosts.isFetchingNextPage}
                    onLoadMore={() => void hosts.fetchNextPage()}
                  />
                  <Button
                    type="button"
                    size="touch"
                    disabled={
                      busy ||
                      !registrableHosts(hosts.data?.pages.flatMap((page) => page.items) ?? []).some(
                        (host) => host.id === value.hostId,
                      )
                    }
                    onClick={() =>
                      associate.mutate({ templateId, revisionId, hostId: value.hostId })
                    }
                  >
                    {t("templates:verifyAvailability")}
                  </Button>
                </>
              ) : null}
              <Button
                type="button"
                size="touch"
                variant="outline"
                disabled={busy}
                onClick={() => setRetiring(true)}
              >
                {t("templates:retireRevision")}
              </Button>
              {problem ? (
                <p role="alert" className="text-sm text-destructive">
                  {t(`templates:problem.${problem}`)}
                </p>
              ) : null}
              <Button type="button" size="touch" variant="outline" onClick={() => setOpen(false)}>
                {t("common:actions.close")}
              </Button>
            </form>
          </SheetBody>
        </SheetContent>
      </Sheet>
      <ConfirmDeleteDialog
        open={retiring}
        onOpenChange={setRetiring}
        title={t("templates:retireRevision")}
        description={t("templates:retireRevisionHint")}
        confirmToken={revisionId}
        typePrompt={t("templates:retirePrompt")}
        copyAriaLabel={t("templates:copyRevision")}
        isPending={busy}
        confirmLabel={t("templates:retireRevision")}
        onConfirm={() => retire.mutate({ id: revisionId })}
      />
    </>
  );
}
