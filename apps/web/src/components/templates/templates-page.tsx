import { useForm, useStore } from "@tanstack/react-form";
import {
  type QueryClient,
  useInfiniteQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
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
import { Button } from "@wssp/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { toast } from "@wssp/ui/components/sileo";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { Globe, Hammer, Plus } from "lucide-react";
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
import { PageHeader } from "@/components/page-shell";
import { PoolImageTarget } from "@/components/pools/pool-image-target";
import { QueryBoundary } from "@/components/query-boundary";
import { ResourceIdentity } from "@/components/resource-identity";
import { SegmentedControl } from "@/components/segmented-control";
import { SkeletonList } from "@/components/skeleton-list";
import { TemplateBuildsSection } from "@/components/template-builds/build-parts";
import { BuildTemplateDialog } from "@/components/template-builds/build-template-dialog";
import { useSubmissionFence } from "@/hooks/use-submission-fence";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { docsRepoPath, docsUrl } from "@/lib/docs-links";
import { dateTimeTitle } from "@/lib/format-date-time";
import { hostConnectionState, toMs } from "@/lib/host-status";
import { isLaunchableRevision } from "@/lib/template-build-rules";
import {
  DEFAULT_TEMPLATE_DRAFT,
  parseTemplateDraft,
  registrableHosts,
  registrationHostState,
  revisionLabel,
  TEMPLATE_ARCHITECTURES,
  TEMPLATE_GUEST_VERSION_MAX,
  TEMPLATE_LABEL_MAX,
  type TemplateDraft,
  type TemplateProblem,
  templateDraftProblems,
  templateProblem,
} from "@/lib/template-rules";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";
import {
  CommunityBadge,
  CommunityTemplateControls,
  CreateCommunityTemplateDialog,
} from "./community-template";
import {
  PublishRevisionButton,
  RevisionImageBadges,
  TemplateImageActions,
} from "./template-image-controls";

/**
 * Templates dashboard (C46): manually registered Incus VM images. A template
 * is an immutable revision pinned to the fingerprint its host resolved at
 * registration, plus the declared guest identity. The page never predicts an
 * image check — the host decides, through the server — and never shows a
 * template usable unless it is active on a connected, admitting host.
 * Archiving keeps the revision (and every sandbox's reference to it); there
 * is no image builder, upload or snapshot catalog here.
 */

/** Refetch cadence; a host turning stale is timer-driven (useRerenderAt). */
const TEMPLATES_REFETCH_MS = 15_000;
/** The registration form's host picker pages with Load more (procedure maximum per page). */
const HOST_PICKER_LIMIT = 100;

type TemplatePage = Awaited<ReturnType<AppRouterClient["sandboxTemplates"]["listTemplates"]>>;
type TemplateItem = TemplatePage["items"][number];
type StatusFilter = "active" | "retired" | "all";

const cursorPages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

function invalidateTemplates(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listTemplates.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listRevisions.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listAvailability.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listRevisionChoices.key() });
}

export function TemplatesPage({ lang }: { lang: string }) {
  const { t, i18n } = useTranslation(["templates", "dashboard", "common"]);
  const [status, setStatus] = useState<StatusFilter>("active");
  const [registering, setRegistering] = useState(false);
  const [building, setBuilding] = useState(false);
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
        description={t("templates:description")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" size="touch" onClick={() => setRegistering(true)}>
              <Plus aria-hidden="true" />
              {t("templates:register.action")}
            </Button>
            <Button
              type="button"
              size="touch"
              variant="secondary"
              onClick={() => setBuilding(true)}
            >
              <Hammer aria-hidden="true" />
              {t("templates:builds.newAction")}
            </Button>
            <Button
              type="button"
              size="touch"
              variant="secondary"
              onClick={() => setFromCommunity(true)}
            >
              <Globe aria-hidden="true" />
              {t("templates:community.action")}
            </Button>
            <Link
              to="/$lang/dashboard/templates/builds"
              params={{ lang }}
              className="inline-flex min-h-11 items-center px-2 text-sm font-medium underline underline-offset-4"
            >
              {t("templates:builds.viewAll")}
            </Link>
          </div>
        }
      />
      <RequirementsSection />
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
          />
        }
      >
        {(rows) => (
          <>
            <ul aria-label={t("templates:listRegion")} className="flex min-w-0 flex-col gap-3">
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
      {registering ? (
        <RegisterTemplateDialog lang={lang} onClose={() => setRegistering(false)} />
      ) : null}
      {building ? <BuildTemplateDialog lang={lang} onClose={() => setBuilding(false)} /> : null}
      {fromCommunity ? (
        <CreateCommunityTemplateDialog lang={lang} onClose={() => setFromCommunity(false)} />
      ) : null}
    </div>
  );
}

/** What the host checks, and where the product docs explain qualifying an image. */
function RequirementsSection() {
  const { t } = useTranslation(["templates"]);
  const items = ["image", "architecture", "agent", "identity", "tools"] as const;
  const docsHref = docsUrl(env.VITE_DOCS_URL, "templates");
  return (
    <section
      aria-labelledby="templates-requirements-title"
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id="templates-requirements-title" className="text-sm font-medium">
        {t("templates:requirements.title")}
      </h2>
      <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
        {items.map((item) => (
          <li key={item}>{t(`templates:requirements.${item}`)}</li>
        ))}
      </ul>
      <p className="text-sm text-muted-foreground">
        {t("templates:requirements.readiness")}{" "}
        {docsHref ? (
          <a
            href={docsHref}
            target="_blank"
            rel="noreferrer"
            data-docs-link=""
            className="inline-flex min-h-11 items-center font-medium underline underline-offset-4"
          >
            {t("templates:requirements.docsLink")}
          </a>
        ) : (
          <span data-docs-path="">
            {t("templates:requirements.docsPath", { path: docsRepoPath("templates") })}
          </span>
        )}
      </p>
    </section>
  );
}

function Pill({
  tone,
  children,
  ...rest
}: { tone: string; children: string } & Record<`data-${string}`, string>) {
  return (
    <span
      {...rest}
      className={cn(
        "inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium",
        tone,
      )}
    >
      {children}
    </span>
  );
}

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
  const redirect = useTwoFactorRedirect(lang);
  const [confirming, setConfirming] = useState(false);
  const [problem, setProblem] = useState<TemplateProblem | null>(null);
  const archived = template.archivedAt !== null;
  const community = template.communitySource ? { refresh: template.communityRefresh } : null;
  const usability = archived ? "archived" : "active";
  const created = toMs(template.createdAt);
  const retired = toMs(template.archivedAt);
  const [appending, setAppending] = useState(false);
  const [building, setBuilding] = useState(false);
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

  return (
    <li
      data-template-id={template.id}
      data-usability={usability}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{template.label}</p>
          <p className="truncate font-mono text-xs text-muted-foreground">{template.slug}</p>
        </div>
        {community ? <CommunityBadge /> : null}
        <Pill tone="border-border bg-muted text-muted-foreground" data-template-status={usability}>
          {t(archived ? "templates:usability.archived" : "templates:logicalActive")}
        </Pill>
      </div>
      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-2">
        <div className="min-w-0">
          <dt className="text-xs text-muted-foreground">
            {retired == null ? t("templates:fields.created") : t("templates:fields.archived")}
          </dt>
          <dd title={dateTimeTitle(retired ?? created, locale)}>
            {(retired ?? created) == null
              ? "—"
              : formatRelativeTime((retired ?? created) as number, locale, now)}
          </dd>
        </div>
      </dl>
      {community ? (
        <CommunityTemplateControls template={{ ...template, community }} lang={lang} />
      ) : null}
      <TemplateRevisionList template={template} lang={lang} />
      <TemplateBuildsSection templateId={template.id} lang={lang} />
      {building ? (
        <BuildTemplateDialog
          lang={lang}
          template={{ id: template.id, label: template.label }}
          onClose={() => setBuilding(false)}
        />
      ) : null}
      {appending ? (
        <RegisterTemplateDialog
          lang={lang}
          logical={template}
          onClose={() => setAppending(false)}
        />
      ) : null}
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`templates:problem.${problem}`)}
        </p>
      ) : null}
      {archived ? null : (
        <div className="flex flex-wrap gap-2">
          {/* A community template is wssp-managed: only Refresh now and Try again write it. */}
          {community ? null : (
            <>
              <Button
                type="button"
                size="touch"
                variant="secondary"
                onClick={() => setAppending(true)}
              >
                {t("templates:appendRevision")}
              </Button>
              <Button
                type="button"
                size="touch"
                variant="secondary"
                onClick={() => setBuilding(true)}
              >
                <Hammer aria-hidden="true" />
                {t("templates:builds.action")}
              </Button>
            </>
          )}
          <TemplateImageActions template={template} lang={lang} />
          <Button
            type="button"
            variant="destructive"
            size="touch"
            disabled={archive.isPending}
            onClick={() => setConfirming(true)}
          >
            {t("templates:archive.action")}
          </Button>
        </div>
      )}
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("templates:archive.title", { label: template.label })}
            </AlertDialogTitle>
            <AlertDialogDescription>{t("templates:archive.description")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="sm:flex-wrap">
            <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
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

type Registered = { label: string; revision: string };

function RegisterTemplateDialog({
  lang,
  logical,
  initialSize,
  onClose: close,
}: {
  lang: string;
  logical?: TemplateItem;
  initialSize?: { cpuCount: number; memoryMiB: number; defaultDiskGiB: number; minDiskGiB: number };
  onClose: () => void;
}) {
  const { t } = useTranslation(["templates", "hosts", "common"]);
  // Submitting may await a host refetch; closing meanwhile must not register.
  const fence = useSubmissionFence();
  const onClose = () => {
    fence.cancel();
    close();
  };
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const hostSelectId = useId();
  const architectureId = useId();
  const [poolTarget, setPoolTarget] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [problem, setProblem] = useState<TemplateProblem | null>(null);
  const [registered, setRegistered] = useState<Registered | null>(null);
  const hostsQuery = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: HOST_PICKER_LIMIT, cursor }),
    }),
    // Readiness comes from heartbeats: a picker left open (or reopened from
    // the cache) must not judge a live host by an old heartbeat.
    staleTime: 0,
    refetchInterval: TEMPLATES_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = registrableHosts(hostsQuery.data?.pages.flatMap((page) => page.items) ?? []);
  const register = useMutation({
    gcTime: 0,
    mutationFn: async (input: ReturnType<typeof parseTemplateDraft>): Promise<Registered> => {
      if (!logical) {
        const created = await orpc.sandboxTemplates.createTemplate.call(input);
        // A new template's first revision is v1.
        return {
          label: created.label,
          revision: revisionLabel({ slug: created.slug, revision: 1 }),
        };
      }
      const { slug: _slug, label: _label, ...revision } = input;
      const created = await orpc.sandboxTemplates.appendRevision.call({
        ...revision,
        templateId: logical.id,
      });
      return {
        label: logical.label,
        revision: revisionLabel({ slug: logical.slug, revision: created.revision }),
      };
    },
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      setProblem(null);
    },
    onSuccess: (template) => {
      form.setFieldValue("envs", "");
      register.reset();
      setRegistered(template);
      toast.success(t("templates:register.done", { label: template.label }));
    },
    onError: (error) => {
      const next = templateProblem(error);
      if (next !== "generic") {
        form.setFieldValue("envs", "");
        register.reset();
      }
      if (redirect(error)) return;
      setProblem(next);
      // The host's state changed under the form: show the current picture.
      if (next === "hostUnavailable" || next === "hostDraining" || next === "hostDeleting")
        void hostsQuery.refetch();
    },
    onSettled: () => invalidateTemplates(queryClient),
  });
  const draftValidator = z
    .custom<TemplateDraft & { poolId: string; memberId: string }>()
    .superRefine((draft, context) => {
      for (const issue of templateDraftProblems(draft, hosts, Date.now())) {
        // Refresh transient host evidence in onSubmit before refusing it.
        if (issue !== "hostUnavailable" && issue !== "hostDraining")
          context.addIssue({
            code: "custom",
            message: t(
              poolTarget && issue === "imageRef"
                ? "templates:draft.poolImageRef"
                : poolTarget && issue === "noHost"
                  ? "templates:draft.noPoolMember"
                  : `templates:draft.${issue}`,
            ),
          });
      }
    });
  const form = useForm({
    defaultValues: {
      ...DEFAULT_TEMPLATE_DRAFT,
      poolId: "",
      memberId: "",
      ...(logical ? { slug: logical.slug, label: logical.label } : {}),
      ...(initialSize
        ? {
            cpuCount: String(initialSize.cpuCount),
            memoryMiB: String(initialSize.memoryMiB),
            defaultDiskGiB: String(initialSize.defaultDiskGiB),
            minDiskGiB: String(initialSize.minDiskGiB),
          }
        : {}),
    },
    validators: { onChange: draftValidator, onSubmit: draftValidator },
    onSubmit: async ({ value }) => {
      const stillCurrent = fence.begin();
      setAttempted(true);
      let current = hosts;
      const blocked = (list: typeof hosts) =>
        templateDraftProblems(value, list, Date.now()).some(
          (item) => item === "hostUnavailable" || item === "hostDraining",
        );
      // Never refuse a host on a cached reading: confirm with a fresh one.
      if (blocked(current)) {
        const fresh = await hostsQuery.refetch();
        if (!stillCurrent()) return;
        current = registrableHosts(fresh.data?.pages.flatMap((page) => page.items) ?? []);
      }
      if (templateDraftProblems(value, current, Date.now()).length > 0) return;
      register.mutate(parseTemplateDraft(value));
    },
  });
  const values = useStore(form.store, (state) => state.values);
  const problems = attempted ? templateDraftProblems(values, hosts, Date.now()) : [];
  const selectedHost = hosts.find((host) => host.id === values.hostId);

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>{t("templates:register.title")}</DialogTitle>
          <DialogDescription>{t("templates:register.description")}</DialogDescription>
        </DialogHeader>
        {registered ? (
          <section
            aria-label={t("templates:register.resultLabel")}
            data-registered=""
            className="flex min-w-0 flex-col gap-3 rounded-md border bg-muted/40 p-3"
          >
            <p role="status" className="text-sm font-medium">
              {t("templates:register.resultTitle", { label: registered.label })}
            </p>
            <p data-registered-revision="" className="text-sm">
              {registered.revision}
            </p>
            <p className="text-sm text-muted-foreground">{t("templates:register.resultHint")}</p>
            <Button type="button" size="touch" onClick={onClose}>
              {t("templates:register.close")}
            </Button>
          </section>
        ) : (
          <form
            noValidate
            className="flex min-w-0 flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              event.stopPropagation();
              setAttempted(true);
              void form.handleSubmit();
            }}
          >
            <label className="flex min-h-11 items-center gap-3">
              <input
                type="checkbox"
                autoComplete="off"
                checked={poolTarget}
                onChange={(e) => {
                  setPoolTarget(e.target.checked);
                  form.setFieldValue("hostId", "");
                  form.setFieldValue("poolId", "");
                  form.setFieldValue("memberId", "");
                }}
              />
              {t("hosts:sharing.imageTarget")}
            </label>
            {poolTarget ? (
              <PoolImageTarget
                poolId={values.poolId}
                memberId={values.memberId}
                onChange={(target) => {
                  form.setFieldValue("poolId", target.poolId);
                  form.setFieldValue("memberId", target.memberId);
                }}
              />
            ) : (
              <fieldset className="flex min-w-0 flex-col gap-2" disabled={register.isPending}>
                <Label htmlFor={hostSelectId}>{t("templates:form.host")}</Label>
                {hostsQuery.isError ? (
                  <InlineRetry
                    variant="destructive"
                    message={t("templates:form.hostsFailed")}
                    onRetry={() => void hostsQuery.refetch()}
                  />
                ) : hostsQuery.isPending ? (
                  <SkeletonList count={1} className="rounded-xl border" />
                ) : hosts.length === 0 ? (
                  <p className="text-sm text-muted-foreground">{t("templates:form.noHosts")}</p>
                ) : (
                  <form.Field name="hostId">
                    {(field) => (
                      <FormSelect
                        id={hostSelectId}
                        optionsSettled={
                          hostsQuery.isSuccess && !hostsQuery.isFetching && !hostsQuery.hasNextPage
                        }
                        autoComplete="off"
                        value={field.state.value}
                        onValueChange={(value) => field.handleChange(value)}
                      >
                        <SelectItem value="">{t("templates:form.chooseHost")}</SelectItem>
                        {hosts.map((host) => (
                          <SelectItem key={host.id} value={host.id}>
                            {translateText(t, "templates:form.hostOption", {
                              label: host.label,
                              slug: host.slug,
                              state: t(
                                `templates:form.hostState.${registrationHostState(host, Date.now())}`,
                              ),
                            })}
                          </SelectItem>
                        ))}
                      </FormSelect>
                    )}
                  </form.Field>
                )}
                <LoadMore
                  hasNextPage={hostsQuery.hasNextPage}
                  isFetchingNextPage={hostsQuery.isFetchingNextPage}
                  onLoadMore={() => void hostsQuery.fetchNextPage()}
                  label={t("templates:form.moreHosts")}
                />
                {selectedHost && registrationHostState(selectedHost, Date.now()) !== "ready" ? (
                  <p className="text-xs text-muted-foreground">
                    {t(
                      `templates:form.hostStateHint.${registrationHostState(selectedHost, Date.now())}`,
                      {
                        state: t(`hosts:status.${hostConnectionState(selectedHost, Date.now())}`),
                      },
                    )}
                  </p>
                ) : null}
              </fieldset>
            )}
            <fieldset className="flex min-w-0 flex-col gap-4" disabled={register.isPending}>
              <form.Field name="label">
                {(field) => (
                  <TextField
                    inputClassName="min-h-11"
                    field={field}
                    label={t("templates:form.label")}
                    disabled={Boolean(logical)}
                    autoComplete="off"
                    inputMode="text"
                    maxLength={TEMPLATE_LABEL_MAX}
                  />
                )}
              </form.Field>
              <form.Field name="slug">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("templates:form.slug")}
                    disabled={Boolean(logical)}
                    description={t("templates:form.slugHint")}
                    autoComplete="off"
                    inputMode="url"
                    maxLength={63}
                    inputClassName="min-h-11 font-mono"
                  />
                )}
              </form.Field>
              <form.Field name="imageRef">
                {(field) => (
                  <TextField
                    field={field}
                    label={t(
                      poolTarget ? "templates:form.poolImageRef" : "templates:form.imageRef",
                    )}
                    description={t(
                      poolTarget
                        ? "templates:form.poolImageRefHint"
                        : "templates:form.imageRefHint",
                    )}
                    autoComplete="off"
                    inputMode="url"
                    maxLength={128}
                    inputClassName="min-h-11 font-mono"
                  />
                )}
              </form.Field>
              <p className="text-xs text-muted-foreground">{t("templates:form.sizeHint")}</p>
              <div className="grid min-w-0 gap-3 sm:grid-cols-2">
                <form.Field name="cpuCount">
                  {(field) => (
                    <TextField
                      field={field}
                      label={t("templates:form.cpuCount")}
                      type="number"
                      inputMode="numeric"
                      min={1}
                      max={32}
                      step={1}
                      autoComplete="off"
                      inputClassName="min-h-11"
                    />
                  )}
                </form.Field>
                <form.Field name="memoryMiB">
                  {(field) => (
                    <TextField
                      field={field}
                      label={t("templates:form.memoryMiB")}
                      type="number"
                      inputMode="numeric"
                      min={512}
                      max={65536}
                      step={256}
                      autoComplete="off"
                      inputClassName="min-h-11"
                    />
                  )}
                </form.Field>
                <form.Field name="defaultDiskGiB">
                  {(field) => (
                    <TextField
                      field={field}
                      label={t("templates:form.defaultDiskGiB")}
                      type="number"
                      inputMode="numeric"
                      min={VM_SIZE_LIMITS.diskGiBMin}
                      max={VM_SIZE_LIMITS.diskGiBMax}
                      step={1}
                      autoComplete="off"
                      inputClassName="min-h-11"
                    />
                  )}
                </form.Field>
                <form.Field name="minDiskGiB">
                  {(field) => (
                    <TextField
                      field={field}
                      label={t("templates:form.minDiskGiB")}
                      type="number"
                      inputMode="numeric"
                      min={VM_SIZE_LIMITS.diskGiBMin}
                      max={VM_SIZE_LIMITS.diskGiBMax}
                      step={1}
                      autoComplete="off"
                      inputClassName="min-h-11"
                    />
                  )}
                </form.Field>
              </div>
              <form.Field name="architecture">
                {(field) => (
                  <div className="flex min-w-0 flex-col gap-2">
                    <Label htmlFor={architectureId}>{t("templates:form.architecture")}</Label>
                    <FormSelect
                      id={architectureId}
                      autoComplete="off"
                      value={field.state.value}
                      onValueChange={(value) => field.handleChange(value)}
                      className="font-mono"
                    >
                      {TEMPLATE_ARCHITECTURES.map((architecture) => (
                        <SelectItem key={architecture} value={architecture}>
                          {architecture}
                        </SelectItem>
                      ))}
                    </FormSelect>
                  </div>
                )}
              </form.Field>
              <form.Field name="envs">
                {(field) => (
                  <TextareaField
                    field={field}
                    label={t("templates:form.envs")}
                    description={t("templates:form.envsHint")}
                    autoComplete="off"
                    rows={3}
                    maxLength={65_536}
                    inputClassName="font-mono"
                    disabled={register.isPending}
                  />
                )}
              </form.Field>
              <fieldset className="flex min-w-0 flex-col gap-3 rounded-lg border bg-card p-3">
                <legend className="px-1 text-sm font-medium">{t("templates:form.guest")}</legend>
                <p className="text-xs text-muted-foreground">{t("templates:form.guestHint")}</p>
                <div className="grid min-w-0 gap-3 sm:grid-cols-2">
                  <form.Field name="guestUid">
                    {(field) => (
                      <TextField
                        inputClassName="min-h-11"
                        field={field}
                        label={t("templates:form.guestUid")}
                        autoComplete="off"
                        inputMode="numeric"
                      />
                    )}
                  </form.Field>
                  <form.Field name="guestGid">
                    {(field) => (
                      <TextField
                        inputClassName="min-h-11"
                        field={field}
                        label={t("templates:form.guestGid")}
                        autoComplete="off"
                        inputMode="numeric"
                      />
                    )}
                  </form.Field>
                </div>
                <form.Field name="guestHome">
                  {(field) => (
                    <TextField
                      field={field}
                      label={t("templates:form.guestHome")}
                      autoComplete="off"
                      inputMode="url"
                      inputClassName="min-h-11 font-mono"
                    />
                  )}
                </form.Field>
                <form.Field name="guestShell">
                  {(field) => (
                    <TextField
                      field={field}
                      label={t("templates:form.guestShell")}
                      autoComplete="off"
                      inputMode="url"
                      inputClassName="min-h-11 font-mono"
                    />
                  )}
                </form.Field>
                <form.Field name="guestVersion">
                  {(field) => (
                    <TextField
                      inputClassName="min-h-11"
                      field={field}
                      label={t("templates:form.guestVersion")}
                      description={t("templates:form.guestVersionHint")}
                      autoComplete="off"
                      inputMode="text"
                      maxLength={TEMPLATE_GUEST_VERSION_MAX}
                    />
                  )}
                </form.Field>
              </fieldset>
            </fieldset>
            {problems.length > 0 ? (
              <ul role="alert" className="list-disc pl-5 text-sm text-destructive">
                {problems.map((item) => (
                  <li key={item} data-draft-problem={item}>
                    {t(
                      poolTarget && item === "imageRef"
                        ? "templates:draft.poolImageRef"
                        : poolTarget && item === "noHost"
                          ? "templates:draft.noPoolMember"
                          : `templates:draft.${item}`,
                    )}
                  </li>
                ))}
              </ul>
            ) : null}
            {register.isPending ? (
              <p role="status" data-image-check="pending" className="text-sm text-muted-foreground">
                {t("templates:register.checking", {
                  host: selectedHost?.label ?? values.hostId,
                })}
              </p>
            ) : null}
            {problem ? (
              <div role="alert" data-image-check="failed" className="text-sm text-destructive">
                <p>{t(`templates:problem.${problem}`)}</p>
              </div>
            ) : null}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" size="touch" disabled={register.isPending}>
                {register.isPending
                  ? t("templates:register.pending")
                  : t("templates:register.submit")}
              </Button>
              <Button type="button" variant="outline" size="touch" onClick={onClose}>
                {t("common:actions.cancel")}
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function TemplateRevisionList({ template, lang }: { template: TemplateItem; lang: string }) {
  const templateId = template.id;
  const [prefill, setPrefill] = useState<{
    cpuCount: number;
    memoryMiB: number;
    defaultDiskGiB: number;
    minDiskGiB: number;
  } | null>(null);
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
            <PublishRevisionButton revision={revision} lang={lang} />
            {template.archivedAt === null && !template.communitySource ? (
              <Button
                type="button"
                size="touch"
                variant="secondary"
                className="mt-2"
                onClick={() =>
                  setPrefill({
                    cpuCount: revision.cpuCount,
                    memoryMiB: revision.memoryMiB,
                    defaultDiskGiB: revision.defaultDiskGiB,
                    minDiskGiB: revision.minDiskGiB,
                  })
                }
              >
                {t("appendWithSize")}
              </Button>
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
      {prefill ? (
        <RegisterTemplateDialog
          lang={lang}
          logical={template}
          initialSize={prefill}
          onClose={() => setPrefill(null)}
        />
      ) : null}
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
        <SheetContent showCloseButton={false} className="overflow-x-hidden overflow-y-auto">
          <SheetHeader>
            <SheetTitle>{t("templates:manageRevisionTitle", { revision: title })}</SheetTitle>
            <SheetDescription>{t("templates:manageRevisionDescription")}</SheetDescription>
          </SheetHeader>
          <form
            className="flex min-w-0 flex-col gap-4 p-4"
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
                {hosts.isPending ? <SkeletonList count={1} className="rounded-xl border" /> : null}
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
                  onClick={() => associate.mutate({ templateId, revisionId, hostId: value.hostId })}
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
