import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { AdvancedSection, FormPage, FormSection } from "@wssp/ui/components/form-page";
import {
  hasKeyValueErrors,
  KeyValueEditor,
  type KeyValueEntry,
} from "@wssp/ui/components/key-value-editor";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { toast } from "@wssp/ui/components/sileo";
import { FieldError, TextField } from "@wssp/ui/components/text-field";
import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { ArrowLeft } from "lucide-react";
import { type ReactNode, useId, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { useTranslation } from "react-i18next";
import { FormPageStatus } from "@/components/form-page-status";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { PoolImageTarget } from "@/components/pools/pool-image-target";
import { SegmentedControl } from "@/components/segmented-control";
import { SkeletonList } from "@/components/skeleton-list";
import { useKeyValueEditorLabels } from "@/hooks/use-form-field-labels";
import { useSubmissionFence } from "@/hooks/use-submission-fence";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { hostConnectionState } from "@/lib/host-status";
import { entriesToRecord, PROTOTYPE_NAMES, stateField } from "@/lib/key-value-entries";
import { isQueryAccessError } from "@/lib/query-access-error";
import {
  DEFAULT_TEMPLATE_DRAFT,
  envRowsToDraft,
  parseTemplateDraft,
  RESERVED_DEFAULT_ENV,
  registrableHosts,
  registrationHostState,
  revisionLabel,
  slugFromName,
  TEMPLATE_ARCHITECTURES,
  TEMPLATE_GUEST_VERSION_MAX,
  TEMPLATE_LABEL_MAX,
  type TemplateDraft,
  type TemplateDraftProblem,
  type TemplateProblem,
  templateDraftProblems,
  templateProblem,
} from "@/lib/template-rules";
import { withFieldError } from "@/lib/with-field-error";
import { orpc } from "@/utils/orpc";
import { invalidateTemplates } from "./template-queries";

/** Env names a template's stored defaults may not use (the server refuses them). */
const ENV_RESERVED = [...RESERVED_DEFAULT_ENV, ...PROTOTYPE_NAMES];

/**
 * Register an existing image (C46), as a page: the host looks the image up in
 * its local Incus store and reports its fingerprint and architecture; nothing
 * is downloaded or built. Essential fields first (where the image is, the
 * image, a name); the slug is derived from the name until edited, and size,
 * environment, guest user and image details sit in collapsed sections with a
 * summary of their current values. With `templateId` it adds a version to
 * that template; `fromRevisionId` prefills that version's default size.
 */

/** Refetch cadence of the host picker (readiness comes from heartbeats). */
const HOSTS_REFETCH_MS = 15_000;
/** The host picker pages with Load more (procedure maximum per page). */
const HOST_PICKER_LIMIT = 100;

type Size = { cpuCount: number; memoryMiB: number; defaultDiskGiB: number; minDiskGiB: number };
type Logical = { id: string; slug: string; label: string };
type Registered = { label: string; revision: string };

export function RegisterTemplatePage({
  lang,
  templateId,
  fromRevisionId,
}: {
  lang: string;
  templateId?: string;
  fromRevisionId?: string;
}) {
  const { t } = useTranslation(["templates", "common"]);
  const template = useQuery({
    ...orpc.sandboxTemplates.getTemplate.queryOptions({ input: { id: templateId ?? "" } }),
    enabled: templateId !== undefined,
    meta: { skipGlobalErrorToast: true },
  });
  const from = useQuery({
    ...orpc.sandboxTemplates.getTemplateRevision.queryOptions({
      input: { id: fromRevisionId ?? "" },
    }),
    enabled: fromRevisionId !== undefined,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [template.error, from.error]);
  const loading =
    (templateId !== undefined && template.isPending) ||
    (fromRevisionId !== undefined && from.isPending);
  if (loading)
    return (
      <section className="flex min-w-0 flex-col gap-6">
        <BackLink lang={lang} />
        <SkeletonList count={3} className="rounded-xl border" />
      </section>
    );
  // A failed background refetch keeps the form (and its draft) with a retry
  // above it; an access or not-found error hides the template.
  if (
    templateId !== undefined &&
    (template.data === undefined ||
      template.data.archivedAt ||
      (template.isError && isQueryAccessError(template.error)))
  )
    return (
      <section className="flex min-w-0 flex-col gap-6">
        <BackLink lang={lang} />
        <InlineRetry
          message={t("templates:registerPage.templateFailed")}
          onRetry={() => void template.refetch()}
        />
      </section>
    );
  const size =
    from.data && from.data.templateId === templateId
      ? {
          cpuCount: from.data.cpuCount,
          memoryMiB: from.data.memoryMiB,
          defaultDiskGiB: from.data.defaultDiskGiB,
          minDiskGiB: from.data.minDiskGiB,
        }
      : undefined;
  return (
    <RegisterTemplateForm
      lang={lang}
      logical={template.data ? template.data : undefined}
      initialSize={size}
      notice={
        template.isError ? (
          <InlineRetry
            variant="destructive"
            message={t("templates:registerPage.templateFailed")}
            onRetry={() => void template.refetch()}
          />
        ) : null
      }
    />
  );
}

function BackLink({ lang }: { lang: string }) {
  const { t } = useTranslation(["templates"]);
  return (
    <Link
      to="/$lang/dashboard/templates"
      params={{ lang }}
      className="inline-flex min-h-11 items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft aria-hidden="true" className="size-4" />
      {t("templates:registerPage.back")}
    </Link>
  );
}

const HOST_PROBLEMS: readonly TemplateDraftProblem[] = [
  "noHost",
  "unknownHost",
  "hostUnavailable",
  "hostDraining",
];

function RegisterTemplateForm({
  lang,
  logical,
  initialSize,
  notice,
}: {
  lang: string;
  logical?: Logical;
  initialSize?: Size;
  /** Shown above the sections (a failed template refetch's retry). */
  notice?: ReactNode;
}) {
  const { t } = useTranslation(["templates", "hosts", "common"]);
  const editorLabels = useKeyValueEditorLabels();
  const kvLabels = useMemo(
    () => ({ ...editorLabels, add: t("templates:registerPage.addVariable") }),
    [editorLabels, t],
  );
  // Submitting may await a host refetch; leaving meanwhile must not register.
  const fence = useSubmissionFence();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const hostSelectId = useId();
  const hostErrorId = useId();
  const architectureId = useId();
  const formRef = useRef<HTMLFormElement>(null);
  const [poolTarget, setPoolTarget] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [slugEdited, setSlugEdited] = useState(false);
  const [envRows, setEnvRows] = useState<KeyValueEntry[]>([]);
  // Bumped to remount the editor (and drop its .env text) when values are cleared.
  const [envEpoch, setEnvEpoch] = useState(0);
  const [problem, setProblem] = useState<TemplateProblem | null>(null);
  const [registered, setRegistered] = useState<Registered | null>(null);
  const hostsQuery = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
      input: (cursor: string | undefined) => ({ limit: HOST_PICKER_LIMIT, cursor }),
    }),
    // A picker left open must not judge a live host by an old heartbeat.
    staleTime: 0,
    refetchInterval: HOSTS_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = registrableHosts(hostsQuery.data?.pages.flatMap((page) => page.items) ?? []);
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
    } as TemplateDraft & { poolId: string; memberId: string },
  });
  const values = useStore(form.store, (state) => state.values);
  // Flagged rows and `.env` lines that did not parse (kept as flagged rows,
  // never sent) both refuse the draft.
  const envInvalid = hasKeyValueErrors(envRows, { reservedKeys: ENV_RESERVED });
  const register = useMutation({
    gcTime: 0,
    mutationFn: async (input: ReturnType<typeof parseTemplateDraft>): Promise<Registered> => {
      if (!logical) {
        const created = await orpc.sandboxTemplates.createTemplate.call(input);
        // A new template's first version is v1.
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
    onMutate: () => setProblem(null),
    onSuccess: (result) => {
      // Private defaults leave the page once they are sent.
      clearEnv();
      register.reset();
      setRegistered(result);
      toast.success(t("templates:register.done", { label: result.label }));
    },
    onError: (error) => {
      const next = templateProblem(error);
      // A definite refusal: the private values leave the form and the mutation.
      if (next !== "generic") {
        clearEnv();
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

  const problems = attempted ? templateDraftProblems(values, hosts, Date.now()) : [];
  const problemText = (item: TemplateDraftProblem) =>
    t(
      poolTarget && item === "imageRef"
        ? "templates:draft.poolImageRef"
        : poolTarget && item === "noHost"
          ? "templates:draft.noPoolMember"
          : `templates:draft.${item}`,
    );
  const errorFor = (item: TemplateDraftProblem) =>
    problems.includes(item) ? problemText(item) : null;
  const hostProblem = problems.find((item) => HOST_PROBLEMS.includes(item)) ?? null;
  const selectedHost = hosts.find((host) => host.id === values.hostId);
  const envCount = Object.keys(entriesToRecord(envRows)).length;

  const setLabel = (label: string) => {
    form.setFieldValue("label", label);
    if (!logical && !slugEdited) form.setFieldValue("slug", slugFromName(label));
  };
  function clearEnv() {
    setEnvRows([]);
    form.setFieldValue("envs", "");
    setEnvEpoch((epoch) => epoch + 1);
  }
  const setEnv = (entries: KeyValueEntry[]) => {
    setEnvRows(entries);
    form.setFieldValue("envs", envRowsToDraft(entriesToRecord(entries)));
  };
  const submit = async () => {
    flushSync(() => setAttempted(true));
    const stillCurrent = fence.begin();
    const value = form.state.values;
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
    if (templateDraftProblems(value, current, Date.now()).length > 0 || envInvalid) {
      focusFirstInvalidField(formRef.current);
      return;
    }
    register.mutate(parseTemplateDraft(value));
  };

  if (registered)
    return (
      <section
        aria-label={t("templates:register.resultLabel")}
        data-registered=""
        className="flex min-w-0 flex-col gap-4"
      >
        <BackLink lang={lang} />
        <div role="status" className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4">
          <h1 className="text-xl font-semibold">
            {t("templates:register.resultTitle", { label: registered.label })}
          </h1>
          <p data-registered-revision="" className="text-sm">
            {registered.revision}
          </p>
          <p className="text-sm text-muted-foreground">{t("templates:register.resultHint")}</p>
          <div className="flex flex-wrap gap-2">
            <Link
              to="/$lang/dashboard/templates"
              params={{ lang }}
              className={buttonVariants({ size: "touch" })}
            >
              {t("templates:registerPage.openTemplates")}
            </Link>
            <Link
              to="/$lang/dashboard/sandboxes"
              params={{ lang }}
              className={buttonVariants({ size: "touch", variant: "outline" })}
            >
              {t("templates:registerPage.startSandbox")}
            </Link>
          </div>
        </div>
      </section>
    );

  const guestSummary = t("templates:registerPage.summary.guest", {
    uid: values.guestUid,
    gid: values.guestGid,
    home: values.guestHome,
    shell: values.guestShell,
  });
  const sizeSummary = t("templates:registerPage.summary.size", {
    cpu: values.cpuCount,
    memory: values.memoryMiB,
    disk: values.defaultDiskGiB,
  });
  const detailsSummary = t("templates:registerPage.summary.details", {
    architecture: values.architecture,
    slug: values.slug || "—",
  });
  const hostName = poolTarget ? null : (selectedHost?.label ?? null);

  const pageTitle = logical
    ? t("templates:registerPage.titleVersion", { label: logical.label })
    : t("templates:registerPage.titleNew");
  return (
    <FormPage
      ref={formRef}
      noValidate
      // Inside the dashboard frame, which already pads the content column.
      className="px-0 pt-0"
      title={pageTitle}
      aria-label={pageTitle}
      description={t("templates:registerPage.description")}
      back={<BackLink lang={lang} />}
      onSubmit={(event) => {
        event.preventDefault();
        event.stopPropagation();
        void submit();
      }}
      actions={
        <>
          <FormPageStatus>
            {register.isPending ? (
              <span role="status" data-image-check="pending">
                {t("templates:register.checking", { host: selectedHost?.label ?? values.hostId })}
              </span>
            ) : problem ? (
              <span role="alert" data-image-check="failed" className="text-destructive">
                {t(`templates:problem.${problem}`)}
              </span>
            ) : hostName ? (
              t("templates:registerPage.statusHost", { host: hostName })
            ) : (
              t("templates:registerPage.status")
            )}
          </FormPageStatus>
          <Button
            type="button"
            size="touch"
            variant="outline"
            onClick={() => {
              fence.cancel();
              void navigate({ to: "/$lang/dashboard/templates", params: { lang } });
            }}
          >
            {t("common:actions.cancel")}
          </Button>
          <Button type="submit" size="touch" disabled={register.isPending}>
            {register.isPending ? t("templates:register.pending") : t("templates:register.submit")}
          </Button>
        </>
      }
    >
      {notice}
      <fieldset className="min-w-0 space-y-8" disabled={register.isPending}>
        <FormSection
          title={t("templates:registerPage.where")}
          description={t("templates:registerPage.whereHint")}
          gridClassName="lg:grid-cols-1"
        >
          <SegmentedControl
            value={poolTarget ? "pool" : "host"}
            ariaLabel={t("templates:registerPage.where")}
            onChange={(next) => {
              setPoolTarget(next === "pool");
              form.setFieldValue("hostId", "");
              form.setFieldValue("poolId", "");
              form.setFieldValue("memberId", "");
            }}
            items={[
              { value: "host", label: t("templates:registerPage.whereHost") },
              { value: "pool", label: t("templates:registerPage.wherePool") },
            ]}
          />
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
            <div className="flex min-w-0 flex-col gap-2">
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
                <FormSelect
                  id={hostSelectId}
                  optionsSettled={
                    hostsQuery.isSuccess && !hostsQuery.isFetching && !hostsQuery.hasNextPage
                  }
                  autoComplete="off"
                  aria-invalid={hostProblem ? true : undefined}
                  aria-describedby={hostProblem ? hostErrorId : undefined}
                  value={values.hostId}
                  onValueChange={(value) => form.setFieldValue("hostId", value)}
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
                    { state: t(`hosts:status.${hostConnectionState(selectedHost, Date.now())}`) },
                  )}
                </p>
              ) : null}
            </div>
          )}
          {hostProblem ? (
            <p
              id={hostErrorId}
              role="alert"
              data-draft-problem={hostProblem}
              className="text-sm text-destructive"
            >
              {problemText(hostProblem)}
            </p>
          ) : null}
          <form.Field name="imageRef">
            {(field) => (
              <TextField
                field={withFieldError(field, errorFor("imageRef"))}
                label={t(poolTarget ? "templates:form.poolImageRef" : "templates:form.imageRef")}
                description={t(
                  poolTarget ? "templates:form.poolImageRefHint" : "templates:form.imageRefHint",
                )}
                autoComplete="off"
                inputMode="url"
                maxLength={128}
                inputClassName="min-h-11 font-mono"
              />
            )}
          </form.Field>
        </FormSection>
        <FormSection
          title={t("templates:registerPage.name")}
          description={
            logical
              ? t("templates:registerPage.versionOf", { label: logical.label, slug: logical.slug })
              : t("templates:registerPage.nameHint")
          }
        >
          {logical ? (
            <p className="text-sm font-medium">{logical.label}</p>
          ) : (
            <form.Field name="label">
              {(field) => (
                <TextField
                  field={withFieldError(field, errorFor("label"), setLabel)}
                  label={t("templates:form.label")}
                  autoComplete="off"
                  inputMode="text"
                  maxLength={TEMPLATE_LABEL_MAX}
                  inputClassName="min-h-11"
                />
              )}
            </form.Field>
          )}
        </FormSection>
        <FormSection
          title={t("templates:registerPage.advanced")}
          description={t("templates:registerPage.advancedHint")}
          gridClassName="lg:grid-cols-1"
        >
          {/* One cell: the sections join into one ruled list. */}
          <div className="min-w-0 space-y-8">
            <AdvancedSection
              gridClassName="lg:grid-cols-1"
              title={t("templates:registerPage.sections.size")}
              summary={sizeSummary}
              data-advanced="size"
            >
              <p className="text-xs text-muted-foreground">{t("templates:form.sizeHint")}</p>
              <div className="grid min-w-0 gap-3 sm:grid-cols-2">
                <form.Field name="cpuCount">
                  {(field) => (
                    <TextField
                      field={withFieldError(field, errorFor("cpuCount"))}
                      label={t("templates:form.cpuCount")}
                      type="number"
                      inputMode="numeric"
                      min={VM_SIZE_LIMITS.cpuCountMin}
                      max={VM_SIZE_LIMITS.cpuCountMax}
                      step={1}
                      autoComplete="off"
                      inputClassName="min-h-11"
                    />
                  )}
                </form.Field>
                <form.Field name="memoryMiB">
                  {(field) => (
                    <TextField
                      field={withFieldError(field, errorFor("memoryMiB"))}
                      label={t("templates:form.memoryMiB")}
                      type="number"
                      inputMode="numeric"
                      min={VM_SIZE_LIMITS.memoryMiBMin}
                      max={VM_SIZE_LIMITS.memoryMiBMax}
                      step={VM_SIZE_LIMITS.memoryMiBStep}
                      autoComplete="off"
                      inputClassName="min-h-11"
                    />
                  )}
                </form.Field>
                <form.Field name="defaultDiskGiB">
                  {(field) => (
                    <TextField
                      field={withFieldError(field, errorFor("defaultDiskGiB"))}
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
                      field={withFieldError(field, errorFor("minDiskGiB"))}
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
            </AdvancedSection>
            <AdvancedSection
              gridClassName="lg:grid-cols-1"
              title={t("templates:registerPage.sections.env")}
              summary={
                envCount === 0
                  ? t("templates:registerPage.summary.envNone")
                  : t("templates:registerPage.summary.env", { count: envCount })
              }
              data-advanced="env"
            >
              <KeyValueEditor
                key={envEpoch}
                field={stateField(
                  "envs",
                  envRows,
                  // The draft's own check, once the rows themselves are clean.
                  envInvalid ? [] : [errorFor("envs")].filter((item) => item !== null),
                  setEnv,
                )}
                label={t("templates:registerPage.envLabel")}
                description={t("templates:registerPage.envHint")}
                labels={kvLabels}
                reservedKeys={ENV_RESERVED}
                secret
              />
            </AdvancedSection>
            <AdvancedSection
              gridClassName="lg:grid-cols-1"
              title={t("templates:registerPage.sections.guest")}
              summary={guestSummary}
              data-advanced="guest"
            >
              <p className="text-xs text-muted-foreground">{t("templates:form.guestHint")}</p>
              <div className="grid min-w-0 gap-3 sm:grid-cols-2">
                <form.Field name="guestUid">
                  {(field) => (
                    <TextField
                      field={withFieldError(field, errorFor("guestUid"))}
                      label={t("templates:form.guestUid")}
                      autoComplete="off"
                      inputMode="numeric"
                      inputClassName="min-h-11"
                    />
                  )}
                </form.Field>
                <form.Field name="guestGid">
                  {(field) => (
                    <TextField
                      field={withFieldError(field, errorFor("guestGid"))}
                      label={t("templates:form.guestGid")}
                      autoComplete="off"
                      inputMode="numeric"
                      inputClassName="min-h-11"
                    />
                  )}
                </form.Field>
              </div>
              <form.Field name="guestHome">
                {(field) => (
                  <TextField
                    field={withFieldError(field, errorFor("guestHome"))}
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
                    field={withFieldError(field, errorFor("guestShell"))}
                    label={t("templates:form.guestShell")}
                    autoComplete="off"
                    inputMode="url"
                    inputClassName="min-h-11 font-mono"
                  />
                )}
              </form.Field>
            </AdvancedSection>
            <AdvancedSection
              gridClassName="lg:grid-cols-1"
              title={t("templates:registerPage.sections.details")}
              summary={detailsSummary}
              data-advanced="details"
            >
              {logical ? null : (
                <form.Field name="slug">
                  {(field) => (
                    <TextField
                      field={withFieldError(field, errorFor("slug"), (value) => {
                        setSlugEdited(true);
                        field.handleChange(value);
                      })}
                      label={t("templates:form.slug")}
                      description={t("templates:form.slugHint")}
                      autoComplete="off"
                      inputMode="url"
                      maxLength={63}
                      inputClassName="min-h-11 font-mono"
                    />
                  )}
                </form.Field>
              )}
              <div className="flex min-w-0 flex-col gap-2">
                <Label htmlFor={architectureId}>{t("templates:form.architecture")}</Label>
                <FormSelect
                  id={architectureId}
                  autoComplete="off"
                  value={values.architecture}
                  onValueChange={(value) => form.setFieldValue("architecture", value)}
                  className="font-mono"
                >
                  {TEMPLATE_ARCHITECTURES.map((architecture) => (
                    <SelectItem key={architecture} value={architecture}>
                      {architecture}
                    </SelectItem>
                  ))}
                </FormSelect>
                <FieldError errors={errorFor("architecture") ? [errorFor("architecture")] : []} />
              </div>
              <form.Field name="guestVersion">
                {(field) => (
                  <TextField
                    field={withFieldError(field, errorFor("guestVersion"))}
                    label={t("templates:form.guestVersion")}
                    description={t("templates:form.guestVersionHint")}
                    autoComplete="off"
                    inputMode="text"
                    maxLength={TEMPLATE_GUEST_VERSION_MAX}
                    inputClassName="min-h-11"
                  />
                )}
              </form.Field>
            </AdvancedSection>
          </div>
        </FormSection>
      </fieldset>
    </FormPage>
  );
}
