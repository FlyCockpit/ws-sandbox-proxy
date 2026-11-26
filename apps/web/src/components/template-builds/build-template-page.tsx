import { useForm, useStore } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { EGRESS_PRESET_NAMES, VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { env } from "@wssp/env/web";
import { Button } from "@wssp/ui/components/button";
import { AdvancedSection, FormPage, FormSection } from "@wssp/ui/components/form-page";
import {
  hasKeyValueErrors,
  KeyValueEditor,
  type KeyValueEntry,
} from "@wssp/ui/components/key-value-editor";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { toast } from "@wssp/ui/components/sileo";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { ArrowLeft } from "lucide-react";
import { type ReactNode, useId, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { FormPageStatus } from "@/components/form-page-status";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { SegmentedControl } from "@/components/segmented-control";
import { SkeletonList } from "@/components/skeleton-list";
import { useAbortOnUnmount } from "@/hooks/use-abort-on-unmount";
import { useKeyValueEditorLabels } from "@/hooks/use-form-field-labels";
import { useSubmissionFence } from "@/hooks/use-submission-fence";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { HOST_STATUS_REFETCH_MS } from "@/lib/host-status";
import { PROTOTYPE_NAMES, stateField } from "@/lib/key-value-entries";
import { isQueryAccessError } from "@/lib/query-access-error";
import { newIntentKey } from "@/lib/sandbox-rules";
import { hashBuildContext, uploadBuildContext } from "@/lib/sandbox-transfers";
import {
  type BuildProblem,
  baseExamples,
  baseSelector,
  buildArgsFromRows,
  buildProblem,
  checkBuildBase,
  checkBuildSource,
  composeBuildSource,
  disabledReasonKey,
  dockerfileEnvNames,
  type EgressChoice,
  egressDomains,
  type SourceFormat,
  secretLikeNames,
} from "@/lib/template-build-rules";
import { withFieldError } from "@/lib/with-field-error";
import { orpc } from "@/utils/orpc";
import { useBaseProblemText, useBuildProblemText, useRecipeProblemText } from "./build-parts";
import {
  BuildTargetNote,
  blocksBuild,
  useHostBuildCheck,
  usePoolBuildCheck,
} from "./build-target-check";

/**
 * Build template page: a Dockerfile or recipe JSON with inline parse errors
 * (the server's own recipe package) and where to build it come first, with a
 * pre-flight that refuses a pool no host can build on. The tag, build args
 * (KEY=value rows with a secret-name warning), network, build VM size and time
 * limit, and the optional uncompressed `.tar` context sit in collapsed
 * sections with a summary each; the context section opens itself when the
 * recipe has COPY. The context is hashed in the browser before acceptance and
 * uploaded through the session's dashboard context routes afterwards (the
 * browser does not pack folders). Success opens the build's page.
 */

const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const TAG = /^[a-z0-9][a-z0-9._-]{0,62}$/;
/** Build-arg names (the recipe's rule); prototype names are refused too. */
const ARG_VALIDATION = {
  keyPattern: /^[A-Za-z_][A-Za-z0-9_]{0,127}$/,
  reservedKeys: [...PROTOTYPE_NAMES],
};
const PICKER_LIMIT = 100;
const SOURCE_MAX = 65_536;
/** Default build time limit when left blank (the server's own default). */
const DEFAULT_TIMEOUT_MINUTES = 30;

type Progress = { phase: "hashing" | "uploading"; percent: number };
type Draft = {
  slug: string;
  format: SourceFormat;
  source: string;
  tag: string;
  targetKind: "host" | "pool";
  hostId: string;
  poolId: string;
  egressMode: EgressChoice;
  presets: string[];
  domains: string;
  cpuCount: string;
  memoryMiB: string;
  diskGiB: string;
  defaultDiskGiB: string;
  timeoutMinutes: string;
};
type Submission = {
  value: Draft;
  body: { recipe: Record<string, unknown> } | { dockerfile: string };
  buildArgs: Record<string, string>;
  context: File | null;
};

function optionalInt(min: number, max: number, step = 1) {
  return (value: string) => {
    if (value.trim() === "") return true;
    const n = Number(value);
    return Number.isInteger(n) && n >= min && n <= max && n % step === 0;
  };
}
const intOrUndefined = (value: string) => (value.trim() === "" ? undefined : Number(value));

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

export function BuildTemplatePage({ lang, templateId }: { lang: string; templateId?: string }) {
  const { t } = useTranslation(["templates"]);
  const template = useQuery({
    ...orpc.sandboxTemplates.getTemplate.queryOptions({ input: { id: templateId ?? "" } }),
    enabled: templateId !== undefined,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [template.error]);
  if (templateId !== undefined && template.isPending)
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
  return (
    <BuildTemplateForm
      lang={lang}
      template={template.data ? { id: template.data.id, label: template.data.label } : undefined}
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

export function BuildTemplateForm({
  lang,
  template,
  notice,
}: {
  lang: string;
  /** The target template; absent: a name field (created when missing). */
  template?: { id: string; label: string };
  /** Shown above the sections (a failed template refetch's retry). */
  notice?: ReactNode;
}) {
  const { t } = useTranslation(["templates", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const redirect = useTwoFactorRedirect(lang);
  const recipeText = useRecipeProblemText();
  const problemText = useBuildProblemText();
  const baseText = useBaseProblemText();
  const editorLabels = useKeyValueEditorLabels();
  const kvLabels = useMemo(
    () => ({ ...editorLabels, add: t("templates:buildPage.addArg") }),
    [editorLabels, t],
  );
  const targetId = useId();
  const targetErrorId = useId();
  const contextId = useId();
  const egressId = useId();
  const formRef = useRef<HTMLFormElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [fileInvalid, setFileInvalid] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [problem, setProblem] = useState<BuildProblem | null>(null);
  // The source the last refusal was about (a FROM refusal clears on edit).
  const [problemSource, setProblemSource] = useState<string | null>(null);
  const [attempted, setAttempted] = useState(false);
  const [argRows, setArgRows] = useState<KeyValueEntry[]>([]);
  const controller = useRef<AbortController | null>(null);
  // Leaving the page mid-hash aborts it; a hash that still resolves sends nothing.
  const fence = useSubmissionFence();
  const nextAbort = useAbortOnUnmount();

  const usage = useQuery({
    ...orpc.templateBuilds.usage.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = useQuery({
    ...orpc.sandboxHosts.listHosts.queryOptions({ input: { limit: PICKER_LIMIT } }),
    // Connection is judged from heartbeat age, so the list polls like the
    // Hosts page; a list read once called every host disconnected 30 s later.
    refetchInterval: HOST_STATUS_REFETCH_MS,
    staleTime: 0,
    refetchOnMount: "always",
    meta: { skipGlobalErrorToast: true },
  });
  const pools = useQuery({
    ...orpc.sandboxPools.listUsable.queryOptions({ input: { limit: PICKER_LIMIT } }),
    meta: { skipGlobalErrorToast: true },
  });
  const hostItems = (hosts.data?.items ?? []).filter((host) => host.deletionRequestedAt == null);
  // The caller's templates, to check FROM before submit (it must name one).
  const templates = useQuery({
    ...orpc.sandboxTemplates.listTemplates.queryOptions({
      input: { limit: PICKER_LIMIT, status: "active" },
    }),
    meta: { skipGlobalErrorToast: true },
  });
  // Only a complete list can say a slug is missing.
  const knownTemplates =
    templates.data && templates.data.nextCursor === null ? templates.data.items : null;
  const poolItems = pools.data?.items ?? [];
  const limits = usage.data;
  const maxMinutes = limits?.maxMinutes ?? 1440;

  const form = useForm({
    defaultValues: {
      slug: "",
      format: "dockerfile",
      source: "",
      tag: "latest",
      targetKind: "host",
      hostId: "",
      poolId: "",
      egressMode: "asWritten",
      presets: [],
      domains: "",
      cpuCount: "",
      memoryMiB: "",
      diskGiB: "",
      defaultDiskGiB: "",
      timeoutMinutes: "",
    } as Draft,
    validators: {
      onSubmit: z.object({
        slug: z
          .string()
          .refine(
            (value) => template !== undefined || (value.length <= 63 && SLUG.test(value)),
            t("templates:builds.dialog.slugInvalid"),
          ),
        tag: z.string().refine((value) => TAG.test(value), t("templates:builds.dialog.tagInvalid")),
        cpuCount: z
          .string()
          .refine(
            optionalInt(VM_SIZE_LIMITS.cpuCountMin, VM_SIZE_LIMITS.cpuCountMax),
            t("templates:builds.dialog.numberInvalid"),
          ),
        memoryMiB: z
          .string()
          .refine(
            optionalInt(
              VM_SIZE_LIMITS.memoryMiBMin,
              VM_SIZE_LIMITS.memoryMiBMax,
              VM_SIZE_LIMITS.memoryMiBStep,
            ),
            t("templates:builds.dialog.numberInvalid"),
          ),
        diskGiB: z
          .string()
          .refine(
            optionalInt(VM_SIZE_LIMITS.diskGiBMin, VM_SIZE_LIMITS.diskGiBMax),
            t("templates:builds.dialog.numberInvalid"),
          ),
        defaultDiskGiB: z
          .string()
          .refine(
            optionalInt(VM_SIZE_LIMITS.diskGiBMin, VM_SIZE_LIMITS.diskGiBMax),
            t("templates:builds.dialog.numberInvalid"),
          ),
        timeoutMinutes: z
          .string()
          .refine(optionalInt(1, maxMinutes), t("templates:builds.dialog.numberInvalid")),
        format: z.enum(["dockerfile", "recipe"]),
        source: z.string(),
        targetKind: z.enum(["host", "pool"]),
        hostId: z.string(),
        poolId: z.string(),
        egressMode: z.enum(["asWritten", "allowlist", "open"]),
        presets: z.array(z.string()),
        domains: z.string(),
      }),
    },
  });
  const values = useStore(form.store, (state) => state.values);

  // Derived each render: the composed source, its check, and the warnings.
  const parsedArgs = buildArgsFromRows(argRows);
  // Flagged rows (and `.env` lines that did not parse) show their own
  // message; a refusal the rows don't explain (a value too long, too many
  // args) shows under the editor.
  const argRowsFlagged = hasKeyValueErrors(argRows, ARG_VALIDATION);
  const argsInvalid = argRowsFlagged || parsedArgs.invalidRow !== null;
  const composed = composeBuildSource(values.format, values.source, {
    mode: values.egressMode,
    presets: values.presets,
    domains: values.domains,
  });
  const check = composed.ok ? checkBuildSource(composed.body, parsedArgs.args) : null;
  const sourceProblem = composed.ok ? (check?.problem ?? null) : composed.problem;
  // FROM must name one of your templates with a ready version: said at the
  // Dockerfile before submit, instead of "not found" in the footer after.
  const baseProblem =
    check !== null && check.problem === null ? checkBuildBase(check.from, knownTemplates) : null;
  const showSourceProblem =
    sourceProblem !== null && (attempted || values.source.trim() !== "") ? sourceProblem : null;
  const secretNames = secretLikeNames([
    ...Object.keys(parsedArgs.args),
    ...(values.format === "dockerfile" ? dockerfileEnvNames(values.source) : []),
  ]);
  const hasCopy = check?.hasCopy ?? false;
  const target = values.targetKind === "host" ? values.hostId : values.poolId;
  const grantsDomains = values.presets.length > 0 || egressDomains(values.domains).length > 0;
  const foreignWarning =
    limits?.allowForeignBuilds === true && values.egressMode !== "asWritten" && !grantsDomains;
  const disabled = limits !== undefined && !limits.enabled;
  const poolPreflight = usePoolBuildCheck(values.targetKind === "pool" ? values.poolId : "");
  const chosenHost = hostItems.find((host) => host.id === values.hostId);
  const hostPreflight = useHostBuildCheck(
    values.targetKind === "host" ? chosenHost : undefined,
    hosts.dataUpdatedAt,
  );
  const targetCheck = values.targetKind === "pool" ? poolPreflight.check : hostPreflight;
  const targetBlocked = blocksBuild(targetCheck);
  const contextMissing = hasCopy && file === null;
  const ready =
    composed.ok &&
    check?.problem === null &&
    baseProblem === null &&
    !argsInvalid &&
    target !== "" &&
    !disabled &&
    !targetBlocked &&
    !contextMissing &&
    !fileInvalid;

  const submit = useMutation({
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
    mutationFn: async ({ value, body, buildArgs, context: contextFile }: Submission) => {
      const stillCurrent = fence.begin();
      const abort = nextAbort();
      controller.current = abort;
      const context = contextFile
        ? await hashBuildContext(contextFile, {
            signal: abort.signal,
            onProgress: (done, total) =>
              setProgress({ phase: "hashing", percent: Math.floor((done / total) * 100) }),
          })
        : null;
      if (!stillCurrent()) throw new DOMException("Left the page", "AbortError");
      setProgress(null);
      const created = await orpc.templateBuilds.create.call({
        idempotencyKey: newIntentKey("template-build"),
        template: template ? { id: template.id } : { slug: value.slug },
        tag: value.tag,
        ...body,
        ...(Object.keys(buildArgs).length ? { buildArgs } : {}),
        ...(value.targetKind === "host"
          ? { sandboxHostId: value.hostId }
          : { poolId: value.poolId }),
        ...(intOrUndefined(value.cpuCount) !== undefined
          ? { cpuCount: intOrUndefined(value.cpuCount) }
          : {}),
        ...(intOrUndefined(value.memoryMiB) !== undefined
          ? { memoryMiB: intOrUndefined(value.memoryMiB) }
          : {}),
        ...(intOrUndefined(value.diskGiB) !== undefined
          ? { diskGiB: intOrUndefined(value.diskGiB) }
          : {}),
        ...(intOrUndefined(value.defaultDiskGiB) !== undefined
          ? { defaultDiskGiB: intOrUndefined(value.defaultDiskGiB) }
          : {}),
        ...(intOrUndefined(value.timeoutMinutes) !== undefined
          ? { timeoutMinutes: intOrUndefined(value.timeoutMinutes) }
          : {}),
        ...(context ? { contextSha256: context.sha256, contextBytes: context.bytes } : {}),
      });
      let uploadFailed = false;
      if (created.needsContext && contextFile) {
        try {
          await uploadBuildContext(
            { serverUrl: env.VITE_SERVER_URL },
            {
              buildId: created.build.id,
              file: contextFile,
              signal: abort.signal,
              onProgress: (sent, total) =>
                setProgress({ phase: "uploading", percent: Math.floor((sent / total) * 100) }),
            },
          );
        } catch {
          uploadFailed = true;
        }
      }
      return { ...created, uploadFailed };
    },
    onMutate: () => setProblem(null),
    onSuccess: (created) => {
      setProgress(null);
      void queryClient.invalidateQueries({ queryKey: orpc.templateBuilds.key() });
      if (created.uploadFailed) toast.error(t("templates:builds.problem.contextUpload"));
      else
        toast.success(
          t(
            created.cacheHit
              ? "templates:builds.dialog.cacheHit"
              : created.joined
                ? "templates:builds.dialog.joined"
                : "templates:builds.dialog.started",
          ),
        );
      void navigate({
        to: "/$lang/dashboard/templates/builds/$buildId",
        params: { lang, buildId: created.build.id },
      });
    },
    onError: (error) => {
      setProgress(null);
      if (controller.current?.signal.aborted) return;
      if (redirect(error)) return;
      const next = buildProblem(error, "createBuild");
      flushSync(() => {
        setProblemSource(form.state.values.source);
        setProblem(next);
      });
      // A refusal of the Dockerfile itself is shown and focused there.
      if (next.kind === "recipe" || next.kind === "baseNotFound")
        focusFirstInvalidField(formRef.current);
    },
  });

  const serverRecipe = problem?.kind === "recipe" ? problem : null;
  // FROM refused by the server: shown at the Dockerfile until it is edited.
  const serverBase =
    problem?.kind === "baseNotFound" && values.source === problemSource ? problem : null;
  const otherProblem =
    problem && problem.kind !== "recipe" && problem.kind !== "baseNotFound" ? problem : null;
  const pending = submit.isPending;
  const sourceMessage = serverRecipe
    ? recipeText(serverRecipe)
    : showSourceProblem?.kind === "recipe"
      ? recipeText(showSourceProblem)
      : showSourceProblem
        ? t(`templates:builds.problem.${showSourceProblem.kind}`)
        : baseProblem
          ? baseText(baseProblem)
          : serverBase && check?.from
            ? baseText({
                kind: "fromNotFound",
                from: baseSelector(check.from),
                examples: baseExamples(templates.data?.items ?? []),
              })
            : null;
  const targetLabel =
    values.targetKind === "host"
      ? chosenHost?.label
      : poolItems.find((pool) => pool.id === values.poolId)?.label;
  const timeout =
    intOrUndefined(values.timeoutMinutes) ?? Math.min(DEFAULT_TIMEOUT_MINUTES, maxMinutes);
  const egressSummary =
    values.egressMode === "asWritten"
      ? t("templates:builds.dialog.egressAsWritten")
      : t("templates:buildPage.summary.egress", {
          mode: t(
            values.egressMode === "open"
              ? "templates:builds.dialog.egressOpen"
              : "templates:builds.dialog.egressAllowlist",
          ),
          count: values.presets.length + egressDomains(values.domains).length,
        });
  const sizeSet = [values.cpuCount, values.memoryMiB, values.diskGiB, values.defaultDiskGiB].some(
    (value) => value.trim() !== "",
  );
  const resourcesSummary = t(
    sizeSet
      ? "templates:buildPage.summary.resourcesCustom"
      : "templates:buildPage.summary.resources",
    { minutes: timeout },
  );

  const pageTitle = template
    ? t("templates:builds.dialog.title", { label: template.label })
    : t("templates:builds.dialog.titleNew");
  return (
    <FormPage
      ref={formRef}
      noValidate
      // Inside the dashboard frame, which already pads the content column.
      className="px-0 pt-0"
      title={pageTitle}
      aria-label={pageTitle}
      description={t("templates:builds.dialog.description")}
      back={<BackLink lang={lang} />}
      onSubmit={async (event) => {
        event.preventDefault();
        flushSync(() => setAttempted(true));
        await form.handleSubmit();
        if (!form.state.isValid || !ready || !composed.ok) {
          focusFirstInvalidField(formRef.current);
          return;
        }
        submit.mutate({
          value: form.state.values,
          body: composed.body,
          buildArgs: parsedArgs.args,
          context: hasCopy ? file : null,
        });
      }}
      actions={
        <>
          <FormPageStatus>
            {progress ? (
              <span role="status" data-build-progress={progress.phase}>
                {t(`templates:builds.dialog.${progress.phase}`, { percent: progress.percent })}
              </span>
            ) : otherProblem ? (
              <span
                role="alert"
                data-build-problem={otherProblem.kind}
                className="text-destructive"
              >
                {problemText(otherProblem)}
              </span>
            ) : (
              <span data-build-plan="">
                {targetLabel
                  ? t("templates:buildPage.plan", {
                      target: targetLabel,
                      minutes: timeout,
                      used: limits?.usage.minutesUsedThisMonth ?? 0,
                      limit: limits?.minutesPerMonth ?? "—",
                    })
                  : t("templates:buildPage.planNoTarget", { minutes: timeout })}
              </span>
            )}
          </FormPageStatus>
          <Button
            type="button"
            size="touch"
            variant="outline"
            onClick={() => {
              controller.current?.abort();
              void navigate({ to: "/$lang/dashboard/templates", params: { lang } });
            }}
          >
            {t("common:actions.cancel")}
          </Button>
          <Button type="submit" size="touch" disabled={pending || disabled || targetBlocked}>
            {pending ? t("templates:builds.dialog.pending") : t("templates:builds.dialog.submit")}
          </Button>
        </>
      }
    >
      {notice}
      {disabled ? (
        <p role="status" data-builds-disabled={limits?.reason ?? "off"} className="text-sm">
          {t(`templates:builds.disabled.${disabledReasonKey(limits?.reason)}`)}
        </p>
      ) : null}
      <FormSection
        title={t("templates:buildPage.recipe")}
        description={t("templates:builds.dialog.sourceHint")}
        gridClassName="lg:grid-cols-1"
      >
        {template ? null : (
          <form.Field name="slug">
            {(field) => (
              <TextField
                field={field}
                label={t("templates:builds.dialog.slug")}
                description={t("templates:builds.dialog.slugHint")}
                autoComplete="off"
                inputMode="text"
                maxLength={63}
                inputClassName="min-h-11 font-mono"
              />
            )}
          </form.Field>
        )}
        <div className="flex min-w-0 flex-col gap-2">
          <p className="text-sm font-medium">{t("templates:builds.dialog.format")}</p>
          <SegmentedControl
            value={values.format}
            onChange={(next) => form.setFieldValue("format", next)}
            ariaLabel={t("templates:builds.dialog.format")}
            items={[
              { value: "dockerfile", label: t("templates:builds.dialog.dockerfile") },
              { value: "recipe", label: t("templates:builds.dialog.recipe") },
            ]}
          />
        </div>
        <form.Field name="source">
          {(field) => (
            <TextareaField
              field={withFieldError(field, sourceMessage)}
              label={
                values.format === "dockerfile"
                  ? t("templates:builds.dialog.dockerfile")
                  : t("templates:builds.dialog.recipe")
              }
              autoComplete="off"
              spellCheck={false}
              rows={10}
              maxLength={SOURCE_MAX}
              inputClassName="font-mono text-xs"
              data-source-problem={sourceMessage ? "" : undefined}
            />
          )}
        </form.Field>
      </FormSection>
      <FormSection
        title={t("templates:builds.dialog.target")}
        description={t("templates:buildPage.targetHint")}
        gridClassName="lg:grid-cols-1"
      >
        <SegmentedControl
          value={values.targetKind}
          onChange={(next) => form.setFieldValue("targetKind", next)}
          ariaLabel={t("templates:buildPage.targetKind")}
          items={[
            { value: "host", label: t("templates:builds.dialog.targetHost") },
            { value: "pool", label: t("templates:builds.dialog.targetPool") },
          ]}
        />
        <div className="flex min-w-0 flex-col gap-2">
          <Label htmlFor={targetId}>{t("templates:builds.dialog.target")}</Label>
          {values.targetKind === "host" ? (
            hosts.isSuccess && hostItems.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t("templates:builds.dialog.noHosts")}
              </p>
            ) : (
              <FormSelect
                id={targetId}
                autoComplete="off"
                optionsSettled={hosts.isSuccess && !hosts.isFetching}
                value={values.hostId}
                aria-invalid={attempted && target === "" ? true : undefined}
                aria-describedby={attempted && target === "" ? targetErrorId : undefined}
                onValueChange={(next) => form.setFieldValue("hostId", next)}
              >
                <SelectItem value="">{t("templates:builds.dialog.chooseHost")}</SelectItem>
                {hostItems.map((host) => (
                  <SelectItem key={host.id} value={host.id}>
                    {`${host.label} · ${host.slug}`}
                  </SelectItem>
                ))}
              </FormSelect>
            )
          ) : pools.isSuccess && poolItems.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("templates:builds.dialog.noPools")}</p>
          ) : (
            <FormSelect
              id={targetId}
              autoComplete="off"
              optionsSettled={pools.isSuccess && !pools.isFetching}
              value={values.poolId}
              aria-invalid={(attempted && target === "") || targetBlocked ? true : undefined}
              aria-describedby={attempted && target === "" ? targetErrorId : undefined}
              onValueChange={(next) => form.setFieldValue("poolId", next)}
            >
              <SelectItem value="">{t("templates:builds.dialog.choosePool")}</SelectItem>
              {poolItems.map((pool) => (
                <SelectItem key={pool.id} value={pool.id}>
                  {`${pool.label} · ${pool.slug}`}
                </SelectItem>
              ))}
            </FormSelect>
          )}
          {attempted && target === "" ? (
            <p id={targetErrorId} role="alert" className="text-sm text-destructive">
              {t("templates:builds.dialog.targetRequired")}
            </p>
          ) : null}
          <BuildTargetNote check={targetCheck} lang={lang} />
        </div>
      </FormSection>
      <FormSection
        title={t("templates:registerPage.advanced")}
        description={t("templates:buildPage.advancedHint")}
        gridClassName="lg:grid-cols-1"
      >
        {/* One cell: the sections join into one ruled list. */}
        <div className="min-w-0 space-y-8">
          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            title={t("templates:buildPage.sections.tag")}
            summary={values.tag}
            data-advanced="tag"
          >
            <form.Field name="tag">
              {(field) => (
                <TextField
                  field={field}
                  label={t("templates:builds.dialog.tag")}
                  description={t("templates:builds.dialog.tagHint")}
                  autoComplete="off"
                  inputMode="text"
                  maxLength={63}
                  inputClassName="min-h-11 font-mono"
                />
              )}
            </form.Field>
          </AdvancedSection>
          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            title={t("templates:buildPage.sections.args")}
            summary={
              Object.keys(parsedArgs.args).length === 0
                ? t("templates:buildPage.summary.argsNone")
                : t("templates:buildPage.summary.args", {
                    count: Object.keys(parsedArgs.args).length,
                  })
            }
            data-advanced="args"
          >
            <KeyValueEditor
              field={stateField(
                "buildArgs",
                argRows,
                !argRowsFlagged && parsedArgs.invalidRow !== null
                  ? [t("templates:buildPage.argsRefused")]
                  : [],
                setArgRows,
              )}
              label={t("templates:builds.dialog.args")}
              description={t("templates:builds.dialog.argsHint")}
              labels={kvLabels}
              keyPattern={ARG_VALIDATION.keyPattern}
              reservedKeys={ARG_VALIDATION.reservedKeys}
              fileImport={false}
            />
            {secretNames.length > 0 ? (
              <p
                role="status"
                data-secret-warning=""
                className="text-sm text-amber-700 dark:text-amber-400"
              >
                {t("templates:builds.dialog.secretWarning", { names: secretNames.join(", ") })}
              </p>
            ) : null}
          </AdvancedSection>
          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            title={t("templates:buildPage.sections.network")}
            summary={egressSummary}
            data-advanced="network"
          >
            <div className="flex min-w-0 flex-col gap-2">
              <Label htmlFor={egressId}>{t("templates:builds.dialog.egress")}</Label>
              <FormSelect
                id={egressId}
                autoComplete="off"
                value={values.egressMode}
                onValueChange={(next) => form.setFieldValue("egressMode", next as EgressChoice)}
              >
                <SelectItem value="asWritten">
                  {t("templates:builds.dialog.egressAsWritten")}
                </SelectItem>
                <SelectItem value="allowlist">
                  {t("templates:builds.dialog.egressAllowlist")}
                </SelectItem>
                <SelectItem value="open" disabled={limits?.openEgress !== true}>
                  {t("templates:builds.dialog.egressOpen")}
                </SelectItem>
              </FormSelect>
              <p className="text-xs text-muted-foreground">
                {limits?.openEgress === true
                  ? t("templates:builds.dialog.egressHint")
                  : t("templates:builds.dialog.egressOpenUnavailable")}
              </p>
            </div>
            {values.egressMode === "asWritten" ? null : (
              <>
                <p className="text-sm">{t("templates:builds.dialog.presets")}</p>
                <div className="flex min-w-0 flex-wrap gap-2">
                  {EGRESS_PRESET_NAMES.map((name) => {
                    const on = values.presets.includes(name);
                    return (
                      <Button
                        key={name}
                        type="button"
                        size="touch"
                        variant={on ? "default" : "outline"}
                        aria-pressed={on}
                        data-egress-preset={name}
                        className="font-mono text-xs"
                        onClick={() =>
                          form.setFieldValue(
                            "presets",
                            on
                              ? values.presets.filter((preset) => preset !== name)
                              : [...values.presets, name],
                          )
                        }
                      >
                        {name}
                      </Button>
                    );
                  })}
                </div>
                <form.Field name="domains">
                  {(field) => (
                    <TextField
                      field={field}
                      label={t("templates:builds.dialog.domains")}
                      description={t("templates:builds.dialog.domainsHint")}
                      autoComplete="off"
                      inputMode="url"
                      spellCheck={false}
                      maxLength={4096}
                      inputClassName="min-h-11 font-mono"
                    />
                  )}
                </form.Field>
              </>
            )}
            {foreignWarning ? (
              <p role="status" className="text-sm text-amber-700 dark:text-amber-400">
                {t("templates:builds.dialog.foreignWarning")}
              </p>
            ) : null}
          </AdvancedSection>
          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            title={t("templates:buildPage.sections.resources")}
            summary={resourcesSummary}
            data-advanced="resources"
          >
            <p className="text-xs text-muted-foreground">
              {t("templates:builds.dialog.resourcesHint")}
            </p>
            <div className="grid min-w-0 gap-3 sm:grid-cols-2">
              <form.Field name="cpuCount">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("templates:builds.dialog.cpu")}
                    type="number"
                    inputMode="numeric"
                    autoComplete="off"
                    min={VM_SIZE_LIMITS.cpuCountMin}
                    max={VM_SIZE_LIMITS.cpuCountMax}
                    inputClassName="min-h-11"
                  />
                )}
              </form.Field>
              <form.Field name="memoryMiB">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("templates:builds.dialog.memory")}
                    type="number"
                    inputMode="numeric"
                    autoComplete="off"
                    min={VM_SIZE_LIMITS.memoryMiBMin}
                    max={VM_SIZE_LIMITS.memoryMiBMax}
                    step={VM_SIZE_LIMITS.memoryMiBStep}
                    inputClassName="min-h-11"
                  />
                )}
              </form.Field>
              <form.Field name="diskGiB">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("templates:builds.dialog.disk")}
                    type="number"
                    inputMode="numeric"
                    autoComplete="off"
                    min={VM_SIZE_LIMITS.diskGiBMin}
                    max={VM_SIZE_LIMITS.diskGiBMax}
                    inputClassName="min-h-11"
                  />
                )}
              </form.Field>
              <form.Field name="defaultDiskGiB">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("templates:builds.dialog.defaultDisk")}
                    type="number"
                    inputMode="numeric"
                    autoComplete="off"
                    min={VM_SIZE_LIMITS.diskGiBMin}
                    max={VM_SIZE_LIMITS.diskGiBMax}
                    inputClassName="min-h-11"
                  />
                )}
              </form.Field>
            </div>
            <form.Field name="timeoutMinutes">
              {(field) => (
                <TextField
                  field={field}
                  label={t("templates:builds.dialog.timeout")}
                  description={t("templates:builds.dialog.timeoutHint", { max: maxMinutes })}
                  type="number"
                  inputMode="numeric"
                  autoComplete="off"
                  min={1}
                  max={maxMinutes}
                  inputClassName="min-h-11"
                />
              )}
            </form.Field>
          </AdvancedSection>
          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            title={t("templates:buildPage.sections.context")}
            summary={
              file
                ? file.name
                : hasCopy
                  ? t("templates:buildPage.summary.contextNeeded")
                  : t("templates:buildPage.summary.contextNone")
            }
            // A Dockerfile with COPY needs the context: its section opens.
            ref={(details: HTMLDetailsElement | null) => {
              if (details && hasCopy) details.open = true;
            }}
            data-advanced="context"
          >
            <div className="flex min-w-0 flex-col gap-2">
              <Label htmlFor={contextId}>{t("templates:builds.dialog.context")}</Label>
              <input
                id={contextId}
                type="file"
                accept=".tar,application/x-tar"
                disabled={pending}
                aria-invalid={fileInvalid || (attempted && contextMissing) || undefined}
                onChange={(event) => {
                  const next = event.target.files?.[0] ?? null;
                  setFile(next);
                  setFileInvalid(next !== null && !next.name.toLowerCase().endsWith(".tar"));
                }}
                className="min-h-11 w-full min-w-0 text-sm file:mr-3 file:min-h-11 file:rounded-md file:border file:bg-background file:px-3"
              />
              <p className="text-xs text-muted-foreground">
                {t("templates:builds.dialog.contextHint")}
              </p>
              {fileInvalid ? (
                <p role="alert" className="text-sm text-destructive">
                  {t("templates:builds.dialog.contextTypeInvalid")}
                </p>
              ) : contextMissing ? (
                <p role={attempted ? "alert" : "status"} data-context-needed="" className="text-sm">
                  {t("templates:builds.dialog.contextNeeded")}
                </p>
              ) : !hasCopy && file !== null && check !== null ? (
                <p role="status" className="text-sm text-muted-foreground">
                  {t("templates:builds.dialog.contextUnused")}
                </p>
              ) : null}
            </div>
          </AdvancedSection>
        </div>
      </FormSection>
    </FormPage>
  );
}
