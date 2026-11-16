import { useForm, useStore } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { EGRESS_PRESET_NAMES, VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { env } from "@wssp/env/web";
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
import { toast } from "@wssp/ui/components/sileo";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import { cn } from "@wssp/ui/lib/utils";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { FormSelect } from "@/components/form-select";
import { SegmentedControl } from "@/components/segmented-control";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { newIntentKey } from "@/lib/sandbox-rules";
import { hashBuildContext, uploadBuildContext } from "@/lib/sandbox-transfers";
import {
  type BuildProblem,
  buildProblem,
  checkBuildSource,
  composeBuildSource,
  disabledReasonKey,
  dockerfileEnvNames,
  type EgressChoice,
  egressDomains,
  parseBuildArgs,
  type SourceFormat,
  secretLikeNames,
} from "@/lib/template-build-rules";
import { orpc } from "@/utils/orpc";
import { useBuildProblemText, useRecipeProblemText } from "./build-parts";

/**
 * Build template Dialog: a Dockerfile or recipe JSON
 * with inline parse errors (the server's own recipe package), the target
 * host or pool, tag, build args (with a secret-name warning), egress mode
 * and preset chips, VM size and time limit, and an optional uncompressed
 * `.tar` context, hashed in the browser before acceptance and uploaded
 * through the session's dashboard context routes afterwards. The browser
 * does not pack folders: a COPY build needs a `.tar` made elsewhere.
 */

const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const TAG = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const PICKER_LIMIT = 100;
const SOURCE_MAX = 65_536;

type Progress = { phase: "hashing" | "uploading"; percent: number };
type Draft = {
  slug: string;
  format: SourceFormat;
  source: string;
  tag: string;
  targetKind: "host" | "pool";
  hostId: string;
  poolId: string;
  args: string;
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

export function BuildTemplateDialog({
  lang,
  template,
  onClose: close,
}: {
  lang: string;
  /** The target template; absent: a slug field (created when missing). */
  template?: { id: string; label: string };
  onClose: () => void;
}) {
  const { t } = useTranslation(["templates", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const redirect = useTwoFactorRedirect(lang);
  const recipeText = useRecipeProblemText();
  const problemText = useBuildProblemText();
  const targetId = useId();
  const contextId = useId();
  const egressId = useId();
  const [file, setFile] = useState<File | null>(null);
  const [fileInvalid, setFileInvalid] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [problem, setProblem] = useState<BuildProblem | null>(null);
  const [attempted, setAttempted] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const onClose = () => {
    controller.current?.abort();
    close();
  };

  const usage = useQuery({
    ...orpc.templateBuilds.usage.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = useQuery({
    ...orpc.sandboxHosts.listHosts.queryOptions({ input: { limit: PICKER_LIMIT } }),
    meta: { skipGlobalErrorToast: true },
  });
  const pools = useQuery({
    ...orpc.sandboxPools.listUsable.queryOptions({ input: { limit: PICKER_LIMIT } }),
    meta: { skipGlobalErrorToast: true },
  });
  const hostItems = (hosts.data?.items ?? []).filter((host) => host.deletionRequestedAt == null);
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
      args: "",
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
        args: z.string(),
        egressMode: z.enum(["asWritten", "allowlist", "open"]),
        presets: z.array(z.string()),
        domains: z.string(),
      }),
    },
  });
  const values = useStore(form.store, (state) => state.values);

  // Derived each render: the composed source, its check, and the warnings.
  const parsedArgs = parseBuildArgs(values.args);
  const composed = composeBuildSource(values.format, values.source, {
    mode: values.egressMode,
    presets: values.presets,
    domains: values.domains,
  });
  const check = composed.ok ? checkBuildSource(composed.body, parsedArgs.args) : null;
  const sourceProblem = composed.ok ? (check?.problem ?? null) : composed.problem;
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
  const ready =
    composed.ok &&
    check?.problem === null &&
    parsedArgs.invalidLine === null &&
    target !== "" &&
    !disabled &&
    (!hasCopy || file !== null) &&
    !fileInvalid;

  const submit = useMutation({
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
    mutationFn: async ({ value, body, buildArgs, context: contextFile }: Submission) => {
      const abort = new AbortController();
      controller.current = abort;
      const context = contextFile
        ? await hashBuildContext(contextFile, {
            signal: abort.signal,
            onProgress: (done, total) =>
              setProgress({ phase: "hashing", percent: Math.floor((done / total) * 100) }),
          })
        : null;
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
      close();
      void navigate({
        to: "/$lang/dashboard/templates/builds/$buildId",
        params: { lang, buildId: created.build.id },
      });
    },
    onError: (error) => {
      setProgress(null);
      if (controller.current?.signal.aborted) return;
      if (redirect(error)) return;
      setProblem(buildProblem(error));
    },
  });

  const serverRecipe = problem?.kind === "recipe" ? problem : null;
  const otherProblem = problem && problem.kind !== "recipe" ? problem : null;
  const pending = submit.isPending;

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle>
            {template
              ? t("templates:builds.dialog.title", { label: template.label })
              : t("templates:builds.dialog.titleNew")}
          </DialogTitle>
          <DialogDescription>{t("templates:builds.dialog.description")}</DialogDescription>
        </DialogHeader>
        {disabled ? (
          <p role="status" data-builds-disabled={limits?.reason ?? "off"} className="text-sm">
            {t(`templates:builds.disabled.${disabledReasonKey(limits?.reason)}`)}
          </p>
        ) : null}
        <form
          noValidate
          className="flex min-w-0 flex-col gap-4"
          onSubmit={async (event) => {
            event.preventDefault();
            setAttempted(true);
            await form.handleSubmit();
            if (!form.state.isValid || !ready || !composed.ok) return;
            submit.mutate({
              value: form.state.values,
              body: composed.body,
              buildArgs: parsedArgs.args,
              context: hasCopy ? file : null,
            });
          }}
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
                field={field}
                label={
                  values.format === "dockerfile"
                    ? t("templates:builds.dialog.dockerfile")
                    : t("templates:builds.dialog.recipe")
                }
                description={t("templates:builds.dialog.sourceHint")}
                autoComplete="off"
                spellCheck={false}
                rows={10}
                maxLength={SOURCE_MAX}
                inputClassName="font-mono text-xs"
              />
            )}
          </form.Field>
          {showSourceProblem || serverRecipe ? (
            <p role="alert" data-source-problem="" className="text-sm text-destructive">
              {serverRecipe
                ? recipeText(serverRecipe)
                : showSourceProblem?.kind === "recipe"
                  ? recipeText(showSourceProblem)
                  : showSourceProblem
                    ? t(`templates:builds.problem.${showSourceProblem.kind}`)
                    : null}
            </p>
          ) : null}
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
          <div className="flex min-w-0 flex-col gap-2">
            <Label htmlFor={targetId}>{t("templates:builds.dialog.target")}</Label>
            <SegmentedControl
              value={values.targetKind}
              onChange={(next) => form.setFieldValue("targetKind", next)}
              ariaLabel={t("templates:builds.dialog.target")}
              items={[
                { value: "host", label: t("templates:builds.dialog.targetHost") },
                { value: "pool", label: t("templates:builds.dialog.targetPool") },
              ]}
            />
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
              <p className="text-sm text-muted-foreground">
                {t("templates:builds.dialog.noPools")}
              </p>
            ) : (
              <FormSelect
                id={targetId}
                autoComplete="off"
                optionsSettled={pools.isSuccess && !pools.isFetching}
                value={values.poolId}
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
              <p role="alert" className="text-sm text-destructive">
                {t("templates:builds.dialog.targetRequired")}
              </p>
            ) : null}
          </div>
          <form.Field name="args">
            {(field) => (
              <TextareaField
                field={field}
                label={t("templates:builds.dialog.args")}
                description={t("templates:builds.dialog.argsHint")}
                autoComplete="off"
                spellCheck={false}
                rows={3}
                maxLength={SOURCE_MAX}
                inputClassName="font-mono text-xs"
              />
            )}
          </form.Field>
          {parsedArgs.invalidLine !== null && values.args.trim() !== "" ? (
            <p role="alert" className="text-sm text-destructive">
              {t("templates:builds.dialog.argsInvalid", { line: parsedArgs.invalidLine })}
            </p>
          ) : null}
          {secretNames.length > 0 ? (
            <p
              role="status"
              data-secret-warning=""
              className="text-sm text-amber-700 dark:text-amber-400"
            >
              {t("templates:builds.dialog.secretWarning", { names: secretNames.join(", ") })}
            </p>
          ) : null}
          <fieldset className="flex min-w-0 flex-col gap-2">
            <legend className="text-sm font-medium">{t("templates:builds.dialog.egress")}</legend>
            <FormSelect
              id={egressId}
              autoComplete="off"
              aria-label={t("templates:builds.dialog.egress")}
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
                        className={cn("font-mono text-xs")}
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
          </fieldset>
          <fieldset className="flex min-w-0 flex-col gap-2">
            <legend className="text-sm font-medium">
              {t("templates:builds.dialog.resources")}
            </legend>
            <div className="grid min-w-0 gap-3 sm:grid-cols-3">
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
            <p className="text-xs text-muted-foreground">
              {t("templates:builds.dialog.resourcesHint")}
            </p>
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
          </fieldset>
          <div className="flex min-w-0 flex-col gap-2">
            <Label htmlFor={contextId}>{t("templates:builds.dialog.context")}</Label>
            <input
              id={contextId}
              type="file"
              accept=".tar,application/x-tar"
              disabled={pending}
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
            ) : hasCopy && file === null ? (
              <p role={attempted ? "alert" : "status"} data-context-needed="" className="text-sm">
                {t("templates:builds.dialog.contextNeeded")}
              </p>
            ) : !hasCopy && file !== null && check !== null ? (
              <p role="status" className="text-sm text-muted-foreground">
                {t("templates:builds.dialog.contextUnused")}
              </p>
            ) : null}
          </div>
          {progress ? (
            <p role="status" data-build-progress={progress.phase} className="text-sm tabular-nums">
              {t(`templates:builds.dialog.${progress.phase}`, { percent: progress.percent })}
            </p>
          ) : null}
          {otherProblem ? (
            <p
              role="alert"
              data-build-problem={otherProblem.kind}
              className="text-sm text-destructive"
            >
              {problemText(otherProblem)}
            </p>
          ) : null}
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button type="button" size="touch" variant="outline" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
            <Button type="submit" size="touch" disabled={pending || disabled}>
              {pending ? t("templates:builds.dialog.pending") : t("templates:builds.dialog.submit")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
