import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { SANDBOX_NAME_MAX, VM_SIZE_LIMITS } from "@wssp/api/sandbox/contracts";
import { revisionRootTaint } from "@wssp/api/sandbox/guest-sudo-policy";
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
import { Switch } from "@wssp/ui/components/switch";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { LoadMore } from "@/components/load-more";
import { LoginsPicker } from "@/components/logins/login-picker";
import { useLoginsAvailability } from "@/components/logins/logins-shared";
import { SharingNotice } from "@/components/pools/pool-sharing";
import { ResourceIdentity } from "@/components/resource-identity";
import { LifetimeFields } from "@/components/sandboxes/sandbox-parts";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { credentialErrorKey } from "@/lib/credential-errors";
import { formatGraceDuration } from "@/lib/format-duration";
import { hostConnectionState, hostResourceFit } from "@/lib/host-status";
import {
  type CapacityWaitChoice,
  capacityWaitChoices,
  DEFAULT_SANDBOX_DRAFT,
  IntentKeys,
  isCreateInputMistake,
  LEASE_DEFAULT_MS,
  type LifetimeLimit,
  type SandboxDraft,
  type SandboxProblem,
  sandboxDraftInput,
  sandboxDraftProblems,
  sandboxProblem,
} from "@/lib/sandbox-rules";
import { orpc } from "@/utils/orpc";

/** Placement and template identity are independent. Only the server decides
 * compatibility/capacity. Lost responses replay the exact accepted intent. */

/** Picker page size (the procedures' maximum). */
const PICKER_LIMIT = 100;

const cursorPages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

/** Problems after which the same request cannot succeed: the next submit gets a new key. */
const DEFINITE: ReadonlySet<SandboxProblem> = new Set([
  "notFound",
  "stateChanged",
  "keyReused",
  "hostCapacity",
  "capacityRam",
  "capacityVcpu",
  "capacityDisk",
  "capacityStorage",
  "capacityCeiling",
  "sizeInvalid",
  "sizeUnsupported",
  "hostUnavailable",
  "poolPolicyChanged",
  "shareQuota",
  "memberQuota",
  "poolFull",
  "poolUnavailable",
  "poolIncompatible",
  "poolMissing",
  "hostDraining",
  "hostDeleting",
  "templateMissing",
  "imageMissing",
  "hostNoEgress",
  "egressGuardUnavailable",
  "openEgressNotPermitted",
  "labels",
  "nameTaken",
  "nameInvalid",
  "egress",
  "invalid",
  "forbidden",
]);

export function CreateSandboxDialog({ lang, onClose }: { lang: string; onClose: () => void }) {
  const { t } = useTranslation(["sandboxes", "hosts", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const redirect = useTwoFactorRedirect(lang);
  const hostSelectId = useId();
  const templateSelectId = useId();
  const revisionSelectId = useId();
  const [logicalId, setLogicalId] = useState("");
  const intents = useRef(new IntentKeys());
  const lastSubmitted = useRef<string | null>(null);
  const lastQuote = useRef<number | undefined>(undefined);
  const [placement, setPlacement] = useState<"host" | "pool">("host");
  const poolSelectId = useId();
  const waitSelectId = useId();
  const placementSelectId = useId();
  const [attempted, setAttempted] = useState(false);
  const [problem, setProblem] = useState<SandboxProblem | null>(null);
  const [loginProblemKey, setLoginProblemKey] = useState<string | null>(null);
  const loginsAvailability = useLoginsAvailability();

  const limits = useQuery({
    ...orpc.sandboxes.getLimits.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  // Direct targets: the deployment limit (hosts may allow less; the server
  // answers with the exact maximum). Pools: the best path for this caller.
  const deploymentLimit: LifetimeLimit = {
    maxTimeoutMs: limits.data?.sandboxTimeoutMaxMs ?? LEASE_DEFAULT_MS,
    allowUnlimited: limits.data?.sandboxTimeoutZero === true,
  };
  const hostsQuery = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = (hostsQuery.data?.pages.flatMap((page) => page.items) ?? []).filter(
    (host) => host.deletionRequestedAt == null,
  );

  const poolsQuery = useInfiniteQuery({
    ...orpc.sandboxPools.listUsable.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const pools = poolsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  /** Deployment and pool wait layers (null: no limit at that layer; 0: off). */
  const effectiveWaitMax = (poolId: string): number | null => {
    const layers = [
      limits.data?.capacityWaitMaxMs ?? 3_600_000,
      pools.find((candidate) => candidate.id === poolId)?.capacityWaitMaxMs ?? null,
    ].filter((value): value is number => value !== null);
    return layers.length === 0 ? null : Math.min(...layers);
  };
  const lifetimeLimit = (draft: SandboxDraft): LifetimeLimit => {
    const pool = draft.poolId
      ? pools.find((candidate) => candidate.id === draft.poolId)
      : undefined;
    return pool
      ? { maxTimeoutMs: pool.lease.maxTimeoutMs, allowUnlimited: pool.lease.timeoutZero }
      : deploymentLimit;
  };

  const create = useMutation({
    ...orpc.sandboxes.createSandbox.mutationOptions(),
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      setProblem(null);
      setLoginProblemKey(null);
    },
    onSuccess: (sandbox) => {
      lastSubmitted.current = null;
      form.setFieldValue("envs", "");
      create.reset();
      intents.current.settle();
      toast.success(t("sandboxes:create.done"));
      void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
      onClose();
      void navigate({
        to: "/$lang/dashboard/sandboxes/$sandboxId",
        params: { lang, sandboxId: sandbox.id },
      });
    },
    onError: (error) => {
      const inputMistake = isCreateInputMistake(error);
      const mapped = sandboxProblem(error);
      const next = inputMistake && mapped === "generic" ? "invalid" : mapped;
      setProblem(next);
      setLoginProblemKey(credentialErrorKey(error));
      if (DEFINITE.has(next)) {
        lastSubmitted.current = null;
        if (!inputMistake) form.setFieldValue("envs", "");
        create.reset();
        intents.current.settle();
        void hostsQuery.refetch();
        void poolsQuery.refetch();
        void templatesQuery.refetch();
        if (logicalId) void revisionsQuery.refetch();
      }
      redirect(error);
    },
  });

  const draftValidator = z.custom<SandboxDraft>().superRefine((draft, context) => {
    for (const issue of draftProblems(draft))
      context.addIssue({ code: "custom", message: t(`sandboxes:draft.${issue}`) });
  });
  const form = useForm({
    defaultValues: DEFAULT_SANDBOX_DRAFT,
    validators: { onChange: draftValidator, onSubmit: draftValidator },
    onSubmit: ({ value }) => {
      setAttempted(true);
      if (create.isPending) return;
      if (draftProblems(value).length > 0) return;
      const selectedPool = pools.find((pool) => pool.id === value.poolId);
      const quoted =
        lastSubmitted.current === JSON.stringify(value)
          ? lastQuote.current
          : selectedPool?.disconnectGraceSeconds;
      lastQuote.current = quoted;
      const submitted = {
        ...value,
        ...(quoted !== undefined ? { expectedDisconnectGraceSeconds: quoted } : {}),
      };
      lastSubmitted.current = JSON.stringify(value);
      create.mutate(
        intents.current.for("create", JSON.stringify(submitted), (key) =>
          sandboxDraftInput(submitted, key, lifetimeLimit(submitted)),
        ),
      );
    },
  });
  const values = useStore(form.store, (state) => state.values);
  const templatesQuery = useInfiniteQuery({
    ...orpc.sandboxTemplates.listTemplates.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor, status: "active" }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const templates = templatesQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const revisionsQuery = useInfiniteQuery({
    ...orpc.sandboxTemplates.listRevisions.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({
        limit: PICKER_LIMIT,
        cursor,
        templateId: logicalId,
      }),
    }),
    enabled: Boolean(logicalId),
    meta: { skipGlobalErrorToast: true },
  });
  const revisions = (revisionsQuery.data?.pages.flatMap((page) => page.items) ?? []).filter(
    (revision) => revision.retiredAt == null,
  );
  const draftProblems = (draft: SandboxDraft) => {
    // Accepted work replays even if discovery changed after a lost response.
    // Only an identical draft may bypass mutable picker checks.
    if (problem === "generic" && lastSubmitted.current === JSON.stringify(draft)) return [];
    const limit = lifetimeLimit(draft);
    const issues = sandboxDraftProblems(
      draft,
      draft.templateMode === "logical" ? templates : revisions,
      limit.maxTimeoutMs,
      limit.allowUnlimited,
    );
    if (draft.hostId && !hosts.some((host) => host.id === draft.hostId && !host.draining))
      issues.push("unknownHost");
    if (draft.poolId && !pools.some((pool) => pool.id === draft.poolId)) issues.push("unknownPool");
    return issues;
  };
  const problems = attempted ? draftProblems(values) : [];
  useTwoFactorRedirectOnError(lang, [
    limits.error,
    hostsQuery.error,
    poolsQuery.error,
    templatesQuery.error,
    revisionsQuery.error,
  ]);
  const selectedHost = hosts.find((host) => host.id === values.hostId);
  const selectedHostState = selectedHost ? hostConnectionState(selectedHost, Date.now()) : null;

  const revision =
    values.templateMode === "revision"
      ? revisions.find((item) => item.id === values.templateId)
      : undefined;
  const advisorySize = {
    cpuCount: values.cpuCount.trim() ? Number(values.cpuCount) : revision?.cpuCount,
    memoryMiB: values.memoryMiB.trim() ? Number(values.memoryMiB) : revision?.memoryMiB,
    diskGiB: values.diskGiB.trim() ? Number(values.diskGiB) : revision?.diskGiB,
  };

  // One set of grant fields: the allowlist when internet access is off, the
  // fallback grants (collapsed) when it is on.
  const grantFields = (
    <>
      <form.Field name="egressDomains">
        {(field) => (
          <TextareaField
            field={field}
            label={t("sandboxes:create.egressDomains")}
            description={t("sandboxes:create.egressDomainsHint")}
            autoComplete="off"
            inputClassName="font-mono"
            rows={2}
            disabled={create.isPending}
          />
        )}
      </form.Field>
      <form.Field name="egressCidrs">
        {(field) => (
          <TextareaField
            field={field}
            label={t("sandboxes:create.egressCidrs")}
            description={t("sandboxes:create.egressCidrsHint")}
            autoComplete="off"
            inputClassName="font-mono"
            rows={2}
            disabled={create.isPending}
          />
        )}
      </form.Field>
    </>
  );

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>{t("sandboxes:create.title")}</DialogTitle>
          <DialogDescription>{t("sandboxes:create.description")}</DialogDescription>
        </DialogHeader>
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
          <form.Field name="name">
            {(field) => (
              <TextField
                field={field}
                label={t("sandboxes:create.name")}
                description={t("sandboxes:create.nameHint")}
                autoComplete="off"
                inputMode="text"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={SANDBOX_NAME_MAX}
                inputClassName="min-h-11 font-mono"
                disabled={create.isPending}
                // Names are lowercase: fold case as the user types.
                onChange={(event) => field.handleChange(event.target.value.toLowerCase())}
              />
            )}
          </form.Field>
          <Label htmlFor={placementSelectId}>{t("sandboxes:create.placement")}</Label>
          <FormSelect
            id={placementSelectId}
            value={placement}
            disabled={create.isPending}
            autoComplete="off"
            onValueChange={(value) => {
              setPlacement(value as "host" | "pool");
              form.setFieldValue("hostId", "");
              form.setFieldValue("poolId", "");
            }}
          >
            <SelectItem value="host">{t("sandboxes:create.direct")}</SelectItem>
            <SelectItem value="pool">{t("sandboxes:create.pool")}</SelectItem>
          </FormSelect>
          {placement === "pool" ? (
            <fieldset className="flex min-w-0 flex-col gap-2" disabled={create.isPending}>
              <SharingNotice />
              {pools.find((pool) => pool.id === values.poolId) ? (
                <p data-grace-quote="">
                  {t("hosts:sharing.grace", {
                    duration: formatGraceDuration(
                      pools.find((pool) => pool.id === values.poolId)?.disconnectGraceSeconds ?? 0,
                      lang,
                    ),
                  })}
                </p>
              ) : null}
              <Label htmlFor={poolSelectId}>{t("sandboxes:create.pool")}</Label>
              <form.Field name="poolId">
                {(field) => (
                  <FormSelect
                    id={poolSelectId}
                    optionsSettled={
                      poolsQuery.isSuccess && !poolsQuery.isFetching && !poolsQuery.hasNextPage
                    }
                    autoComplete="off"
                    value={field.state.value ?? ""}
                    onValueChange={(value) => {
                      field.handleChange(value);
                    }}
                  >
                    <SelectItem value="">{t("sandboxes:create.choosePool")}</SelectItem>
                    {pools.map((pool) => (
                      <SelectItem key={pool.id} value={pool.id}>
                        <span>
                          <ResourceIdentity label={pool.label} slug={pool.slug} /> ·{" "}
                          {"owner" in pool ? pool.owner?.name : t("hosts:sharing.owned")} ·{" "}
                          {pool.id}
                        </span>
                      </SelectItem>
                    ))}
                  </FormSelect>
                )}
              </form.Field>
              {poolsQuery.isPending ? <SkeletonList count={1} /> : null}
              {poolsQuery.isError ? (
                <InlineRetry
                  message={t("sandboxes:create.poolsFailed")}
                  onRetry={() => void poolsQuery.refetch()}
                />
              ) : null}
              <LoadMore
                hasNextPage={poolsQuery.hasNextPage}
                isFetchingNextPage={poolsQuery.isFetchingNextPage}
                onLoadMore={() => void poolsQuery.fetchNextPage()}
              />
              {values.poolId ? (
                <form.Field name="capacityWait">
                  {(field) => (
                    <div className="flex min-w-0 flex-col gap-2">
                      <Label htmlFor={waitSelectId}>{t("sandboxes:create.capacityWait")}</Label>
                      <FormSelect
                        id={waitSelectId}
                        autoComplete="off"
                        value={field.state.value ?? "none"}
                        onValueChange={(value) => field.handleChange(value as CapacityWaitChoice)}
                      >
                        {capacityWaitChoices(effectiveWaitMax(values.poolId ?? "")).map(
                          (choice) => (
                            <SelectItem key={choice} value={choice}>
                              {t(`sandboxes:create.wait.${choice}`)}
                            </SelectItem>
                          ),
                        )}
                      </FormSelect>
                      <p className="text-xs text-muted-foreground">
                        {t("sandboxes:create.capacityWaitHint")}
                      </p>
                    </div>
                  )}
                </form.Field>
              ) : null}
            </fieldset>
          ) : (
            <fieldset className="flex min-w-0 flex-col gap-2" disabled={create.isPending}>
              <Label htmlFor={hostSelectId}>{t("sandboxes:create.host")}</Label>
              {hostsQuery.isError ? (
                <InlineRetry
                  variant="destructive"
                  message={t("sandboxes:create.hostsFailed")}
                  onRetry={() => void hostsQuery.refetch()}
                />
              ) : hostsQuery.isPending ? (
                <SkeletonList count={1} className="rounded-xl border" />
              ) : hosts.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t("sandboxes:create.noHosts")}</p>
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
                      onValueChange={(value) => {
                        field.handleChange(value);
                      }}
                    >
                      <SelectItem value="">{t("sandboxes:create.chooseHost")}</SelectItem>
                      {hosts.map((host) => (
                        // A draining host refuses new sandboxes (M7-S5): say so,
                        // and do not let it be chosen.
                        <SelectItem
                          key={host.id}
                          value={host.id}
                          disabled={host.draining}
                          data-draining={host.draining ? "" : undefined}
                        >
                          {translateText(
                            t,
                            host.draining
                              ? "sandboxes:create.hostOptionDraining"
                              : "sandboxes:create.hostOptionCapacity",
                            {
                              label: host.label,
                              slug: host.slug,
                              state: t(`hosts:status.${hostConnectionState(host, Date.now())}`),
                              live: host.liveSandboxCount,
                              fit: t(
                                `sandboxes:create.fit.${hostResourceFit(host, advisorySize, Date.now())}`,
                              ),
                            },
                          )}
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
                label={t("sandboxes:create.moreHosts")}
              />
              {hosts.some((host) => host.draining) ? (
                <p data-draining-hosts="" className="text-xs text-muted-foreground">
                  {t("sandboxes:create.drainingHosts")}
                </p>
              ) : null}
              {selectedHostState != null && selectedHostState !== "ready" ? (
                <p data-host-waits="" className="text-xs text-amber-700 dark:text-amber-400">
                  {t("sandboxes:create.hostWaits")}
                </p>
              ) : null}
            </fieldset>
          )}
          <fieldset className="flex min-w-0 flex-col gap-2" disabled={create.isPending}>
            <Label htmlFor={templateSelectId}>{t("sandboxes:create.template")}</Label>
            {templatesQuery.isPending ? (
              <SkeletonList count={1} className="rounded-xl border" />
            ) : null}
            {templatesQuery.isError ? (
              <InlineRetry
                message={t("sandboxes:create.templatesFailed")}
                onRetry={() => void templatesQuery.refetch()}
              />
            ) : null}
            <FormSelect
              id={templateSelectId}
              optionsSettled={
                templatesQuery.isSuccess &&
                !templatesQuery.isFetching &&
                !templatesQuery.hasNextPage
              }
              autoComplete="off"
              value={logicalId}
              disabled={templatesQuery.isPending}
              onValueChange={(value) => {
                setLogicalId(value);
                form.setFieldValue("templateMode", "logical");
                form.setFieldValue("templateId", value);
              }}
            >
              <SelectItem value="">{t("sandboxes:create.chooseTemplate")}</SelectItem>
              {templates.map((template) => (
                <SelectItem key={template.id} value={template.id}>
                  {translateText(t, "sandboxes:create.logicalOption", {
                    label: template.label,
                    slug: template.slug,
                  })}
                </SelectItem>
              ))}
            </FormSelect>
            {!templatesQuery.isPending && templates.length === 0 ? (
              <p className="text-xs text-muted-foreground">{t("sandboxes:create.noTemplates")}</p>
            ) : null}
            <LoadMore
              hasNextPage={templatesQuery.hasNextPage}
              isFetchingNextPage={templatesQuery.isFetchingNextPage}
              onLoadMore={() => void templatesQuery.fetchNextPage()}
              label={t("sandboxes:create.moreTemplates")}
            />
            <p className="text-xs text-muted-foreground">{t("sandboxes:create.selectorHint")}</p>
            {logicalId ? (
              <>
                <Label htmlFor={revisionSelectId}>{t("sandboxes:create.revision")}</Label>
                {revisionsQuery.isPending ? (
                  <SkeletonList count={1} className="rounded-xl border" />
                ) : null}
                {revisionsQuery.isError ? (
                  <InlineRetry
                    message={t("sandboxes:create.revisionsFailed")}
                    onRetry={() => void revisionsQuery.refetch()}
                  />
                ) : null}
                <FormSelect
                  id={revisionSelectId}
                  optionsSettled={
                    revisionsQuery.isSuccess &&
                    !revisionsQuery.isFetching &&
                    !revisionsQuery.hasNextPage
                  }
                  autoComplete="off"
                  value={values.templateMode === "logical" ? "" : values.templateId}
                  onValueChange={(value) => {
                    form.setFieldValue("templateMode", value ? "revision" : "logical");
                    form.setFieldValue("templateId", value || logicalId);
                  }}
                >
                  <SelectItem value="">{t("sandboxes:create.latest")}</SelectItem>
                  {revisions.map((revision) => (
                    <SelectItem key={revision.id} value={revision.id}>
                      {t("sandboxes:create.revisionOption", {
                        revision: revision.revision,
                        architecture: revision.architecture,
                        cpuCount: revision.cpuCount,
                        memoryMiB: revision.memoryMiB,
                        diskGiB: revision.diskGiB,
                      })}
                    </SelectItem>
                  ))}
                </FormSelect>
                <LoadMore
                  hasNextPage={revisionsQuery.hasNextPage}
                  isFetchingNextPage={revisionsQuery.isFetchingNextPage}
                  onLoadMore={() => void revisionsQuery.fetchNextPage()}
                  label={t("sandboxes:create.moreRevisions")}
                />
              </>
            ) : null}
          </fieldset>
          <fieldset
            className="flex min-w-0 flex-col gap-3 rounded-lg border p-3"
            disabled={create.isPending}
          >
            <legend className="px-1 text-sm font-medium">{t("sandboxes:create.size")}</legend>
            <p className="text-xs text-muted-foreground">{t("sandboxes:create.sizeHint")}</p>
            {values.templateMode === "logical" ? (
              <p data-size-advisory="" className="text-xs text-muted-foreground">
                {t("sandboxes:create.latestSizeHint")}
              </p>
            ) : null}
            <div className="grid min-w-0 gap-3 sm:grid-cols-2">
              <form.Field name="cpuCount">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("sandboxes:create.cpuCount")}
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
                    label={t("sandboxes:create.memoryMiB")}
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
              <form.Field name="diskGiB">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("sandboxes:create.diskGiB")}
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
          </fieldset>
          {limits.isError ? (
            <InlineRetry
              message={t("sandboxes:lifetime.limitsFailed")}
              onRetry={() => void limits.refetch()}
            />
          ) : null}
          <LifetimeFields
            maxTimeoutMs={lifetimeLimit(values).maxTimeoutMs}
            allowUnlimited={lifetimeLimit(values).allowUnlimited}
            minutes={values.lifetimeMinutes}
            onMinutes={(value) => form.setFieldValue("lifetimeMinutes", value)}
            onExpire={values.onExpire}
            onOnExpire={(value) =>
              form.setFieldValue("onExpire", value as SandboxDraft["onExpire"])
            }
            disabled={create.isPending}
          />
          <form.Field name="envs">
            {(field) => (
              <TextareaField
                field={field}
                label={t("sandboxes:create.envs")}
                description={t("sandboxes:create.envsHint")}
                autoComplete="off"
                inputClassName="font-mono"
                rows={3}
                maxLength={65_536}
                disabled={create.isPending}
              />
            )}
          </form.Field>
          <form.Field name="labels">
            {(field) => (
              <TextareaField
                field={field}
                label={t("sandboxes:create.labels")}
                description={t("sandboxes:create.labelsHint")}
                autoComplete="off"
                inputClassName="font-mono"
                rows={3}
                maxLength={8192}
                disabled={create.isPending}
              />
            )}
          </form.Field>
          <fieldset
            className="flex min-w-0 flex-col gap-3"
            disabled={create.isPending}
            data-egress-fields=""
          >
            <legend className="mb-1 text-sm font-medium">{t("sandboxes:create.egress")}</legend>
            <form.Field name="internetAccess">
              {(field) => (
                <label className="flex min-h-11 items-center gap-3 text-sm">
                  <Switch
                    data-internet-access=""
                    checked={field.state.value}
                    onCheckedChange={(checked) => field.handleChange(checked)}
                    disabled={create.isPending}
                  />
                  {t("sandboxes:create.internetAccess")}
                </label>
              )}
            </form.Field>
            <p data-egress-hint="" className="text-xs text-muted-foreground">
              {t(
                values.internetAccess
                  ? "sandboxes:create.internetAccessOnHint"
                  : "sandboxes:create.egressHint",
              )}
            </p>
            {values.internetAccess ? (
              <details data-egress-fallback="" className="min-w-0 text-sm">
                <summary className="flex min-h-11 cursor-pointer items-center font-medium">
                  {t("sandboxes:create.fallbackSummary")}
                </summary>
                <div className="flex min-w-0 flex-col gap-3 pt-2">
                  <p className="text-xs text-muted-foreground">
                    {t("sandboxes:create.fallbackHint")}
                  </p>
                  {grantFields}
                </div>
              </details>
            ) : (
              grantFields
            )}
          </fieldset>
          <fieldset
            className="flex min-w-0 flex-col gap-3"
            disabled={create.isPending}
            data-guest-sudo-fields=""
          >
            <legend className="mb-1 text-sm font-medium">{t("sandboxes:create.guestRoot")}</legend>
            <form.Field name="guestSudo">
              {(field) => (
                <label className="flex min-h-11 items-center gap-3 text-sm">
                  <Switch
                    data-guest-sudo=""
                    checked={field.state.value}
                    onCheckedChange={(checked) => field.handleChange(checked)}
                    disabled={create.isPending}
                  />
                  {t("sandboxes:create.guestSudo")}
                </label>
              )}
            </form.Field>
            <p data-guest-sudo-hint="" className="text-xs text-muted-foreground">
              {t(
                values.guestSudo
                  ? "sandboxes:create.guestSudoOnHint"
                  : "sandboxes:create.guestSudoOffHint",
              )}
            </p>
            {!values.guestSudo && revision && revisionRootTaint(revision) ? (
              <p data-guest-root-tainted="" className="text-xs text-amber-700 dark:text-amber-400">
                {t("sandboxes:create.guestRootTainted")}
              </p>
            ) : null}
          </fieldset>
          {loginsAvailability === "enabled" ? (
            <LoginsPicker
              value={values.credentials ?? []}
              disabled={create.isPending}
              onChange={(next) => form.setFieldValue("credentials", next)}
            />
          ) : null}
          {problems.length > 0 ? (
            <ul role="alert" className="list-disc pl-5 text-sm text-destructive">
              {problems.map((item) => (
                <li key={item} data-draft-problem={item}>
                  {t(`sandboxes:draft.${item}`)}
                </li>
              ))}
            </ul>
          ) : null}
          {loginProblemKey ? (
            <p role="alert" data-create-login-problem="" className="text-sm text-destructive">
              {t(loginProblemKey)}
            </p>
          ) : problem ? (
            <p role="alert" data-create-problem={problem} className="text-sm text-destructive">
              {t(
                problem === "notFound"
                  ? "sandboxes:problem.createNotFound"
                  : problem === "forbidden"
                    ? "sandboxes:problem.createForbidden"
                    : `sandboxes:problem.${problem}`,
              )}
            </p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button type="submit" size="touch" disabled={create.isPending}>
              {create.isPending ? t("sandboxes:create.pending") : t("sandboxes:create.submit")}
            </Button>
            <Button type="button" variant="outline" size="touch" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
