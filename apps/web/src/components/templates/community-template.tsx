import { useForm, useStore } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
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
import { TextField } from "@wssp/ui/components/text-field";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { FormSelect } from "@/components/form-select";
import { InlineRetry } from "@/components/inline-retry";
import { SegmentedControl } from "@/components/segmented-control";
import {
  BuildErrorText,
  BuildStatePill,
  useBuildProblemText,
} from "@/components/template-builds/build-parts";
import {
  BuildTargetNote,
  blocksBuild,
  useHostBuildCheck,
  usePoolBuildCheck,
} from "@/components/template-builds/build-target-check";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { HOST_STATUS_REFETCH_MS } from "@/lib/host-status";
import { newIntentKey } from "@/lib/sandbox-rules";
import {
  BUILD_LIST_REFETCH_MS,
  type BuildProblem,
  buildProblem,
  canRetryCommunity,
  communityRefreshSkip,
  disabledReasonKey,
  isBuildActive,
} from "@/lib/template-build-rules";
import { orpc } from "@/utils/orpc";
import { useImageMode } from "./template-image-controls";

/**
 * Community base templates (community-base S12): the "Create from community
 * image" Dialog (tested catalog entries only, the builder target, a disabled
 * state with its reason) and the header controls of a community template
 * (badge, daily refresh switch, Refresh now, Try again, last outcome and the
 * peer-storage warning). The server stays the authority for every refusal.
 */

const PICKER_LIMIT = 100;
const LABEL_MAX = 100;

type Draft = {
  source: string;
  label: string;
  targetKind: "host" | "pool";
  hostId: string;
  poolId: string;
};

function invalidateCommunity(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listTemplates.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listRevisions.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.templateBuilds.key() });
}

/** Peer image storage: a community base is only as available as its holders. */
function CommunityPeerWarning() {
  const { t } = useTranslation(["templates"]);
  if (useImageMode() !== "peer") return null;
  return (
    <p
      role="status"
      data-community-peer-warning=""
      className="text-sm text-amber-700 dark:text-amber-400"
    >
      {t("templates:community.dialog.peerWarning")}
    </p>
  );
}

export function CreateCommunityTemplateDialog({
  lang,
  onClose,
}: {
  lang: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["templates", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const redirect = useTwoFactorRedirect(lang);
  const problemText = useBuildProblemText();
  const imageId = useId();
  const targetId = useId();
  const [attempted, setAttempted] = useState(false);
  const [problem, setProblem] = useState<BuildProblem | null>(null);
  const [intentKey] = useState(() => newIntentKey("community-template"));

  const images = useQuery({
    ...orpc.communityTemplates.images.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = useQuery({
    ...orpc.sandboxHosts.listHosts.queryOptions({ input: { limit: PICKER_LIMIT } }),
    // Connection is judged from heartbeat age: poll like the Hosts page.
    refetchInterval: HOST_STATUS_REFETCH_MS,
    staleTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  const pools = useQuery({
    ...orpc.sandboxPools.listUsable.queryOptions({ input: { limit: PICKER_LIMIT } }),
    meta: { skipGlobalErrorToast: true },
  });
  const imageItems = images.data?.images ?? [];
  const disabledReason = images.data?.disabledReason ?? null;
  const hostItems = (hosts.data?.items ?? []).filter((host) => host.deletionRequestedAt == null);
  const poolItems = pools.data?.items ?? [];

  const form = useForm({
    defaultValues: {
      source: "",
      label: "",
      targetKind: "host",
      hostId: "",
      poolId: "",
    } as Draft,
    validators: {
      onSubmit: z.object({
        source: z.string().min(1, t("templates:community.dialog.imageRequired")),
        label: z.string().max(LABEL_MAX, t("templates:community.dialog.labelInvalid")),
        targetKind: z.enum(["host", "pool"]),
        hostId: z.string(),
        poolId: z.string(),
      }),
    },
  });
  const values = useStore(form.store, (state) => state.values);
  // Someone with no hosts of their own builds on a pool: until they pick,
  // "Build on" starts at A pool instead of "You have no hosts."
  const [kindChosen, setKindChosen] = useState(false);
  const targetKind: Draft["targetKind"] =
    !kindChosen && hosts.isSuccess && hostItems.length === 0 && poolItems.length > 0
      ? "pool"
      : values.targetKind;
  const target = targetKind === "host" ? values.hostId : values.poolId;
  const poolPreflight = usePoolBuildCheck(targetKind === "pool" ? values.poolId : "");
  const chosenHost = hostItems.find((host) => host.id === values.hostId);
  const hostPreflight = useHostBuildCheck(
    targetKind === "host" ? chosenHost : undefined,
    hosts.dataUpdatedAt,
  );
  const targetCheck = targetKind === "pool" ? poolPreflight.check : hostPreflight;
  const targetBlocked = blocksBuild(targetCheck);

  const create = useMutation({
    ...orpc.communityTemplates.create.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: (result) => {
      invalidateCommunity(queryClient);
      toast.success(
        t(
          result.existing
            ? "templates:community.dialog.existing"
            : "templates:community.dialog.started",
        ),
      );
      onClose();
      if (result.build)
        void navigate({
          to: "/$lang/dashboard/templates/builds/$buildId",
          params: { lang, buildId: result.build.id },
        });
    },
    onError: (error) => {
      if (!redirect(error)) setProblem(buildProblem(error));
    },
  });
  const disabled = disabledReason !== null;

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>{t("templates:community.dialog.title")}</DialogTitle>
          <DialogDescription>{t("templates:community.dialog.description")}</DialogDescription>
        </DialogHeader>
        {disabled ? (
          <p role="status" data-community-disabled={disabledReason} className="text-sm">
            {t(`templates:builds.disabled.${disabledReasonKey(disabledReason)}`)}
          </p>
        ) : null}
        <CommunityPeerWarning />
        <form
          noValidate
          className="flex min-w-0 flex-col gap-4"
          onSubmit={async (event) => {
            event.preventDefault();
            event.stopPropagation();
            setAttempted(true);
            await form.handleSubmit();
            if (!form.state.isValid || target === "" || disabled || targetBlocked) return;
            const value = form.state.values;
            const label = value.label.trim();
            create.mutate({
              source: value.source,
              idempotencyKey: intentKey,
              target:
                targetKind === "host" ? { sandboxHostId: value.hostId } : { poolId: value.poolId },
              ...(label ? { label } : {}),
            });
          }}
        >
          <fieldset className="flex min-w-0 flex-col gap-4" disabled={create.isPending || disabled}>
            <div className="flex min-w-0 flex-col gap-2">
              <Label htmlFor={imageId}>{t("templates:community.dialog.image")}</Label>
              {images.isError ? (
                <InlineRetry
                  variant="destructive"
                  message={t("templates:community.dialog.imagesFailed")}
                  onRetry={() => void images.refetch()}
                />
              ) : images.isSuccess && imageItems.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t("templates:community.dialog.noImages")}
                </p>
              ) : (
                <form.Field name="source">
                  {(field) => (
                    <FormSelect
                      id={imageId}
                      autoComplete="off"
                      optionsSettled={images.isSuccess && !images.isFetching}
                      value={field.state.value}
                      onValueChange={(next) => field.handleChange(next)}
                    >
                      <SelectItem value="">
                        {t("templates:community.dialog.chooseImage")}
                      </SelectItem>
                      {imageItems.map((image) => (
                        <SelectItem key={image.id} value={image.id}>
                          {t("templates:community.dialog.imageOption", {
                            label: image.label,
                            architecture: image.architecture,
                          })}
                        </SelectItem>
                      ))}
                    </FormSelect>
                  )}
                </form.Field>
              )}
              {attempted && values.source === "" ? (
                <p role="alert" className="text-sm text-destructive">
                  {t("templates:community.dialog.imageRequired")}
                </p>
              ) : null}
            </div>
            <form.Field name="label">
              {(field) => (
                <TextField
                  field={field}
                  label={t("templates:community.dialog.label")}
                  description={t("templates:community.dialog.labelHint")}
                  autoComplete="off"
                  inputMode="text"
                  maxLength={LABEL_MAX}
                  inputClassName="min-h-11"
                />
              )}
            </form.Field>
            <div className="flex min-w-0 flex-col gap-2">
              <Label htmlFor={targetId}>{t("templates:community.dialog.target")}</Label>
              <SegmentedControl
                value={targetKind}
                onChange={(next) => {
                  setKindChosen(true);
                  form.setFieldValue("targetKind", next);
                }}
                ariaLabel={t("templates:community.dialog.target")}
                items={[
                  { value: "host", label: t("templates:builds.dialog.targetHost") },
                  { value: "pool", label: t("templates:builds.dialog.targetPool") },
                ]}
              />
              {targetKind === "host" ? (
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
              <BuildTargetNote check={targetCheck} lang={lang} />
            </div>
          </fieldset>
          {problem ? (
            <p
              role="alert"
              data-community-problem={problem.kind}
              className="text-sm text-destructive"
            >
              {problemText(problem)}
            </p>
          ) : null}
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button type="button" size="touch" variant="outline" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
            <Button
              type="submit"
              size="touch"
              disabled={create.isPending || disabled || targetBlocked}
            >
              {create.isPending
                ? t("templates:community.dialog.pending")
                : t("templates:community.dialog.submit")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** The Community badge for a template card's title row. */
export function CommunityBadge() {
  const { t } = useTranslation(["templates"]);
  return (
    <span
      data-community-badge=""
      title={t("templates:community.badgeHint")}
      className="inline-flex items-center rounded-sm border border-sky-600/40 bg-sky-600/10 px-2 py-0.5 text-xs font-medium text-sky-700 dark:text-sky-400"
    >
      {t("templates:community.badge")}
    </span>
  );
}

/**
 * The header controls of a community template: the refresh switch, Refresh
 * now, Try again (after a failed or cancelled preparation), the latest
 * preparation's outcome and the peer-storage warning.
 */
export function CommunityTemplateControls({
  template,
  lang,
}: {
  template: { id: string; archivedAt: string | Date | null; community: { refresh: boolean } };
  lang: string;
}) {
  const { t } = useTranslation(["templates"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const problemText = useBuildProblemText();
  const switchId = useId();
  const [refreshKey, setRefreshKey] = useState(() => newIntentKey("community-refresh"));
  const [retryKey, setRetryKey] = useState(() => newIntentKey("community-retry"));
  const latest = useQuery({
    ...orpc.templateBuilds.list.queryOptions({ input: { templateId: template.id, limit: 1 } }),
    refetchInterval: (current) =>
      current.state.data?.items.some((build) => isBuildActive(build.state))
        ? BUILD_LIST_REFETCH_MS
        : false,
    meta: { skipGlobalErrorToast: true },
  });
  const last = latest.data?.items[0];
  const onError = (error: unknown) => {
    if (!redirect(error)) toast.error(problemText(buildProblem(error)));
  };
  const setRefresh = useMutation({
    ...orpc.communityTemplates.setRefresh.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: (_result, input) =>
      toast.success(
        t(
          input.refresh
            ? "templates:community.header.refreshOn"
            : "templates:community.header.refreshOff",
        ),
      ),
    onError: (error) => {
      if (!redirect(error)) toast.error(t("templates:community.header.refreshFailed"));
    },
    onSettled: () => invalidateCommunity(queryClient),
  });
  const refresh = useMutation({
    ...orpc.communityTemplates.refresh.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: (outcome) => {
      setRefreshKey(newIntentKey("community-refresh"));
      if (outcome.kind === "started") toast.success(t("templates:community.header.started"));
      else if (outcome.kind === "active") toast.success(t("templates:community.header.active"));
      else
        toast.message(
          t(`templates:community.header.skipped.${communityRefreshSkip(outcome.reason)}`),
        );
    },
    onError,
    onSettled: () => invalidateCommunity(queryClient),
  });
  const retry = useMutation({
    ...orpc.communityTemplates.retry.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: (result) => {
      setRetryKey(newIntentKey("community-retry"));
      toast.success(
        t(
          result.existing
            ? "templates:community.header.active"
            : "templates:community.header.started",
        ),
      );
    },
    onError,
    onSettled: () => invalidateCommunity(queryClient),
  });
  if (template.archivedAt !== null) return null;
  const busy = refresh.isPending || retry.isPending;
  return (
    <section
      data-community-controls=""
      className="flex min-w-0 flex-col gap-3 rounded-lg border p-3"
    >
      <div className="flex min-h-11 min-w-0 items-center justify-between gap-3 text-sm">
        <label htmlFor={switchId} className="min-w-0 space-y-0.5">
          <span className="block font-medium">{t("templates:community.header.refresh")}</span>
          <span className="block text-muted-foreground">
            {t("templates:community.header.refreshHint")}
          </span>
        </label>
        <Switch
          id={switchId}
          checked={template.community.refresh}
          disabled={setRefresh.isPending}
          onCheckedChange={(checked) =>
            setRefresh.mutate({ templateId: template.id, refresh: checked })
          }
        />
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-2 text-sm" data-community-outcome="">
        <span className="text-muted-foreground">{t("templates:community.header.lastOutcome")}</span>
        {latest.isError ? (
          <InlineRetry
            message={t("templates:community.header.outcomeFailed")}
            onRetry={() => void latest.refetch()}
          />
        ) : last ? (
          <>
            <BuildStatePill state={last.state} />
            <BuildErrorText build={last} />
          </>
        ) : latest.isSuccess ? (
          <span>{t("templates:community.header.noOutcome")}</span>
        ) : null}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          size="touch"
          variant="secondary"
          disabled={busy}
          onClick={() => refresh.mutate({ templateId: template.id, idempotencyKey: refreshKey })}
        >
          {refresh.isPending
            ? t("templates:community.header.refreshNowPending")
            : t("templates:community.header.refreshNow")}
        </Button>
        {canRetryCommunity(last) ? (
          <Button
            type="button"
            size="touch"
            disabled={busy}
            onClick={() => retry.mutate({ templateId: template.id, idempotencyKey: retryKey })}
          >
            {retry.isPending
              ? t("templates:community.header.retryPending")
              : t("templates:community.header.retry")}
          </Button>
        ) : null}
      </div>
      <CommunityPeerWarning />
    </section>
  );
}
