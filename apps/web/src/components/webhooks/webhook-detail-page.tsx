import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
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
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { AdvancedSection } from "@wssp/ui/components/form-page";
import { SelectItem } from "@wssp/ui/components/select";
import { toast } from "@wssp/ui/components/sileo";
import { FieldError, TextField } from "@wssp/ui/components/text-field";
import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { ArrowLeft } from "lucide-react";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { OneTimeSecretPanel } from "@/components/credentials/credential-parts";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { FormSelect } from "@/components/form-select";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import {
  EventCheckboxes,
  invalidateWebhooks,
  KindsChoice,
  kindsSummaryKey,
  webhookDraftSchema,
} from "@/components/webhooks/webhooks-page";
import { WideSheet } from "@/components/wide-sheet";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { dateTimeTitle, formatDateTime } from "@/lib/format-date-time";
import {
  ROTATION_OVERLAPS,
  WEBHOOK_DEFAULT_OPERATION_KINDS,
  type WebhookDraft,
  type WebhookProblem,
  webhookHost,
  webhookProblem,
} from "@/lib/webhook-rules";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

type Endpoint = Awaited<ReturnType<AppRouterClient["webhooks"]["get"]>>;
type DeliveryItem = Awaited<
  ReturnType<AppRouterClient["webhooks"]["listDeliveries"]>
>["items"][number];
const DELIVERY_STATES = ["PENDING", "IN_FLIGHT", "SUCCEEDED", "FAILED", "CANCELLED"] as const;
type DeliveryStateFilter = (typeof DELIVERY_STATES)[number] | "ALL";

const ms = (iso: string | null) => (iso ? Date.parse(iso) : null);

export function WebhookDetailPage({ lang, endpointId }: { lang: string; endpointId: string }) {
  const { t, i18n } = useTranslation(["webhooks", "dashboard", "common"]);
  const endpoint = useQuery({
    ...orpc.webhooks.get.queryOptions({ input: { id: endpointId } }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [endpoint.error]);
  const [revealed, setRevealed] = useState<string | null>(null);
  const missing = endpoint.isError && webhookProblem(endpoint.error) === "notFound";

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <Link
        to="/$lang/settings/webhooks"
        params={{ lang }}
        className="inline-flex min-h-11 items-center gap-2 text-sm underline underline-offset-4"
      >
        <ArrowLeft aria-hidden="true" className="size-4" />
        {t("webhooks:detail.back")}
      </Link>
      {revealed ? (
        <OneTimeSecretPanel
          secret={revealed}
          label={t("webhooks:rotate.secretLabel")}
          onDone={() => setRevealed(null)}
        >
          <p className="text-sm text-muted-foreground">{t("webhooks:create.secretHint")}</p>
        </OneTimeSecretPanel>
      ) : null}
      {missing ? (
        <EmptyState className="rounded-xl border px-4" title={t("webhooks:detail.notFound")} />
      ) : (
        <QueryBoundary
          query={{
            data: endpoint.data,
            isPending: endpoint.isPending,
            isError: endpoint.isError,
            error: endpoint.error,
            refetch: endpoint.refetch,
          }}
          skeleton={<SkeletonList layout="resource" count={2} className="rounded-xl border" />}
          errorMessage={t("dashboard:list.loadFailed")}
        >
          {(data) => (
            <EndpointSummary
              endpoint={data}
              lang={lang}
              locale={i18n.language}
              onRotated={setRevealed}
            />
          )}
        </QueryBoundary>
      )}
      {missing ? null : <DeliveryLog lang={lang} endpointId={endpointId} locale={i18n.language} />}
    </div>
  );
}

function EndpointSummary({
  endpoint,
  lang,
  locale,
  onRotated,
}: {
  endpoint: Endpoint;
  lang: string;
  locale: string;
  onRotated: (secret: string) => void;
}) {
  const { t } = useTranslation(["webhooks", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const redirect = useTwoFactorRedirect(lang);
  const [editing, setEditing] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [problem, setProblem] = useState<WebhookProblem | null>(null);
  const host = webhookHost(endpoint.url);
  const now = Date.now();
  const fail = (error: unknown) => {
    if (!redirect(error)) setProblem(webhookProblem(error));
  };
  const update = useMutation({
    ...orpc.webhooks.update.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSettled: () => invalidateWebhooks(queryClient),
  });
  const test = useMutation({
    ...orpc.webhooks.test.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSettled: () => invalidateWebhooks(queryClient),
  });
  const remove = useMutation({
    ...orpc.webhooks.delete.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const toggle = async () => {
    setProblem(null);
    try {
      await update.mutateAsync({
        id: endpoint.id,
        url: endpoint.url,
        description: endpoint.description,
        events: endpoint.events,
        operationKinds: endpoint.operationKinds,
        enabled: !endpoint.enabled,
      });
      toast.success(
        endpoint.enabled ? t("webhooks:toggle.disabled") : t("webhooks:toggle.enabled"),
      );
    } catch (error) {
      fail(error);
    }
  };

  return (
    <section className="flex min-w-0 flex-col gap-4">
      <PageHeader
        title={host}
        description={endpoint.description ?? undefined}
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              size="touch"
              variant="outline"
              disabled={!endpoint.enabled || test.isPending}
              onClick={async () => {
                setProblem(null);
                try {
                  await test.mutateAsync({ id: endpoint.id });
                  toast.success(t("webhooks:test.queued"));
                } catch (error) {
                  fail(error);
                }
              }}
            >
              {t("webhooks:test.action")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={() => setEditing(true)}>
              {t("webhooks:edit.action")}
            </Button>
            <Button
              type="button"
              size="touch"
              variant="outline"
              disabled={update.isPending}
              onClick={() => void toggle()}
            >
              {endpoint.enabled ? t("webhooks:toggle.disable") : t("webhooks:toggle.enable")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={() => setRotating(true)}>
              {t("webhooks:rotate.action")}
            </Button>
            <Button
              type="button"
              size="touch"
              variant="destructive"
              onClick={() => setDeleting(true)}
            >
              {t("webhooks:delete.action")}
            </Button>
          </div>
        }
      />
      {endpoint.enabled ? null : (
        <p
          role="status"
          data-disabled-reason={endpoint.disabledReason ?? "owner"}
          className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
        >
          {endpoint.disabledReason === "sustained_failures"
            ? t("webhooks:status.disabledForFailures")
            : t("webhooks:status.disabledByOwner")}
        </p>
      )}
      <div className="flex min-w-0 flex-col gap-1 rounded-xl border bg-card p-4 text-sm">
        <p className="break-all font-mono text-xs">{endpoint.url}</p>
        <div className="flex flex-wrap gap-1.5">
          {endpoint.events.map((event) => (
            <Badge key={event}>{t(`webhooks:event.${event}`)}</Badge>
          ))}
        </div>
        <p>{t("webhooks:detail.secretVersion", { version: endpoint.secretVersion })}</p>
        {endpoint.previousSecretExpiresAt ? (
          <p>
            {t("webhooks:detail.previousSecretUntil", {
              date: formatDateTime(endpoint.previousSecretExpiresAt, locale),
            })}
          </p>
        ) : null}
        <p title={dateTimeTitle(endpoint.health.lastSuccessAt, locale)}>
          {t("webhooks:detail.lastSuccess", {
            when: endpoint.health.lastSuccessAt
              ? formatRelativeTime(ms(endpoint.health.lastSuccessAt) ?? now, locale, now)
              : t("webhooks:detail.never"),
          })}
        </p>
        {endpoint.health.lastFailureAt ? (
          <p title={dateTimeTitle(endpoint.health.lastFailureAt, locale)}>
            {t("webhooks:detail.lastFailure", {
              when: formatRelativeTime(ms(endpoint.health.lastFailureAt) ?? now, locale, now),
              errorClass: endpoint.health.lastFailureClass
                ? t(`webhooks:errorClass.${endpoint.health.lastFailureClass}`)
                : "",
            })}
          </p>
        ) : null}
      </div>
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {t(`webhooks:problem.${problem}`)}
        </p>
      ) : null}
      {editing ? (
        <EditWebhookSheet lang={lang} endpoint={endpoint} onClose={() => setEditing(false)} />
      ) : null}
      {rotating ? (
        <RotateSecretDialog
          lang={lang}
          endpointId={endpoint.id}
          onClose={() => setRotating(false)}
          onRotated={(secret) => {
            setRotating(false);
            onRotated(secret);
          }}
        />
      ) : null}
      <ConfirmDeleteDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={t("webhooks:delete.title", { host })}
        description={t("webhooks:delete.description")}
        confirmToken={host}
        typePrompt={t("webhooks:delete.typePrompt")}
        copyAriaLabel={t("webhooks:delete.copyHost")}
        isPending={remove.isPending}
        onConfirm={async () => {
          try {
            await remove.mutateAsync({ id: endpoint.id });
            toast.success(t("webhooks:delete.done"));
            invalidateWebhooks(queryClient);
            setDeleting(false);
            void navigate({ to: "/$lang/settings/webhooks", params: { lang } });
          } catch (error) {
            setDeleting(false);
            fail(error);
          }
        }}
      />
    </section>
  );
}

function EditWebhookSheet({
  lang,
  endpoint,
  onClose,
}: {
  lang: string;
  endpoint: Endpoint;
  onClose: () => void;
}) {
  const { t } = useTranslation(["webhooks", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<WebhookProblem | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const eventsErrorId = useId();
  const update = useMutation({
    ...orpc.webhooks.update.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const initialKinds: WebhookDraft["kinds"] =
    endpoint.operationKinds === "all"
      ? "all"
      : endpoint.operationKinds.length === WEBHOOK_DEFAULT_OPERATION_KINDS.length &&
          WEBHOOK_DEFAULT_OPERATION_KINDS.every((kind) =>
            (endpoint.operationKinds as readonly string[]).includes(kind),
          )
        ? "default"
        : "custom";
  const form = useForm({
    defaultValues: {
      url: endpoint.url,
      description: endpoint.description ?? "",
      events: endpoint.events,
      kinds: initialKinds,
    } as WebhookDraft,
    validators: { onSubmit: webhookDraftSchema(t) },
    onSubmitInvalid: () => focusFirstInvalidField(root.current),
    onSubmit: async ({ value }) => {
      setProblem(null);
      try {
        await update.mutateAsync({
          id: endpoint.id,
          url: value.url.trim(),
          description: value.description.trim() || null,
          events: [...value.events],
          operationKinds:
            value.kinds === "all"
              ? "all"
              : value.kinds === "custom"
                ? endpoint.operationKinds
                : [...WEBHOOK_DEFAULT_OPERATION_KINDS],
          enabled: endpoint.enabled,
        });
      } catch (error) {
        if (!redirect(error)) setProblem(webhookProblem(error));
        return;
      } finally {
        invalidateWebhooks(queryClient);
      }
      toast.success(t("webhooks:edit.saved"));
      onClose();
    },
  });
  const values = useStore(form.store, (state) => state.values);
  const submitting = useStore(form.store, (state) => state.isSubmitting);

  // Same Essential/Advanced split as the create page.
  return (
    <WideSheet
      title={t("webhooks:edit.title")}
      description={t("webhooks:edit.description")}
      closeLabel={t("common:actions.close")}
      busy={submitting}
      onClose={onClose}
      onSubmit={() => void form.handleSubmit()}
      actions={
        <>
          <Button type="button" variant="outline" size="touch" onClick={onClose}>
            {t("common:actions.cancel")}
          </Button>
          <Button type="submit" size="touch" disabled={submitting}>
            {submitting ? t("common:actions.saving") : t("common:actions.saveChanges")}
          </Button>
        </>
      }
    >
      <div ref={root} data-webhook-form="edit" className="min-w-0 space-y-8">
        <div className="flex min-w-0 flex-col gap-6">
          <form.Field name="url">
            {(field) => (
              <TextField
                field={field}
                type="url"
                label={t("webhooks:form.url")}
                description={t("webhooks:form.urlHint")}
                autoComplete="off"
                inputClassName="min-h-11"
                maxLength={2048}
              />
            )}
          </form.Field>
          <form.Field name="events">
            {(field) => (
              <div className="flex min-w-0 flex-col gap-2">
                <EventCheckboxes
                  value={field.state.value}
                  onChange={field.handleChange}
                  invalid={field.state.meta.errors.length > 0}
                  errorId={eventsErrorId}
                />
                <FieldError id={eventsErrorId} errors={field.state.meta.errors} />
              </div>
            )}
          </form.Field>
        </div>
        <AdvancedSection
          gridClassName="lg:grid-cols-1"
          title={t("webhooks:form.details")}
          summary={values.description.trim() || t("webhooks:form.noDescription")}
        >
          <form.Field name="description">
            {(field) => (
              <TextField
                field={field}
                label={t("webhooks:form.description")}
                autoComplete="off"
                inputMode="text"
                inputClassName="min-h-11"
                maxLength={200}
              />
            )}
          </form.Field>
        </AdvancedSection>
        <AdvancedSection
          gridClassName="lg:grid-cols-1"
          title={t("webhooks:form.kindsSection")}
          summary={t(kindsSummaryKey(values.kinds))}
        >
          <form.Field name="kinds">
            {(field) => (
              <KindsChoice
                value={field.state.value}
                onChange={field.handleChange}
                allowCustom={initialKinds === "custom"}
              />
            )}
          </form.Field>
        </AdvancedSection>
        {problem ? (
          <p role="alert" className="text-sm text-destructive">
            {t(`webhooks:problem.${problem}`)}
          </p>
        ) : null}
      </div>
    </WideSheet>
  );
}

function RotateSecretDialog({
  lang,
  endpointId,
  onClose,
  onRotated,
}: {
  lang: string;
  endpointId: string;
  onClose: () => void;
  onRotated: (secret: string) => void;
}) {
  const { t } = useTranslation(["webhooks", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const overlapId = useId();
  const [overlap, setOverlap] = useState<(typeof ROTATION_OVERLAPS)[number]["id"]>("day");
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<WebhookProblem | null>(null);
  const rotate = async () => {
    setPending(true);
    setProblem(null);
    try {
      const seconds = ROTATION_OVERLAPS.find((choice) => choice.id === overlap)?.seconds ?? 86_400;
      const result = await orpc.webhooks.rotateSecret.call({
        id: endpointId,
        overlapSeconds: seconds,
      });
      onRotated(result.secret);
    } catch (error) {
      if (!redirect(error)) setProblem(webhookProblem(error));
    } finally {
      setPending(false);
      invalidateWebhooks(queryClient);
    }
  };
  return (
    <AlertDialog open onOpenChange={(open) => (open || pending ? undefined : onClose())}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t("webhooks:rotate.title")}</AlertDialogTitle>
          <AlertDialogDescription>{t("webhooks:rotate.description")}</AlertDialogDescription>
        </AlertDialogHeader>
        <div className="flex min-w-0 flex-col gap-2">
          <label htmlFor={overlapId} className="text-sm font-medium">
            {t("webhooks:rotate.overlap")}
          </label>
          <FormSelect
            id={overlapId}
            value={overlap}
            onValueChange={(next) => setOverlap(next as typeof overlap)}
            className="min-h-11"
          >
            {ROTATION_OVERLAPS.map((choice) => (
              <SelectItem key={choice.id} value={choice.id}>
                {t(
                  choice.id === "none"
                    ? "webhooks:rotate.overlapNone"
                    : choice.id === "hour"
                      ? "webhooks:rotate.overlapHour"
                      : choice.id === "day"
                        ? "webhooks:rotate.overlapDay"
                        : "webhooks:rotate.overlapWeek",
                )}
              </SelectItem>
            ))}
          </FormSelect>
          {problem ? (
            <p role="alert" className="text-sm text-destructive">
              {t(`webhooks:problem.${problem}`)}
            </p>
          ) : null}
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending} className="min-h-11">
            {t("common:actions.cancel")}
          </AlertDialogCancel>
          <AlertDialogAction
            disabled={pending}
            className="min-h-11"
            onClick={(event) => {
              event.preventDefault();
              void rotate();
            }}
          >
            {t("webhooks:rotate.confirm")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function DeliveryLog({
  lang,
  endpointId,
  locale,
}: {
  lang: string;
  endpointId: string;
  locale: string;
}) {
  const { t } = useTranslation(["webhooks", "dashboard"]);
  const filterId = useId();
  const [state, setState] = useState<DeliveryStateFilter>("ALL");
  const [open, setOpen] = useState<string | null>(null);
  const deliveries = useInfiniteQuery({
    ...orpc.webhooks.listDeliveries.infiniteOptions({
      input: (cursor: string | undefined) => ({
        id: endpointId,
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
        ...(state === "ALL" ? {} : { state }),
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [deliveries.error]);
  const rows = deliveries.data?.pages.flatMap((page) => page.items);
  const now = Date.now();

  return (
    <section aria-labelledby={`${filterId}-title`} className="flex min-w-0 flex-col gap-3">
      <div className="flex min-w-0 flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h2 id={`${filterId}-title`} className="text-lg font-semibold">
            {t("webhooks:deliveries.title")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("webhooks:deliveries.description")}</p>
        </div>
        <div className="flex min-w-0 flex-col gap-1">
          <label htmlFor={filterId} className="text-sm font-medium">
            {t("webhooks:deliveries.filter")}
          </label>
          <FormSelect
            id={filterId}
            value={state}
            onValueChange={(next) => setState(next as DeliveryStateFilter)}
            className="min-h-11 min-w-40"
          >
            <SelectItem value="ALL">{t("webhooks:deliveries.all")}</SelectItem>
            {DELIVERY_STATES.map((value) => (
              <SelectItem key={value} value={value}>
                {t(`webhooks:deliveries.state.${value}`)}
              </SelectItem>
            ))}
          </FormSelect>
        </div>
      </div>
      <QueryBoundary
        query={{
          data: rows,
          isPending: deliveries.isPending,
          isError: deliveries.isError,
          error: deliveries.error,
          refetch: deliveries.refetch,
        }}
        skeleton={<SkeletonList layout="resource" count={3} className="rounded-xl border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={
          <EmptyState className="rounded-xl border px-4" title={t("webhooks:deliveries.empty")} />
        }
      >
        {(items) => (
          <>
            <ul className="flex min-w-0 flex-col gap-2">
              {items.map((delivery) => (
                <DeliveryRow
                  key={delivery.id}
                  delivery={delivery}
                  now={now}
                  locale={locale}
                  onOpen={() => setOpen(delivery.id)}
                />
              ))}
            </ul>
            <LoadMore
              hasNextPage={deliveries.hasNextPage}
              isFetchingNextPage={deliveries.isFetchingNextPage}
              onLoadMore={() => void deliveries.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      {open ? <DeliveryDialog lang={lang} deliveryId={open} onClose={() => setOpen(null)} /> : null}
    </section>
  );
}

function DeliveryRow({
  delivery,
  now,
  locale,
  onOpen,
}: {
  delivery: DeliveryItem;
  now: number;
  locale: string;
  onOpen: () => void;
}) {
  const { t } = useTranslation(["webhooks"]);
  const next = ms(delivery.nextAttemptAt);
  return (
    <li
      data-delivery-id={delivery.id}
      data-state={delivery.state}
      className="flex min-w-0 flex-wrap items-center justify-between gap-2 rounded-lg border p-3 text-sm"
    >
      <div className="flex min-w-0 flex-col gap-1">
        <p className="flex flex-wrap items-center gap-2">
          <Badge variant={delivery.state === "FAILED" ? "destructive" : "outline"}>
            {t(`webhooks:deliveries.state.${delivery.state}`)}
          </Badge>
          <span>
            {t(`webhooks:event.${delivery.eventType}`, { defaultValue: delivery.eventType })}
          </span>
          <span className="text-muted-foreground">
            {t(`webhooks:deliveries.kind.${delivery.kind}`)}
          </span>
        </p>
        <p className="text-muted-foreground">
          <span title={dateTimeTitle(delivery.createdAt, locale)}>
            {formatRelativeTime(ms(delivery.createdAt) ?? now, locale, now)}
          </span>{" "}
          ·{" "}
          {t("webhooks:deliveries.attempts", {
            count: delivery.attemptCount,
            max: delivery.maxAttempts,
          })}
          {delivery.lastErrorClass
            ? ` · ${t(`webhooks:errorClass.${delivery.lastErrorClass}`)}`
            : ""}
          {next ? (
            <span data-next-attempt="" title={dateTimeTitle(next, locale)}>
              {` · ${t("webhooks:deliveries.nextAttempt", { when: formatRelativeTime(next, locale, now) })}`}
            </span>
          ) : null}
        </p>
      </div>
      <Button type="button" size="touch" variant="outline" onClick={onOpen}>
        {t("webhooks:deliveries.open")}
      </Button>
    </li>
  );
}

function DeliveryDialog({
  lang,
  deliveryId,
  onClose,
}: {
  lang: string;
  deliveryId: string;
  onClose: () => void;
}) {
  const { t } = useTranslation(["webhooks", "dashboard", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<WebhookProblem | null>(null);
  const detail = useQuery({
    ...orpc.webhooks.getDelivery.queryOptions({ input: { id: deliveryId } }),
    meta: { skipGlobalErrorToast: true },
  });
  const redeliver = useMutation({
    ...orpc.webhooks.redeliver.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSettled: () => invalidateWebhooks(queryClient),
  });
  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("webhooks:delivery.title", { id: deliveryId })}</DialogTitle>
          <DialogDescription>
            {detail.data ? `${t("webhooks:delivery.eventId")}: ${detail.data.eventId}` : null}
          </DialogDescription>
        </DialogHeader>
        <QueryBoundary
          query={{
            data: detail.data,
            isPending: detail.isPending,
            isError: detail.isError,
            error: detail.error,
            refetch: detail.refetch,
          }}
          skeleton={<SkeletonList count={2} />}
          errorMessage={t("dashboard:list.loadFailed")}
        >
          {(data) => (
            <div className="flex min-w-0 flex-col gap-3 text-sm">
              <h3 className="font-medium">{t("webhooks:delivery.attempts")}</h3>
              {data.attempts.length === 0 ? (
                <p className="text-muted-foreground">{t("webhooks:delivery.noAttempts")}</p>
              ) : (
                <ol className="flex min-w-0 flex-col gap-2">
                  {data.attempts.map((attempt) => (
                    <li key={attempt.attempt} className="min-w-0 rounded-md border p-2">
                      <p className="font-medium">
                        {t("webhooks:delivery.attempt", { n: attempt.attempt })} ·{" "}
                        {attempt.statusCode
                          ? t("webhooks:delivery.status", { status: attempt.statusCode })
                          : null}{" "}
                        {attempt.errorClass ? t(`webhooks:errorClass.${attempt.errorClass}`) : null}{" "}
                        · {t("webhooks:delivery.duration", { ms: attempt.durationMs })}
                      </p>
                      {attempt.resolvedAddress ? (
                        <p className="text-muted-foreground">
                          {t("webhooks:delivery.address", { address: attempt.resolvedAddress })}
                        </p>
                      ) : null}
                      {attempt.responseExcerpt ? (
                        <details>
                          <summary className="min-h-11 cursor-pointer content-center">
                            {t("webhooks:delivery.response")}
                          </summary>
                          <CodeSnippet
                            code={attempt.responseExcerpt}
                            copyLabel={t("webhooks:delivery.response")}
                            preClassName="max-h-40 text-xs"
                          />
                        </details>
                      ) : null}
                    </li>
                  ))}
                </ol>
              )}
              {problem ? (
                <p role="alert" className="text-destructive">
                  {t(`webhooks:problem.${problem}`)}
                </p>
              ) : null}
              <Button
                type="button"
                size="touch"
                disabled={redeliver.isPending}
                onClick={async () => {
                  setProblem(null);
                  try {
                    await redeliver.mutateAsync({ id: deliveryId });
                    toast.success(t("webhooks:delivery.redelivered"));
                    onClose();
                  } catch (error) {
                    if (!redirect(error)) setProblem(webhookProblem(error));
                  }
                }}
              >
                {t("webhooks:delivery.redeliver")}
              </Button>
            </div>
          )}
        </QueryBoundary>
      </DialogContent>
    </Dialog>
  );
}
