import { useForm, useStore } from "@tanstack/react-form";
import {
  type QueryClient,
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { TextField } from "@wssp/ui/components/text-field";
import { Plus } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { OneTimeSecretPanel } from "@/components/credentials/credential-parts";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  WEBHOOK_EVENT_TYPES,
  type WebhookDraft,
  type WebhookProblem,
  webhookDraftProblems,
  webhookHost,
  webhookProblem,
} from "@/lib/webhook-rules";
import { orpc } from "@/utils/orpc";

/**
 * Webhook endpoints (owner-scoped). The signing secret is returned once by
 * create and shown inline from this page's transient state only; lists and
 * reads never carry it. Every write is a live-owner-session procedure.
 */

export function invalidateWebhooks(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: orpc.webhooks.key() });
}

const DEFAULT_WEBHOOK_DRAFT: WebhookDraft = {
  url: "",
  description: "",
  events: ["sandbox.ready", "sandbox.create_failed", "sandbox.destroyed"],
  kinds: "default",
};

export function WebhooksPage({ lang }: { lang: string }) {
  const { t } = useTranslation(["webhooks", "dashboard", "common"]);
  const status = useQuery({
    ...orpc.webhooks.status.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const configured = status.data?.configured === true;
  const endpoints = useInfiniteQuery({
    ...orpc.webhooks.list.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: DASHBOARD_PAGE_LIMIT, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    enabled: configured,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [status.error, endpoints.error]);
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<string | null>(null);
  const rows = endpoints.data?.pages.flatMap((page) => page.items);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t("webhooks:title")}
        description={t("webhooks:description")}
        actions={
          configured ? (
            <Button
              type="button"
              size="touch"
              disabled={revealed !== null}
              onClick={() => setCreating(true)}
            >
              <Plus aria-hidden="true" />
              {t("webhooks:create.action")}
            </Button>
          ) : null
        }
      />
      {revealed ? (
        <OneTimeSecretPanel
          secret={revealed}
          label={t("webhooks:create.secretLabel")}
          onDone={() => setRevealed(null)}
        >
          <p className="text-sm text-muted-foreground">{t("webhooks:create.secretHint")}</p>
        </OneTimeSecretPanel>
      ) : null}
      {status.isPending ? (
        <SkeletonList layout="resource" count={2} className="rounded-xl border" />
      ) : !configured ? (
        <EmptyState
          className="rounded-xl border px-4"
          title={t("webhooks:notConfigured.title")}
          description={t("webhooks:notConfigured.description")}
        />
      ) : (
        <QueryBoundary
          query={{
            data: rows,
            isPending: endpoints.isPending,
            isError: endpoints.isError,
            error: endpoints.error,
            refetch: endpoints.refetch,
          }}
          skeleton={<SkeletonList layout="resource" count={3} className="rounded-xl border" />}
          errorMessage={t("dashboard:list.loadFailed")}
          isEmpty={(items) => items.length === 0}
          empty={
            <EmptyState
              className="rounded-xl border px-4"
              title={t("webhooks:empty.title")}
              description={t("webhooks:empty.description")}
            />
          }
        >
          {(items) => (
            <>
              <ul aria-label={t("webhooks:list.label")} className="flex min-w-0 flex-col gap-3">
                {items.map((endpoint) => (
                  <li
                    key={endpoint.id}
                    data-webhook-id={endpoint.id}
                    className="flex min-w-0 flex-col gap-2 rounded-xl border bg-card p-4 text-card-foreground"
                  >
                    <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                      <Link
                        to="/$lang/settings/webhooks/$endpointId"
                        params={{ lang, endpointId: endpoint.id }}
                        aria-label={t("webhooks:list.open", { host: webhookHost(endpoint.url) })}
                        className="inline-flex min-h-11 min-w-0 items-center break-all font-medium underline underline-offset-4"
                      >
                        {endpoint.url}
                      </Link>
                      <Badge variant={endpoint.enabled ? "secondary" : "destructive"}>
                        {endpoint.enabled
                          ? t("webhooks:status.enabled")
                          : t("webhooks:status.disabled")}
                      </Badge>
                    </div>
                    {endpoint.description ? (
                      <p className="break-words text-sm text-muted-foreground">
                        {endpoint.description}
                      </p>
                    ) : null}
                    <ul
                      aria-label={t("webhooks:list.events")}
                      className="flex min-w-0 flex-wrap gap-1.5"
                    >
                      {endpoint.events.map((event) => (
                        <li key={event} className="rounded-sm border px-2 py-0.5 text-xs">
                          {t(`webhooks:event.${event}`)}
                        </li>
                      ))}
                    </ul>
                    <p className="text-sm text-muted-foreground">
                      {endpoint.health.consecutiveFailures > 0
                        ? t("webhooks:list.failing", { count: endpoint.health.consecutiveFailures })
                        : t("webhooks:list.healthy")}
                    </p>
                  </li>
                ))}
              </ul>
              <LoadMore
                hasNextPage={endpoints.hasNextPage}
                isFetchingNextPage={endpoints.isFetchingNextPage}
                onLoadMore={() => void endpoints.fetchNextPage()}
              />
            </>
          )}
        </QueryBoundary>
      )}
      {creating ? (
        <CreateWebhookDialog
          lang={lang}
          onClose={() => setCreating(false)}
          onCreated={(secret) => {
            setRevealed(secret);
            setCreating(false);
          }}
        />
      ) : null}
    </div>
  );
}

export function EventCheckboxes({
  value,
  onChange,
}: {
  value: readonly (typeof WEBHOOK_EVENT_TYPES)[number][];
  onChange: (next: (typeof WEBHOOK_EVENT_TYPES)[number][]) => void;
}) {
  const { t } = useTranslation(["webhooks"]);
  return (
    <fieldset className="flex min-w-0 flex-col gap-1">
      <legend className="mb-1 text-sm font-medium">{t("webhooks:form.events")}</legend>
      {WEBHOOK_EVENT_TYPES.map((event) => (
        <label key={event} className="flex min-h-11 items-center gap-3 text-sm">
          <Checkbox
            checked={value.includes(event)}
            onCheckedChange={(checked) =>
              onChange(
                checked
                  ? WEBHOOK_EVENT_TYPES.filter((item) => item === event || value.includes(item))
                  : value.filter((item) => item !== event),
              )
            }
          />
          {t(`webhooks:event.${event}`)}
        </label>
      ))}
    </fieldset>
  );
}

export function KindsChoice({
  value,
  onChange,
  allowCustom,
}: {
  value: WebhookDraft["kinds"];
  onChange: (next: WebhookDraft["kinds"]) => void;
  allowCustom: boolean;
}) {
  const { t } = useTranslation(["webhooks"]);
  const choices = allowCustom
    ? (["default", "all", "custom"] as const)
    : (["default", "all"] as const);
  return (
    <fieldset className="flex min-w-0 flex-col gap-1">
      <legend className="mb-1 text-sm font-medium">{t("webhooks:form.kinds")}</legend>
      {choices.map((choice) => (
        <label key={choice} className="flex min-h-11 items-center gap-3 text-sm">
          <input
            type="radio"
            name="webhook-kinds"
            className="size-4"
            checked={value === choice}
            onChange={() => onChange(choice)}
          />
          {t(
            choice === "default"
              ? "webhooks:form.kindsDefault"
              : choice === "all"
                ? "webhooks:form.kindsAll"
                : "webhooks:form.kindsCustom",
          )}
        </label>
      ))}
    </fieldset>
  );
}

function CreateWebhookDialog({
  lang,
  onClose,
  onCreated,
}: {
  lang: string;
  onClose: () => void;
  onCreated: (secret: string) => void;
}) {
  const { t } = useTranslation(["webhooks", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<WebhookProblem | null>(null);
  const [pending, setPending] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const form = useForm({
    defaultValues: DEFAULT_WEBHOOK_DRAFT,
    onSubmit: async ({ value }) => {
      setAttempted(true);
      if (webhookDraftProblems(value).length > 0) return;
      setProblem(null);
      setPending(true);
      try {
        const result = await orpc.webhooks.create.call({
          url: value.url.trim(),
          ...(value.description.trim() ? { description: value.description.trim() } : {}),
          events: [...value.events],
          ...(value.kinds === "all" ? { operationKinds: "all" as const } : {}),
        });
        onCreated(result.secret);
      } catch (error) {
        if (!redirect(error)) setProblem(webhookProblem(error));
      } finally {
        setPending(false);
        invalidateWebhooks(queryClient);
      }
    },
  });
  const values = useStore(form.store, (state) => state.values);
  const problems = attempted ? webhookDraftProblems(values) : [];

  return (
    // The dialog cannot be dismissed mid-create, so a created secret is never lost.
    <Dialog open onOpenChange={(open) => (open || pending ? undefined : onClose())}>
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>{t("webhooks:create.title")}</DialogTitle>
          <DialogDescription>{t("webhooks:create.description")}</DialogDescription>
        </DialogHeader>
        <form
          noValidate
          className="flex min-w-0 flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void form.handleSubmit();
          }}
        >
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
          <form.Field name="events">
            {(field) => <EventCheckboxes value={field.state.value} onChange={field.handleChange} />}
          </form.Field>
          {values.events.includes("operation.completed") ? (
            <form.Field name="kinds">
              {(field) => (
                <KindsChoice
                  value={field.state.value}
                  onChange={field.handleChange}
                  allowCustom={false}
                />
              )}
            </form.Field>
          ) : null}
          {problems.length > 0 ? (
            <div role="alert" className="text-sm text-destructive">
              {problems.map((issue) => (
                <p key={issue}>
                  {issue === "destinationInvalid"
                    ? t("webhooks:problem.destinationInvalid")
                    : t(`webhooks:form.${issue}`)}
                </p>
              ))}
            </div>
          ) : null}
          {problem ? (
            <p role="alert" className="text-sm text-destructive">
              {t(`webhooks:problem.${problem}`)}
            </p>
          ) : null}
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="touch"
              disabled={pending}
              onClick={onClose}
            >
              {t("common:actions.cancel")}
            </Button>
            <Button type="submit" size="touch" disabled={pending}>
              {pending ? t("webhooks:create.submitting") : t("webhooks:create.submit")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
