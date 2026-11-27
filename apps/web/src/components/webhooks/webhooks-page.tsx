import { type QueryClient, useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Badge } from "@wssp/ui/components/badge";
import { buttonVariants } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import { cn } from "@wssp/ui/lib/utils";
import { Plus } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { LoadMore } from "@/components/load-more";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  WEBHOOK_EVENT_TYPES,
  type WebhookDraft,
  type WebhookDraftProblem,
  webhookDraftProblems,
  webhookHost,
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

export const DEFAULT_WEBHOOK_DRAFT: WebhookDraft = {
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
  const rows = endpoints.data?.pages.flatMap((page) => page.items);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t("webhooks:title")}
        description={t("webhooks:description")}
        actions={
          configured ? (
            <Link
              to="/$lang/settings/webhooks/new"
              params={{ lang }}
              data-webhook-add=""
              className={cn(buttonVariants({ size: "touch" }), "self-start")}
            >
              <Plus aria-hidden="true" />
              {t("webhooks:create.action")}
            </Link>
          ) : null
        }
      />
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
            fetchStatus: endpoints.fetchStatus,
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
                {items.map((endpoint) => {
                  const failing = endpoint.health.consecutiveFailures > 0;
                  return (
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
                        {/* An enabled endpoint whose latest deliveries fail is not healthy:
                          say so in the badge, not only in grey text below. */}
                        <Badge
                          data-webhook-status={
                            !endpoint.enabled ? "disabled" : failing ? "failing" : "enabled"
                          }
                          variant={
                            !endpoint.enabled ? "destructive" : failing ? "warning" : "secondary"
                          }
                        >
                          {!endpoint.enabled
                            ? t("webhooks:status.disabled")
                            : failing
                              ? t("webhooks:status.failing")
                              : t("webhooks:status.enabled")}
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
                      {endpoint.enabled || failing ? (
                        <p
                          className={cn(
                            "text-sm",
                            failing ? "font-medium text-state-warning" : "text-muted-foreground",
                          )}
                        >
                          {endpoint.health.consecutiveFailures > 0
                            ? t("webhooks:list.failing", {
                                count: endpoint.health.consecutiveFailures,
                              })
                            : t("webhooks:list.healthy")}
                        </p>
                      ) : null}
                    </li>
                  );
                })}
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
    </div>
  );
}

type WebhookEvent = (typeof WEBHOOK_EVENT_TYPES)[number];

/** Events by resource ("sandbox.ready" → "sandbox"), in the catalog's order. */
function webhookEventGroups(): [string, WebhookEvent[]][] {
  const groups = new Map<string, WebhookEvent[]>();
  for (const event of WEBHOOK_EVENT_TYPES) {
    const group = event.slice(0, event.indexOf("."));
    groups.set(group, [...(groups.get(group) ?? []), event]);
  }
  return [...groups];
}

/**
 * Event choice grouped by resource, each group with a tri-state "all" box
 * (checked, mixed, clear). Every event shows its human label with the raw
 * event id underneath for developers.
 */
export function EventCheckboxes({
  value,
  onChange,
  errorId,
  invalid = false,
}: {
  value: readonly WebhookEvent[];
  onChange: (next: WebhookEvent[]) => void;
  /** The inline error's id while "choose at least one" is showing. */
  errorId?: string;
  invalid?: boolean;
}) {
  const { t } = useTranslation(["webhooks"]);
  const idBase = useId();
  const ordered = (chosen: ReadonlySet<WebhookEvent>) =>
    WEBHOOK_EVENT_TYPES.filter((item) => chosen.has(item));
  return (
    <fieldset
      data-webhook-events=""
      aria-describedby={invalid ? errorId : undefined}
      className="flex min-w-0 flex-col gap-3"
    >
      <legend className="mb-1 text-sm font-medium">{t("webhooks:form.events")}</legend>
      <div className="grid min-w-0 gap-3 sm:grid-cols-2">
        {webhookEventGroups().map(([group, events], index) => {
          const chosen = events.filter((event) => value.includes(event));
          const all = chosen.length === events.length;
          const some = chosen.length > 0 && !all;
          const titleId = `${idBase}-${group}`;
          return (
            <div
              key={group}
              role="group"
              aria-labelledby={titleId}
              data-event-group={group}
              className="flex min-w-0 flex-col gap-1 rounded-lg border p-3"
            >
              {events.length > 1 ? (
                <label className="flex min-h-11 items-center gap-3 text-sm">
                  <Checkbox
                    data-event-group-all={group}
                    checked={all}
                    indeterminate={some}
                    aria-invalid={invalid && index === 0 ? true : undefined}
                    aria-describedby={invalid && index === 0 ? errorId : undefined}
                    aria-label={t("webhooks:form.groupAll", {
                      group: t(`webhooks:eventGroup.${group}`),
                    })}
                    onCheckedChange={(checked) => {
                      const next = new Set(value);
                      for (const event of events) {
                        if (checked) next.add(event);
                        else next.delete(event);
                      }
                      onChange(ordered(next));
                    }}
                  />
                  <span id={titleId} className="font-medium">
                    {t(`webhooks:eventGroup.${group}`)}
                  </span>
                  <span className="ms-auto text-xs text-muted-foreground tabular-nums">
                    {t("webhooks:form.groupCount", { chosen: chosen.length, total: events.length })}
                  </span>
                </label>
              ) : (
                <span id={titleId} className="flex min-h-11 items-center text-sm font-medium">
                  {t(`webhooks:eventGroup.${group}`)}
                </span>
              )}
              <ul className={cn("flex min-w-0 flex-col", events.length > 1 && "ps-7")}>
                {events.map((event) => (
                  <li key={event}>
                    <label className="flex min-h-11 min-w-0 items-center gap-3 py-1 text-sm">
                      <Checkbox
                        checked={value.includes(event)}
                        aria-invalid={
                          invalid && index === 0 && events.length === 1 ? true : undefined
                        }
                        onCheckedChange={(checked) => {
                          const next = new Set(value);
                          if (checked) next.add(event);
                          else next.delete(event);
                          onChange(ordered(next));
                        }}
                      />
                      <span className="min-w-0">
                        <span className="block">{t(`webhooks:event.${event}`)}</span>
                        <span className="block font-mono text-xs text-muted-foreground [overflow-wrap:anywhere]">
                          {event}
                        </span>
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}

/** The short name of an operation-kinds choice, for a collapsed section's summary. */
export function kindsSummaryKey(kinds: WebhookDraft["kinds"]) {
  return kinds === "all"
    ? "webhooks:form.kindsAllShort"
    : kinds === "custom"
      ? "webhooks:form.kindsCustomShort"
      : "webhooks:form.kindsDefaultShort";
}

/**
 * The draft rules as a form schema, so each problem shows next to its own
 * field (URL, events, description) instead of in a list at the bottom.
 */
export function webhookDraftSchema(t: (key: string) => string) {
  const field: Record<WebhookDraftProblem, "url" | "events" | "description"> = {
    urlRequired: "url",
    urlTooLong: "url",
    destinationInvalid: "url",
    eventsRequired: "events",
    descriptionTooLong: "description",
  };
  return z.custom<WebhookDraft>().superRefine((draft, ctx) => {
    for (const problem of webhookDraftProblems(draft))
      ctx.addIssue({
        code: "custom",
        path: [field[problem]],
        message:
          problem === "destinationInvalid"
            ? t("webhooks:problem.destinationInvalid")
            : t(`webhooks:form.${problem}`),
      });
  });
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
