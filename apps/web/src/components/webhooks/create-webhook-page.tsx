import { useForm, useStore } from "@tanstack/react-form";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { AdvancedSection, FormPage, FormSection } from "@wssp/ui/components/form-page";
import { FieldError, TextField } from "@wssp/ui/components/text-field";
import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { cn } from "@wssp/ui/lib/utils";
import { ChevronLeft } from "lucide-react";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { OneTimeSecretPanel, SecretLeaveGuard } from "@/components/credentials/credential-parts";
import { EmptyState } from "@/components/empty-state";
import { FormPageStatus } from "@/components/form-page-status";
import { InlineRetry } from "@/components/inline-retry";
import { PageHeader } from "@/components/page-shell";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { type WebhookProblem, webhookProblem } from "@/lib/webhook-rules";
import { orpc } from "@/utils/orpc";
import {
  DEFAULT_WEBHOOK_DRAFT,
  EventCheckboxes,
  invalidateWebhooks,
  KindsChoice,
  kindsSummaryKey,
  webhookDraftSchema,
} from "./webhooks-page";

function WebhooksBackLink({ lang, disabled = false }: { lang: string; disabled?: boolean }) {
  const { t } = useTranslation("webhooks");
  return (
    <Link
      to="/$lang/settings/webhooks"
      params={{ lang }}
      disabled={disabled}
      data-webhooks-back=""
      className="-ms-2 inline-flex min-h-11 items-center gap-1 rounded-md px-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring aria-disabled:pointer-events-none aria-disabled:opacity-50"
    >
      <ChevronLeft aria-hidden="true" className="size-4" />
      {t("title")}
    </Link>
  );
}

/**
 * Add a webhook endpoint: a page (the event list does not fit a dialog).
 * Essential: the URL and the events, grouped by resource. The description
 * and the operation kinds wait under Advanced. After it is created the
 * signing secret is shown once, then "Open endpoint" goes to its page.
 * While the request is pending and while the secret is shown, leaving asks
 * first: a create still in flight would reveal its secret to nobody.
 */
export function CreateWebhookPage({ lang }: { lang: string }) {
  const { t } = useTranslation(["webhooks", "common"]);
  const status = useQuery({
    ...orpc.webhooks.status.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [status.error]);
  const navigate = useNavigate();
  const [created, setCreated] = useState<{ id: string; secret: string } | null>(null);
  const [pending, setPending] = useState(false);
  const guard = <SecretLeaveGuard active={pending || created !== null} />;
  if (status.isPending) return <SkeletonList layout="resource" count={2} />;
  // A failed read is not "not configured": say so and offer a retry.
  if (status.data === undefined)
    return (
      <div className="flex min-w-0 flex-col gap-6">
        <PageHeader back={<WebhooksBackLink lang={lang} />} title={t("webhooks:create.title")} />
        <InlineRetry
          message={t("webhooks:create.statusFailed")}
          onRetry={() => void status.refetch()}
        />
      </div>
    );
  if (!status.data.configured)
    return (
      <div className="flex min-w-0 flex-col gap-6">
        <PageHeader back={<WebhooksBackLink lang={lang} />} title={t("webhooks:create.title")} />
        <EmptyState
          className="rounded-xl border px-4"
          title={t("webhooks:notConfigured.title")}
          description={t("webhooks:notConfigured.description")}
        />
      </div>
    );
  if (created)
    return (
      <div data-webhook-created="" className="flex min-w-0 flex-col gap-6">
        {guard}
        <PageHeader
          back={<WebhooksBackLink lang={lang} />}
          title={t("webhooks:create.createdTitle")}
          description={t("webhooks:create.createdDescription")}
        />
        <OneTimeSecretPanel
          secret={created.secret}
          label={t("webhooks:create.secretLabel")}
          onDone={() =>
            void navigate({
              to: "/$lang/settings/webhooks/$endpointId",
              params: { lang, endpointId: created.id },
              // Done is the person confirming the secret is saved.
              ignoreBlocker: true,
            })
          }
        >
          <p className="text-sm text-muted-foreground">{t("webhooks:create.secretHint")}</p>
        </OneTimeSecretPanel>
      </div>
    );
  return (
    <>
      {guard}
      <CreateWebhookForm
        lang={lang}
        onCreated={setCreated}
        pending={pending}
        setPending={setPending}
      />
    </>
  );
}

function CreateWebhookForm({
  lang,
  onCreated,
  pending,
  setPending,
}: {
  lang: string;
  onCreated: (created: { id: string; secret: string }) => void;
  pending: boolean;
  setPending: (pending: boolean) => void;
}) {
  const { t } = useTranslation(["webhooks", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const root = useRef<HTMLDivElement>(null);
  const eventsErrorId = useId();
  const [problem, setProblem] = useState<WebhookProblem | null>(null);
  const form = useForm({
    defaultValues: DEFAULT_WEBHOOK_DRAFT,
    validators: { onSubmit: webhookDraftSchema(t) },
    onSubmitInvalid: () => focusFirstInvalidField(root.current),
    onSubmit: async ({ value }) => {
      setProblem(null);
      setPending(true);
      try {
        const result = await orpc.webhooks.create.call({
          url: value.url.trim(),
          ...(value.description.trim() ? { description: value.description.trim() } : {}),
          events: [...value.events],
          ...(value.kinds === "all" ? { operationKinds: "all" as const } : {}),
        });
        onCreated({ id: result.endpoint.id, secret: result.secret });
      } catch (error) {
        if (!redirect(error)) {
          const next = webhookProblem(error);
          if (next === "destinationInvalid") {
            form.setFieldMeta("url", (meta) => ({
              ...meta,
              errorMap: {
                ...meta.errorMap,
                onSubmit: t("webhooks:problem.destinationUnreachable"),
              },
            }));
            focusFirstInvalidField(root.current);
          } else setProblem(next);
        }
      } finally {
        setPending(false);
        invalidateWebhooks(queryClient);
      }
    },
  });
  const values = useStore(form.store, (state) => state.values);
  const pageTitle = t("webhooks:create.title");
  return (
    <FormPage
      noValidate
      // Inside the dashboard frame, which already pads the content column.
      className="px-0 pt-0"
      title={pageTitle}
      aria-label={pageTitle}
      description={t("webhooks:create.description")}
      back={<WebhooksBackLink lang={lang} disabled={pending} />}
      onSubmit={(event) => {
        event.preventDefault();
        event.stopPropagation();
        void form.handleSubmit();
      }}
      actions={
        <>
          <FormPageStatus>
            {t("webhooks:create.status", { count: values.events.length })}
          </FormPageStatus>
          <Link
            to="/$lang/settings/webhooks"
            params={{ lang }}
            disabled={pending}
            data-webhook-cancel=""
            className={cn(
              buttonVariants({ size: "touch", variant: "outline" }),
              "aria-disabled:pointer-events-none aria-disabled:opacity-50",
            )}
          >
            {t("common:actions.cancel")}
          </Link>
          <Button type="submit" size="touch" disabled={pending}>
            {pending ? t("webhooks:create.submitting") : t("webhooks:create.submit")}
          </Button>
        </>
      }
    >
      <div ref={root} data-webhook-form="create" className="min-w-0 space-y-8">
        <FormSection title={t("webhooks:form.destination")}>
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
        </FormSection>
        <FormSection
          title={t("webhooks:form.events")}
          description={t("webhooks:form.eventsHint")}
          gridClassName="lg:grid-cols-1"
        >
          <form.Field name="events">
            {(field) => (
              <>
                <EventCheckboxes
                  value={field.state.value}
                  onChange={field.handleChange}
                  invalid={field.state.meta.errors.length > 0}
                  errorId={eventsErrorId}
                />
                <FieldError id={eventsErrorId} errors={field.state.meta.errors} />
              </>
            )}
          </form.Field>
        </FormSection>
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
        {values.events.includes("operation.completed") ? (
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
                  allowCustom={false}
                />
              )}
            </form.Field>
          </AdvancedSection>
        ) : null}
        {problem ? (
          <p role="alert" className="text-sm text-destructive">
            {t(`webhooks:problem.${problem}`)}
          </p>
        ) : null}
      </div>
    </FormPage>
  );
}
