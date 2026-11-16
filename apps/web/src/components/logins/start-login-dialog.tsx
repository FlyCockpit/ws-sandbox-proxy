import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { Button } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import type { TFunction } from "i18next";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { FormSelect } from "@/components/form-select";
import { LoadMore } from "@/components/load-more";
import {
  type AccountItem,
  accountLabel,
  type InstanceItem,
  instanceLabel,
  invalidateLogins,
  type LoginItem,
} from "@/components/logins/logins-shared";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { credentialErrorCode } from "@/lib/credential-errors";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

/**
 * Start a login sandbox: "Add account"
 * (a new account and its first instance), "Add another instance" (a new
 * instance of an account) or "Re-login" (an existing instance). The server
 * places a small, short-lived sandbox, then the session page shows its
 * terminal. A pool target without an own host that fits refuses
 * `login_needs_consent`; the dialog then asks for consent to a host the
 * owner does not own and retries with `allowForeignHost`.
 */

export type StartLoginTarget =
  | { kind: "newAccount" }
  | { kind: "newInstance"; account: AccountItem }
  | { kind: "relogin"; account: AccountItem; instance: InstanceItem };

type StartLoginInput = Parameters<AppRouterClient["logins"]["startLogin"]>[0];

/** §11: 30 minutes by default, at most 2 hours. */
const LOGIN_TIMEOUT_DEFAULT_MIN = 30;
const LOGIN_TIMEOUT_MAX_MIN = 120;

const PICKER_LIMIT = 100;
const cursorPages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

type StartLoginDraft = {
  name: string;
  placement: "host" | "pool";
  hostId: string;
  poolId: string;
  templateId: string;
  egressDomains: string;
  timeoutMinutes: string;
};

/** Egress domains, one per line (blank lines ignored). */
function parseEgressDomains(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function draftSchema(t: TFunction) {
  return z
    .object({
      name: z.string().trim().max(80, t("logins:form.nameTooLong")),
      placement: z.enum(["host", "pool"]),
      hostId: z.string(),
      poolId: z.string(),
      templateId: z.string().min(1, t("logins:session.start.templateRequired")),
      egressDomains: z
        .string()
        .refine(
          (value) =>
            parseEgressDomains(value).length <= 32 &&
            parseEgressDomains(value).every((domain) => domain.length <= 253 && !/\s/.test(domain)),
          t("logins:session.start.egressInvalid"),
        ),
      timeoutMinutes: z
        .string()
        .refine(
          (value) =>
            /^\d+$/.test(value.trim()) &&
            Number(value) >= 1 &&
            Number(value) <= LOGIN_TIMEOUT_MAX_MIN,
          t("logins:session.start.timeoutRange", { max: LOGIN_TIMEOUT_MAX_MIN }),
        ),
    })
    .superRefine((draft, context) => {
      if (draft.placement === "host" && !draft.hostId)
        context.addIssue({
          code: "custom",
          path: ["hostId"],
          message: t("logins:session.start.placementRequired"),
        });
      if (draft.placement === "pool" && !draft.poolId)
        context.addIssue({
          code: "custom",
          path: ["poolId"],
          message: t("logins:session.start.placementRequired"),
        });
    });
}

/** The startLogin input for a draft and target (pure; the server re-checks everything). */
function startLoginInput(
  login: Pick<LoginItem, "id">,
  target: StartLoginTarget,
  draft: StartLoginDraft,
  allowForeignHost: boolean,
): StartLoginInput {
  const name = draft.name.trim();
  const named = name ? { name } : {};
  const domains = parseEgressDomains(draft.egressDomains);
  return {
    credentialId: login.id,
    ...(target.kind === "newAccount"
      ? { newAccount: named, newInstance: {} }
      : target.kind === "newInstance"
        ? { accountId: target.account.id, newInstance: named }
        : { accountId: target.account.id, instanceId: target.instance.id }),
    ...(draft.placement === "pool" ? { poolId: draft.poolId } : { sandboxHostId: draft.hostId }),
    template: `template/${draft.templateId}`,
    ...(domains.length > 0 ? { egressDomains: domains } : {}),
    ...(allowForeignHost ? { allowForeignHost: true } : {}),
    timeoutMs: Number(draft.timeoutMinutes.trim()) * 60_000,
  };
}

export function StartLoginDialog({
  lang,
  login,
  target,
  onClose,
}: {
  lang: string;
  login: LoginItem;
  target: StartLoginTarget;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "sandboxes", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const redirect = useTwoFactorRedirect(lang);
  const placementId = useId();
  const hostSelectId = useId();
  const poolSelectId = useId();
  const templateSelectId = useId();
  const consentId = useId();
  const [needsConsent, setNeedsConsent] = useState(false);
  const [consent, setConsent] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [needsUpload, setNeedsUpload] = useState(false);

  const hostsQuery = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = (hostsQuery.data?.pages.flatMap((page) => page.items) ?? []).filter(
    (host) => host.deletionRequestedAt == null && !host.draining,
  );
  const poolsQuery = useInfiniteQuery({
    ...orpc.sandboxPools.listUsable.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const pools = poolsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const templatesQuery = useInfiniteQuery({
    ...orpc.sandboxTemplates.listTemplates.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor, status: "active" }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const templates = templatesQuery.data?.pages.flatMap((page) => page.items) ?? [];
  useTwoFactorRedirectOnError(lang, [hostsQuery.error, poolsQuery.error, templatesQuery.error]);

  const start = useMutation({
    ...orpc.logins.startLogin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: {
      name: "",
      placement: "host",
      hostId: "",
      poolId: "",
      templateId: "",
      egressDomains: "",
      timeoutMinutes: String(LOGIN_TIMEOUT_DEFAULT_MIN),
    } as StartLoginDraft,
    validators: { onSubmit: draftSchema(t) },
    onSubmit: async ({ value }) => {
      setProblem(null);
      setNeedsUpload(false);
      if (needsConsent && !consent) {
        setProblem(t("logins:session.consent.required"));
        return;
      }
      try {
        const started = await start.mutateAsync(
          startLoginInput(login, target, value, needsConsent && consent),
        );
        invalidateLogins(queryClient);
        onClose();
        void navigate({
          to: "/$lang/settings/logins/sessions/$sessionId",
          params: { lang, sessionId: started.sessionId },
        });
      } catch (error) {
        if (redirect(error)) return;
        const code = credentialErrorCode(error);
        if (code === "login_needs_consent") {
          setNeedsConsent(true);
          return;
        }
        if (code === "login_requires_upload") setNeedsUpload(true);
        setProblem(friendly(error));
      }
    },
  });
  const placement = useStore(form.store, (state) => state.values.placement);
  const pending = start.isPending;
  const title =
    target.kind === "newAccount"
      ? t("logins:session.start.titleAccount")
      : target.kind === "newInstance"
        ? translateText(t, "logins:session.start.titleInstance", {
            account: accountLabel(t, target.account),
          })
        : translateText(t, "logins:session.start.titleRelogin", {
            instance: instanceLabel(t, target.instance),
          });

  return (
    <Dialog open onOpenChange={(open) => (open || pending ? undefined : onClose())}>
      <DialogContent
        closeLabel={t("common:actions.close")}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{t("logins:session.start.description")}</DialogDescription>
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
          {target.kind !== "relogin" ? (
            <>
              <p className="text-sm text-muted-foreground">
                {t("logins:session.start.unverifiedAccount")}
              </p>
              <form.Field name="name">
                {(field) => (
                  <TextField
                    field={field}
                    label={
                      target.kind === "newAccount"
                        ? t("logins:session.start.accountName")
                        : t("logins:session.start.instanceName")
                    }
                    description={t("logins:form.optionalNameHint")}
                    inputMode="text"
                    autoComplete="off"
                    inputClassName="min-h-11"
                    maxLength={80}
                  />
                )}
              </form.Field>
            </>
          ) : (
            <p className="text-sm text-muted-foreground">{t("logins:session.start.reloginHint")}</p>
          )}
          <fieldset className="flex min-w-0 flex-col gap-2" disabled={pending}>
            <Label htmlFor={placementId}>{t("sandboxes:create.placement")}</Label>
            <form.Field name="placement">
              {(field) => (
                <FormSelect
                  id={placementId}
                  autoComplete="off"
                  value={field.state.value}
                  onValueChange={(value) => {
                    field.handleChange(value as "host" | "pool");
                    setNeedsConsent(false);
                    setConsent(false);
                  }}
                >
                  <SelectItem value="host">{t("sandboxes:create.direct")}</SelectItem>
                  <SelectItem value="pool">{t("sandboxes:create.pool")}</SelectItem>
                </FormSelect>
              )}
            </form.Field>
            {placement === "host" ? (
              <form.Field name="hostId">
                {(field) => (
                  <div className="flex min-w-0 flex-col gap-2">
                    <Label htmlFor={hostSelectId}>{t("sandboxes:create.host")}</Label>
                    <FormSelect
                      id={hostSelectId}
                      autoComplete="off"
                      optionsSettled={
                        hostsQuery.isSuccess && !hostsQuery.isFetching && !hostsQuery.hasNextPage
                      }
                      value={field.state.value}
                      onValueChange={field.handleChange}
                      aria-invalid={field.state.meta.errors.length > 0 || undefined}
                    >
                      <SelectItem value="">{t("sandboxes:create.chooseHost")}</SelectItem>
                      {hosts.map((host) => (
                        <SelectItem key={host.id} value={host.id}>
                          {translateText(t, "logins:session.start.option", {
                            label: host.label,
                            slug: host.slug,
                          })}
                        </SelectItem>
                      ))}
                    </FormSelect>
                    <p className="text-xs text-muted-foreground">
                      {t("logins:session.start.ownHostHint")}
                    </p>
                    <FieldErrors errors={field.state.meta.errors} />
                    <LoadMore
                      hasNextPage={hostsQuery.hasNextPage}
                      isFetchingNextPage={hostsQuery.isFetchingNextPage}
                      onLoadMore={() => void hostsQuery.fetchNextPage()}
                      label={t("sandboxes:create.moreHosts")}
                    />
                  </div>
                )}
              </form.Field>
            ) : (
              <form.Field name="poolId">
                {(field) => (
                  <div className="flex min-w-0 flex-col gap-2">
                    <Label htmlFor={poolSelectId}>{t("sandboxes:create.pool")}</Label>
                    <FormSelect
                      id={poolSelectId}
                      autoComplete="off"
                      optionsSettled={
                        poolsQuery.isSuccess && !poolsQuery.isFetching && !poolsQuery.hasNextPage
                      }
                      value={field.state.value}
                      onValueChange={(value) => {
                        field.handleChange(value);
                        setNeedsConsent(false);
                        setConsent(false);
                      }}
                      aria-invalid={field.state.meta.errors.length > 0 || undefined}
                    >
                      <SelectItem value="">{t("sandboxes:create.choosePool")}</SelectItem>
                      {pools.map((pool) => (
                        <SelectItem key={pool.id} value={pool.id}>
                          {translateText(t, "logins:session.start.option", {
                            label: pool.label,
                            slug: pool.slug,
                          })}
                        </SelectItem>
                      ))}
                    </FormSelect>
                    <FieldErrors errors={field.state.meta.errors} />
                    <LoadMore
                      hasNextPage={poolsQuery.hasNextPage}
                      isFetchingNextPage={poolsQuery.isFetchingNextPage}
                      onLoadMore={() => void poolsQuery.fetchNextPage()}
                    />
                  </div>
                )}
              </form.Field>
            )}
          </fieldset>
          <form.Field name="templateId">
            {(field) => (
              <fieldset className="flex min-w-0 flex-col gap-2" disabled={pending}>
                <Label htmlFor={templateSelectId}>{t("sandboxes:create.template")}</Label>
                <FormSelect
                  id={templateSelectId}
                  autoComplete="off"
                  optionsSettled={
                    templatesQuery.isSuccess &&
                    !templatesQuery.isFetching &&
                    !templatesQuery.hasNextPage
                  }
                  value={field.state.value}
                  onValueChange={field.handleChange}
                  aria-invalid={field.state.meta.errors.length > 0 || undefined}
                >
                  <SelectItem value="">{t("sandboxes:create.chooseTemplate")}</SelectItem>
                  {templates.map((template) => (
                    <SelectItem key={template.id} value={template.id}>
                      {translateText(t, "logins:session.start.option", {
                        label: template.label,
                        slug: template.slug,
                      })}
                    </SelectItem>
                  ))}
                </FormSelect>
                <FieldErrors errors={field.state.meta.errors} />
                <LoadMore
                  hasNextPage={templatesQuery.hasNextPage}
                  isFetchingNextPage={templatesQuery.isFetchingNextPage}
                  onLoadMore={() => void templatesQuery.fetchNextPage()}
                  label={t("sandboxes:create.moreTemplates")}
                />
              </fieldset>
            )}
          </form.Field>
          <form.Field name="egressDomains">
            {(field) => (
              <TextareaField
                field={field}
                label={t("logins:session.start.egress")}
                description={t("logins:session.start.egressHint")}
                autoComplete="off"
                inputClassName="font-mono"
                rows={2}
                disabled={pending}
              />
            )}
          </form.Field>
          <form.Field name="timeoutMinutes">
            {(field) => (
              <TextField
                field={field}
                label={t("logins:session.start.timeout")}
                description={t("logins:session.start.timeoutHint", {
                  max: LOGIN_TIMEOUT_MAX_MIN,
                })}
                inputMode="numeric"
                autoComplete="off"
                inputClassName="min-h-11"
                maxLength={3}
              />
            )}
          </form.Field>
          {needsConsent ? (
            <div
              role="alert"
              data-login-consent=""
              className="flex min-w-0 flex-col gap-2 rounded-lg border border-amber-500/50 p-3 text-sm"
            >
              <p className="font-medium">{t("logins:session.consent.title")}</p>
              <p>{t("logins:session.consent.warning")}</p>
              <div className="flex min-h-11 items-center gap-3">
                <Checkbox
                  id={consentId}
                  checked={consent}
                  onCheckedChange={(checked) => setConsent(checked === true)}
                />
                <Label htmlFor={consentId}>{t("logins:session.consent.checkbox")}</Label>
              </div>
            </div>
          ) : null}
          {problem ? (
            <div role="alert" className="flex flex-col gap-1 text-sm text-destructive">
              <p>{problem}</p>
              {needsUpload ? (
                <p className="text-muted-foreground">{t("logins:session.start.uploadHint")}</p>
              ) : null}
            </div>
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
            <Button type="submit" size="touch" disabled={pending || (needsConsent && !consent)}>
              {pending ? t("logins:session.start.submitting") : t("logins:session.start.submit")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function FieldErrors({ errors }: { errors: readonly unknown[] }) {
  const messages = errors
    .map((error) =>
      typeof error === "string"
        ? error
        : error && typeof error === "object" && "message" in error
          ? String((error as { message: unknown }).message)
          : null,
    )
    .filter((message): message is string => !!message);
  if (messages.length === 0) return null;
  return (
    <p role="alert" className="text-sm text-destructive">
      {messages[0]}
    </p>
  );
}
