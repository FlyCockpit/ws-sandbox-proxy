import { useForm } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@wssp/ui/components/sheet";
import { toast } from "@wssp/ui/components/sileo";
import { Switch } from "@wssp/ui/components/switch";
import { TextField } from "@wssp/ui/components/text-field";
import type { TFunction } from "i18next";
import { Plus } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { LoadMore } from "@/components/load-more";
import { InstanceRecovery } from "@/components/logins/login-instance-admin";
import {
  type AccountItem,
  accountLabel,
  type InstanceItem,
  instanceLabel,
  invalidateLogins,
  type LoginItem,
  ProblemText,
} from "@/components/logins/logins-shared";
import { StartLoginDialog, type StartLoginTarget } from "@/components/logins/start-login-dialog";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { dateTimeTitle } from "@/lib/format-date-time";
import {
  definitionFiles,
  fileToBase64,
  type LoginDefinition,
  type LoginProblem,
  loginProblem,
  loginProblemEntry,
  totalBytes,
} from "@/lib/login-rules";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * Accounts (provider accounts, pausable, optional names) and their instances
 * (independent token sets with automatic READY / NEEDS_LOGIN / EMPTY states;
 * no pause). Values are write-only: Upload sends one, and the page shows only
 * metadata (state, holders, last capture).
 */

function nameSchema(t: TFunction) {
  return z.object({
    name: z.string().trim().max(80, t("logins:form.nameTooLong")),
  });
}

function maxConcurrentProblem(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed === "") return false;
  return !/^\d+$/.test(trimmed) || Number(trimmed) < 1 || Number(trimmed) > 100_000;
}

function instanceSchema(t: TFunction) {
  return z.object({
    name: z.string().trim().max(80, t("logins:form.nameTooLong")),
    maxConcurrent: z
      .string()
      .refine((value) => !maxConcurrentProblem(value), t("logins:form.maxConcurrentRange")),
  });
}

const parseMaxConcurrent = (value: string) => (value.trim() === "" ? null : Number(value.trim()));

export function AccountsSection({
  lang,
  login,
  definition,
  writable,
}: {
  lang: string;
  login: LoginItem;
  /** `undefined` while loading; `null` when the pinned definition no longer parses. */
  definition: LoginDefinition | null | undefined;
  writable: boolean;
}) {
  const { t } = useTranslation(["logins", "dashboard", "common"]);
  const accounts = useInfiniteQuery({
    ...orpc.logins.listAccounts.infiniteOptions({
      input: (cursor: string | undefined) => ({
        credentialId: login.id,
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [accounts.error]);
  const [adding, setAdding] = useState(false);
  const [loggingIn, setLoggingIn] = useState(false);
  const rows = accounts.data?.pages.flatMap((page) => page.items);

  return (
    <section aria-labelledby="accounts-heading" className="flex min-w-0 flex-col gap-3">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <h2 id="accounts-heading" className="font-heading text-lg font-semibold">
            {t("logins:accounts.heading")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("logins:accounts.description")}</p>
        </div>
        {writable ? (
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="touch" onClick={() => setLoggingIn(true)}>
              <Plus aria-hidden="true" />
              {t("logins:session.addAccount")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={() => setAdding(true)}>
              {t("logins:accounts.addEmpty")}
            </Button>
          </div>
        ) : null}
      </div>
      <QueryBoundary
        query={{
          data: rows,
          isPending: accounts.isPending,
          isError: accounts.isError,
          fetchStatus: accounts.fetchStatus,
          error: accounts.error,
          refetch: accounts.refetch,
        }}
        skeleton={<SkeletonList layout="resource" count={2} className="rounded-xl border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={
          <EmptyState
            className="rounded-xl border px-4"
            title={t("logins:accounts.empty.title")}
            description={t("logins:accounts.empty.description")}
          />
        }
      >
        {(items) => (
          <>
            <ul aria-label={t("logins:accounts.label")} className="flex min-w-0 flex-col gap-4">
              {items.map((account) => (
                <AccountCard
                  key={account.id}
                  lang={lang}
                  login={login}
                  account={account}
                  definition={definition}
                  writable={writable}
                />
              ))}
            </ul>
            <LoadMore
              hasNextPage={accounts.hasNextPage}
              isFetchingNextPage={accounts.isFetchingNextPage}
              onLoadMore={() => void accounts.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      {adding ? (
        <AddAccountDialog lang={lang} login={login} onClose={() => setAdding(false)} />
      ) : null}
      {loggingIn ? (
        <StartLoginDialog
          lang={lang}
          login={login}
          target={{ kind: "newAccount" }}
          onClose={() => setLoggingIn(false)}
        />
      ) : null}
    </section>
  );
}

function AccountCard({
  lang,
  login,
  account,
  definition,
  writable,
}: {
  lang: string;
  login: LoginItem;
  account: AccountItem;
  /** `undefined` while loading; `null` when the pinned definition no longer parses. */
  definition: LoginDefinition | null | undefined;
  writable: boolean;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const pauseId = useId();
  const [renaming, setRenaming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const label = accountLabel(t, account);
  const update = useMutation({
    ...orpc.logins.updateAccount.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSettled: () => invalidateLogins(queryClient),
  });
  const remove = useMutation({
    ...orpc.logins.deleteAccount.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });

  return (
    <li
      data-account-id={account.id}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h3 className="break-words font-medium">{label}</h3>
          {account.paused ? (
            <Badge variant="destructive">{t("logins:accounts.paused")}</Badge>
          ) : null}
        </div>
        {writable ? (
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="touch" variant="outline" onClick={() => setRenaming(true)}>
              {t("logins:accounts.rename")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={() => setDeleting(true)}>
              {t("common:actions.delete")}
            </Button>
          </div>
        ) : null}
      </div>
      <div className="flex min-h-11 min-w-0 items-center justify-between gap-3 text-sm">
        <label htmlFor={pauseId} className="min-w-0 space-y-0.5">
          <span className="block font-medium">{t("logins:accounts.pause")}</span>
          <span className="block text-muted-foreground">{t("logins:accounts.pauseHint")}</span>
        </label>
        <Switch
          id={pauseId}
          checked={account.paused}
          disabled={!writable || update.isPending}
          onCheckedChange={async (checked) => {
            setProblem(null);
            try {
              await update.mutateAsync({
                credentialId: login.id,
                accountId: account.id,
                paused: checked,
              });
              toast.success(
                checked
                  ? t("logins:accounts.pausedDone", { name: label })
                  : t("logins:accounts.resumedDone", { name: label }),
              );
            } catch (error) {
              if (!redirect(error)) setProblem(loginProblem(error));
            }
          }}
        />
      </div>
      <ProblemText problem={problem} />
      <InstancesList
        lang={lang}
        login={login}
        account={account}
        definition={definition}
        writable={writable}
      />
      {renaming ? (
        <RenameAccountSheet
          lang={lang}
          login={login}
          account={account}
          onClose={() => setRenaming(false)}
        />
      ) : null}
      <ConfirmDeleteDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={t("logins:accounts.deleteTitle", { name: label })}
        description={t("logins:accounts.deleteDescription")}
        confirmToken={label}
        typePrompt={t("logins:accounts.deletePrompt")}
        copyAriaLabel={t("logins:accounts.copyName")}
        isPending={remove.isPending}
        onConfirm={async () => {
          setProblem(null);
          try {
            await remove.mutateAsync({ credentialId: login.id, accountId: account.id });
            toast.success(t("logins:accounts.deleted"));
          } catch (error) {
            if (!redirect(error)) setProblem(loginProblem(error));
          } finally {
            setDeleting(false);
            invalidateLogins(queryClient);
          }
        }}
      />
    </li>
  );
}

function AddAccountDialog({
  lang,
  login,
  onClose,
}: {
  lang: string;
  login: LoginItem;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const create = useMutation({
    ...orpc.logins.createAccount.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { name: "" },
    validators: { onSubmit: nameSchema(t) },
    onSubmit: async ({ value }) => {
      setProblem(null);
      const name = value.name.trim();
      try {
        await create.mutateAsync({ credentialId: login.id, ...(name ? { name } : {}) });
      } catch (error) {
        if (!redirect(error)) setProblem(loginProblem(error));
        return;
      } finally {
        invalidateLogins(queryClient);
      }
      toast.success(t("logins:accounts.added"));
      onClose();
    },
  });

  return (
    <Dialog open onOpenChange={(open) => (open || create.isPending ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("logins:accounts.addTitle")}</DialogTitle>
          <DialogDescription>{t("logins:accounts.addDescription")}</DialogDescription>
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
          <form.Field name="name">
            {(field) => (
              <TextField
                field={field}
                label={t("logins:form.optionalName")}
                inputMode="text"
                autoComplete="off"
                inputClassName="min-h-11"
                maxLength={80}
              />
            )}
          </form.Field>
          <ProblemText problem={problem} />
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="touch"
              disabled={create.isPending}
              onClick={onClose}
            >
              {t("common:actions.cancel")}
            </Button>
            <Button type="submit" size="touch" disabled={create.isPending}>
              {t("logins:accounts.add")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RenameAccountSheet({
  lang,
  login,
  account,
  onClose,
}: {
  lang: string;
  login: LoginItem;
  account: AccountItem;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const update = useMutation({
    ...orpc.logins.updateAccount.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { name: account.name ?? "" },
    validators: { onSubmit: nameSchema(t) },
    onSubmit: async ({ value }) => {
      setProblem(null);
      try {
        await update.mutateAsync({
          credentialId: login.id,
          accountId: account.id,
          name: value.name.trim() || null,
        });
      } catch (error) {
        if (!redirect(error)) setProblem(loginProblem(error));
        return;
      } finally {
        invalidateLogins(queryClient);
      }
      toast.success(t("logins:edit.saved"));
      onClose();
    },
  });

  return (
    <Sheet open onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent closeLabel={t("common:actions.close")}>
        <SheetHeader>
          <SheetTitle>{t("logins:accounts.renameTitle")}</SheetTitle>
          <SheetDescription>{t("logins:form.optionalNameHint")}</SheetDescription>
        </SheetHeader>
        <form
          noValidate
          className="flex min-h-0 min-w-0 flex-1 flex-col"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void form.handleSubmit();
          }}
        >
          <SheetBody className="flex min-w-0 flex-col gap-4">
            <form.Field name="name">
              {(field) => (
                <TextField
                  field={field}
                  label={t("logins:form.optionalName")}
                  inputMode="text"
                  autoComplete="off"
                  inputClassName="min-h-11"
                  maxLength={80}
                />
              )}
            </form.Field>
            <ProblemText problem={problem} />
          </SheetBody>
          <SheetFooter>
            <Button type="button" variant="outline" size="touch" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
            <form.Subscribe selector={(formState) => formState.isSubmitting}>
              {(submitting) => (
                <Button type="submit" size="touch" disabled={submitting}>
                  {submitting ? t("common:actions.saving") : t("common:actions.saveChanges")}
                </Button>
              )}
            </form.Subscribe>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

function InstancesList({
  lang,
  login,
  account,
  definition,
  writable,
}: {
  lang: string;
  login: LoginItem;
  account: AccountItem;
  /** `undefined` while loading; `null` when the pinned definition no longer parses. */
  definition: LoginDefinition | null | undefined;
  writable: boolean;
}) {
  const { t } = useTranslation(["logins", "dashboard", "common"]);
  const instances = useInfiniteQuery({
    ...orpc.logins.listInstances.infiniteOptions({
      input: (cursor: string | undefined) => ({
        credentialId: login.id,
        accountId: account.id,
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [instances.error]);
  const [adding, setAdding] = useState(false);
  const [starting, setStarting] = useState<StartLoginTarget | null>(null);
  const rows = instances.data?.pages.flatMap((page) => page.items);

  return (
    <div className="flex min-w-0 flex-col gap-2">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-medium">{t("logins:instances.heading")}</h4>
        {writable ? (
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              size="touch"
              variant="outline"
              onClick={() => setStarting({ kind: "newInstance", account })}
            >
              <Plus aria-hidden="true" />
              {t("logins:session.addInstance")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={() => setAdding(true)}>
              {t("logins:instances.addEmpty")}
            </Button>
          </div>
        ) : null}
      </div>
      <QueryBoundary
        query={{
          data: rows,
          isPending: instances.isPending,
          isError: instances.isError,
          fetchStatus: instances.fetchStatus,
          error: instances.error,
          refetch: instances.refetch,
        }}
        skeleton={<SkeletonList count={1} className="rounded-lg border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={<p className="text-sm text-muted-foreground">{t("logins:instances.empty")}</p>}
      >
        {(items) => (
          <>
            <ul
              aria-label={t("logins:instances.label", { account: accountLabel(t, account) })}
              className="flex min-w-0 flex-col divide-y rounded-lg border"
            >
              {items.map((instance) => (
                <InstanceRow
                  key={instance.id}
                  lang={lang}
                  login={login}
                  instance={instance}
                  definition={definition}
                  writable={writable}
                  onRelogin={() => setStarting({ kind: "relogin", account, instance })}
                />
              ))}
            </ul>
            <LoadMore
              hasNextPage={instances.hasNextPage}
              isFetchingNextPage={instances.isFetchingNextPage}
              onLoadMore={() => void instances.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      {starting ? (
        <StartLoginDialog
          lang={lang}
          login={login}
          target={starting}
          onClose={() => setStarting(null)}
        />
      ) : null}
      {adding ? (
        <AddInstanceDialog
          lang={lang}
          login={login}
          account={account}
          onClose={() => setAdding(false)}
        />
      ) : null}
    </div>
  );
}

/** The newest of the last capture and the last upload (epoch ms), or null. */
function instanceLastSavedAt(
  instance: Pick<InstanceItem, "lastCapturedAt" | "lastUploadedAt">,
): number | null {
  const times = [instance.lastCapturedAt, instance.lastUploadedAt].flatMap((value) =>
    value ? [Date.parse(value)] : [],
  );
  return times.length > 0 ? Math.max(...times) : null;
}

const STATE_VARIANT = {
  READY: "secondary",
  NEEDS_LOGIN: "destructive",
  EMPTY: "outline",
} as const;

function InstanceRow({
  lang,
  login,
  instance,
  definition,
  writable,
  onRelogin,
}: {
  lang: string;
  login: LoginItem;
  instance: InstanceItem;
  /** `undefined` while loading; `null` when the pinned definition no longer parses. */
  definition: LoginDefinition | null | undefined;
  writable: boolean;
  onRelogin: () => void;
}) {
  const { t, i18n } = useTranslation(["logins", "common"]);
  const [recovery, setRecovery] = useState(false);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [editing, setEditing] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const label = instanceLabel(t, instance);
  const now = Date.now();
  const lastSaved = instanceLastSavedAt(instance);
  const remove = useMutation({
    ...orpc.logins.deleteInstance.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });

  return (
    <li data-instance-id={instance.id} className="flex min-w-0 flex-col gap-2 px-3 py-3 text-sm">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="break-words font-medium">{label}</span>
          <Badge variant={STATE_VARIANT[instance.state]}>
            {t(`logins:instances.state.${instance.state}`)}
          </Badge>
          {instance.loginInProgress ? <Badge>{t("logins:instances.loginInProgress")}</Badge> : null}
        </div>
        {writable ? (
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              size="touch"
              variant="outline"
              disabled={instance.loginInProgress}
              onClick={onRelogin}
            >
              {t("logins:session.relogin")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={() => setUploading(true)}>
              {t("logins:upload.action")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={() => setEditing(true)}>
              {t("common:actions.edit")}
            </Button>
            <Button type="button" size="touch" variant="outline" onClick={() => setDeleting(true)}>
              {t("common:actions.delete")}
            </Button>
          </div>
        ) : null}
      </div>
      <p className="text-muted-foreground" title={dateTimeTitle(lastSaved, i18n.language)}>
        {instance.maxConcurrent === null
          ? t("logins:instances.holdersUnlimited", { count: instance.activeLeases })
          : t("logins:instances.holders", {
              count: instance.activeLeases,
              capacity: instance.maxConcurrent,
            })}
        {" · "}
        {t("logins:instances.lastCapture", {
          when:
            lastSaved === null
              ? t("logins:instances.never")
              : formatRelativeTime(lastSaved, i18n.language, now),
        })}
      </p>
      {instance.state === "NEEDS_LOGIN" && instance.needsLoginReason ? (
        <p className="break-words text-destructive">
          {t("logins:instances.needsLoginReason", { reason: instance.needsLoginReason })}
        </p>
      ) : null}
      <ProblemText problem={problem} />
      <Button
        type="button"
        size="touch"
        variant="ghost"
        className="self-start"
        aria-expanded={recovery}
        onClick={() => setRecovery((open) => !open)}
      >
        {recovery ? t("logins:leases.hide") : t("logins:leases.show")}
      </Button>
      {recovery ? (
        <InstanceRecovery lang={lang} login={login} instance={instance} writable={writable} />
      ) : null}
      {editing ? (
        <EditInstanceSheet
          lang={lang}
          login={login}
          instance={instance}
          onClose={() => setEditing(false)}
        />
      ) : null}
      {uploading ? (
        <UploadValueDialog
          lang={lang}
          login={login}
          instance={instance}
          definition={definition}
          onClose={() => setUploading(false)}
        />
      ) : null}
      <ConfirmDeleteDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={t("logins:instances.deleteTitle", { name: label })}
        description={t("logins:instances.deleteDescription")}
        confirmToken={label}
        typePrompt={t("logins:instances.deletePrompt")}
        copyAriaLabel={t("logins:instances.copyName")}
        isPending={remove.isPending}
        onConfirm={async () => {
          setProblem(null);
          try {
            await remove.mutateAsync({ credentialId: login.id, instanceId: instance.id });
            toast.success(t("logins:instances.deleted"));
          } catch (error) {
            if (!redirect(error)) setProblem(loginProblem(error));
          } finally {
            setDeleting(false);
            invalidateLogins(queryClient);
          }
        }}
      />
    </li>
  );
}

function AddInstanceDialog({
  lang,
  login,
  account,
  onClose,
}: {
  lang: string;
  login: LoginItem;
  account: AccountItem;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const shareable = login.mode === "SHAREABLE";
  const create = useMutation({
    ...orpc.logins.createInstance.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { name: "", maxConcurrent: "" },
    validators: { onSubmit: instanceSchema(t) },
    onSubmit: async ({ value }) => {
      setProblem(null);
      const name = value.name.trim();
      try {
        await create.mutateAsync({
          credentialId: login.id,
          accountId: account.id,
          ...(name ? { name } : {}),
          ...(shareable ? { maxConcurrent: parseMaxConcurrent(value.maxConcurrent) } : {}),
        });
      } catch (error) {
        if (!redirect(error)) setProblem(loginProblem(error));
        return;
      } finally {
        invalidateLogins(queryClient);
      }
      toast.success(t("logins:instances.added"));
      onClose();
    },
  });

  return (
    <Dialog open onOpenChange={(open) => (open || create.isPending ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {t("logins:instances.addTitle", { account: accountLabel(t, account) })}
          </DialogTitle>
          <DialogDescription>{t("logins:instances.addDescription")}</DialogDescription>
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
          <form.Field name="name">
            {(field) => (
              <TextField
                field={field}
                label={t("logins:form.optionalName")}
                inputMode="text"
                autoComplete="off"
                inputClassName="min-h-11"
                maxLength={80}
              />
            )}
          </form.Field>
          {shareable ? (
            <form.Field name="maxConcurrent">
              {(field) => (
                <TextField
                  field={field}
                  label={t("logins:form.maxConcurrent")}
                  description={t("logins:form.maxConcurrentHint")}
                  inputMode="numeric"
                  autoComplete="off"
                  inputClassName="min-h-11"
                  maxLength={6}
                />
              )}
            </form.Field>
          ) : (
            <p className="text-sm text-muted-foreground">{t("logins:instances.exclusiveHint")}</p>
          )}
          <ProblemText problem={problem} />
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="touch"
              disabled={create.isPending}
              onClick={onClose}
            >
              {t("common:actions.cancel")}
            </Button>
            <Button type="submit" size="touch" disabled={create.isPending}>
              {t("logins:instances.addEmpty")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function EditInstanceSheet({
  lang,
  login,
  instance,
  onClose,
}: {
  lang: string;
  login: LoginItem;
  instance: InstanceItem;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const shareable = login.mode === "SHAREABLE";
  const update = useMutation({
    ...orpc.logins.updateInstance.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: {
      name: instance.name ?? "",
      maxConcurrent:
        shareable && instance.maxConcurrent !== null ? String(instance.maxConcurrent) : "",
    },
    validators: { onSubmit: instanceSchema(t) },
    onSubmit: async ({ value }) => {
      setProblem(null);
      try {
        await update.mutateAsync({
          credentialId: login.id,
          instanceId: instance.id,
          name: value.name.trim() || null,
          ...(shareable ? { maxConcurrent: parseMaxConcurrent(value.maxConcurrent) } : {}),
        });
      } catch (error) {
        if (!redirect(error)) setProblem(loginProblem(error));
        return;
      } finally {
        invalidateLogins(queryClient);
      }
      toast.success(t("logins:edit.saved"));
      onClose();
    },
  });

  return (
    <Sheet open onOpenChange={(open) => (open ? undefined : onClose())}>
      <SheetContent closeLabel={t("common:actions.close")}>
        <SheetHeader>
          <SheetTitle>{t("logins:instances.editTitle")}</SheetTitle>
          <SheetDescription>{t("logins:form.optionalNameHint")}</SheetDescription>
        </SheetHeader>
        <form
          noValidate
          className="flex min-h-0 min-w-0 flex-1 flex-col"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void form.handleSubmit();
          }}
        >
          <SheetBody className="flex min-w-0 flex-col gap-4">
            <form.Field name="name">
              {(field) => (
                <TextField
                  field={field}
                  label={t("logins:form.optionalName")}
                  inputMode="text"
                  autoComplete="off"
                  inputClassName="min-h-11"
                  maxLength={80}
                />
              )}
            </form.Field>
            {shareable ? (
              <form.Field name="maxConcurrent">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("logins:form.maxConcurrent")}
                    description={t("logins:form.maxConcurrentEditHint")}
                    inputMode="numeric"
                    autoComplete="off"
                    inputClassName="min-h-11"
                    maxLength={6}
                  />
                )}
              </form.Field>
            ) : null}
            <ProblemText problem={problem} />
          </SheetBody>
          <SheetFooter>
            <Button type="button" variant="outline" size="touch" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
            <form.Subscribe selector={(formState) => formState.isSubmitting}>
              {(submitting) => (
                <Button type="submit" size="touch" disabled={submitting}>
                  {submitting ? t("common:actions.saving") : t("common:actions.saveChanges")}
                </Button>
              )}
            </form.Subscribe>
          </SheetFooter>
        </form>
      </SheetContent>
    </Sheet>
  );
}

/**
 * Write a value (write-only): env entries are password inputs, declared files
 * are picked from disk. Nothing is read back; on success the dialog closes and
 * the browser drops what was typed. The server validates against the pinned
 * definition and answers with metadata only.
 */
function UploadValueDialog({
  lang,
  login,
  instance,
  definition,
  onClose,
}: {
  lang: string;
  login: LoginItem;
  instance: InstanceItem;
  /** `undefined` while loading; `null` when the pinned definition no longer parses. */
  definition: LoginDefinition | null | undefined;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const fileInputPrefix = useId();
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const [problemEntry, setProblemEntry] = useState<string | null>(null);
  const [localProblem, setLocalProblem] = useState<"missing" | "tooLarge" | "nothing" | null>(null);
  const [files, setFiles] = useState<Record<string, File | null>>({});
  const envEntries = definition?.credentials.env ?? [];
  const fileEntries = definition ? definitionFiles(definition) : [];
  const maxBytes = definition?.credentials.maxBytes ?? 0;
  const write = useMutation({
    ...orpc.logins.writeValue.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: {
      env: Object.fromEntries(envEntries.map((entry) => [entry.name, ""])) as Record<
        string,
        string
      >,
    },
    onSubmit: async ({ value }) => {
      setProblem(null);
      setProblemEntry(null);
      setLocalProblem(null);
      const env = Object.fromEntries(
        Object.entries(value.env).filter(([, entryValue]) => entryValue !== ""),
      );
      const picked = fileEntries.flatMap((entry) => {
        const file = files[entry.path];
        return file ? [{ path: entry.path, file }] : [];
      });
      const missing =
        envEntries.some((entry) => entry.required && !env[entry.name]) ||
        fileEntries.some((entry) => entry.required && !files[entry.path]);
      if (missing) return setLocalProblem("missing");
      if (picked.length === 0 && Object.keys(env).length === 0) return setLocalProblem("nothing");
      if (totalBytes(picked.map((entry) => entry.file)) > maxBytes)
        return setLocalProblem("tooLarge");
      try {
        const encoded = await Promise.all(
          picked.map(async (entry) => ({
            path: entry.path,
            kind: "file" as const,
            contentBase64: await fileToBase64(entry.file),
          })),
        );
        await write.mutateAsync({
          credentialId: login.id,
          instanceId: instance.id,
          ...(encoded.length > 0 ? { files: encoded } : {}),
          ...(Object.keys(env).length > 0 ? { env } : {}),
        });
      } catch (error) {
        if (!redirect(error)) {
          setProblem(loginProblem(error));
          setProblemEntry(loginProblemEntry(error));
        }
        return;
      } finally {
        invalidateLogins(queryClient);
      }
      form.reset();
      setFiles({});
      toast.success(t("logins:upload.done"));
      onClose();
    },
  });

  return (
    <Dialog open onOpenChange={(open) => (open || write.isPending ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {t("logins:upload.title", { name: instanceLabel(t, instance) })}
          </DialogTitle>
          <DialogDescription>{t("logins:upload.description")}</DialogDescription>
        </DialogHeader>
        {definition === undefined ? (
          <SkeletonList count={2} className="rounded-lg border" />
        ) : definition === null ? (
          <p role="alert" className="text-sm text-destructive">
            {t("logins:problem.definitionCorrupt")}
          </p>
        ) : (
          <form
            noValidate
            autoComplete="off"
            className="flex min-w-0 flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              event.stopPropagation();
              void form.handleSubmit();
            }}
          >
            {instance.state !== "EMPTY" ? (
              <p role="note" className="text-sm text-muted-foreground">
                {t("logins:upload.replaces")}
              </p>
            ) : null}
            {envEntries.map((entry) => (
              <form.Field key={entry.name} name={`env.${entry.name}`}>
                {(field) => (
                  <TextField
                    field={field}
                    type="password"
                    label={
                      entry.required
                        ? entry.name
                        : t("logins:upload.optional", { name: entry.name })
                    }
                    description={entry.description}
                    autoComplete="off"
                    inputClassName="min-h-11 font-mono"
                    maxLength={4096}
                  />
                )}
              </form.Field>
            ))}
            {fileEntries.map((entry, index) => {
              const inputId = `${fileInputPrefix}-file-${index}`;
              return (
                <div key={entry.path} className="flex min-w-0 flex-col gap-2">
                  <Label htmlFor={inputId} className="break-all font-mono text-xs">
                    {entry.required
                      ? `~/${entry.path}`
                      : t("logins:upload.optional", { name: `~/${entry.path}` })}
                  </Label>
                  <Input
                    id={inputId}
                    type="file"
                    className="min-h-11"
                    onChange={(event) => {
                      const file = event.target.files?.[0] ?? null;
                      setFiles((current) => ({ ...current, [entry.path]: file }));
                    }}
                  />
                </div>
              );
            })}
            {fileEntries.length > 0 ? (
              <p className="text-xs text-muted-foreground">
                {t("logins:upload.filesHint", { max: Math.floor(maxBytes / 1024) })}
              </p>
            ) : null}
            {localProblem ? (
              <p role="alert" className="text-sm text-destructive">
                {t(`logins:upload.problem.${localProblem}`)}
              </p>
            ) : null}
            <ProblemText problem={problem} entry={problemEntry} />
            <div className="flex flex-wrap justify-end gap-2">
              <Button
                type="button"
                variant="outline"
                size="touch"
                disabled={write.isPending}
                onClick={onClose}
              >
                {t("common:actions.cancel")}
              </Button>
              <Button type="submit" size="touch" disabled={write.isPending}>
                {write.isPending ? t("logins:upload.submitting") : t("logins:upload.submit")}
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
