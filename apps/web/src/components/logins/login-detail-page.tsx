import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
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
import { Button } from "@wssp/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { SelectItem } from "@wssp/ui/components/select";
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
import { ArrowLeft } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { FormSelect } from "@/components/form-select";
import { AccountsSection } from "@/components/logins/login-accounts";
import { LoginActivity, OpenLoginSessions } from "@/components/logins/login-activity";
import {
  invalidateLogins,
  type LoginItem,
  ProblemText,
  useLoginsAvailability,
} from "@/components/logins/logins-shared";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  type LoginProblem,
  loginProblem,
  readDefinition,
  shareRotationRisk,
} from "@/lib/login-rules";
import { orpc } from "@/utils/orpc";

/**
 * One login: settings (delivery is fixed at create), copy-back and foreign
 * hosts (live owner session), re-pin to another version of the same
 * definition, delete after typing the name, and its accounts and instances.
 * Values are write-only; the page shows only their metadata.
 */
export function LoginDetailPage({ lang, loginId }: { lang: string; loginId: string }) {
  const { t } = useTranslation(["logins", "dashboard", "common"]);
  const availability = useLoginsAvailability();
  const login = useQuery({
    ...orpc.logins.getLogin.queryOptions({ input: { id: loginId } }),
    enabled: availability === "enabled" || availability === "readOnly",
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [login.error]);
  const missing = login.isError && loginProblem(login.error) === "notFound";

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <Link
        to="/$lang/settings/logins"
        params={{ lang }}
        className="inline-flex min-h-11 items-center gap-2 text-sm underline underline-offset-4"
      >
        <ArrowLeft aria-hidden="true" className="size-4" />
        {t("logins:detail.back")}
      </Link>
      {availability === "pending" ? (
        <SkeletonList layout="resource" count={2} className="rounded-xl border" />
      ) : availability === "unavailable" ? (
        <EmptyState
          className="rounded-xl border px-4"
          title={t("logins:unavailable.title")}
          description={t("logins:unavailable.description")}
        />
      ) : missing ? (
        <EmptyState className="rounded-xl border px-4" title={t("logins:detail.notFound")} />
      ) : (
        <QueryBoundary
          query={{
            data: login.data,
            isPending: login.isPending,
            isError: login.isError,
            error: login.error,
            refetch: login.refetch,
          }}
          skeleton={<SkeletonList layout="resource" count={2} className="rounded-xl border" />}
          errorMessage={t("dashboard:list.loadFailed")}
        >
          {(data) => <LoginBody lang={lang} login={data} writable={availability === "enabled"} />}
        </QueryBoundary>
      )}
    </div>
  );
}

function LoginBody({
  lang,
  login,
  writable,
}: {
  lang: string;
  login: LoginItem;
  writable: boolean;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const redirect = useTwoFactorRedirect(lang);
  const [editing, setEditing] = useState(false);
  const [repinning, setRepinning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const pinned = useQuery({
    ...orpc.logins.getDefinition.queryOptions({ input: { id: login.definition.id } }),
    meta: { skipGlobalErrorToast: true },
  });
  // undefined while loading; null when the pinned document no longer parses.
  const definition = pinned.data
    ? readDefinition(pinned.data.document)
    : pinned.isError
      ? null
      : undefined;
  const remove = useMutation({
    ...orpc.logins.deleteLogin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        title={login.name}
        description={t("logins:list.definition", {
          name: login.definition.displayName,
          version: login.definition.version,
        })}
        actions={
          <div className="flex flex-wrap gap-2">
            {writable ? (
              <>
                <Button
                  type="button"
                  size="touch"
                  variant="outline"
                  onClick={() => setEditing(true)}
                >
                  {t("common:actions.edit")}
                </Button>
                <Button
                  type="button"
                  size="touch"
                  variant="outline"
                  onClick={() => setRepinning(true)}
                >
                  {t("logins:repin.action")}
                </Button>
              </>
            ) : null}
            <Button
              type="button"
              size="touch"
              variant="destructive"
              onClick={() => setDeleting(true)}
            >
              {t("logins:delete.action")}
            </Button>
          </div>
        }
      />
      {definition && shareRotationRisk(definition) ? (
        <p role="note" className="rounded-md border p-3 text-sm text-destructive">
          {t("logins:warning.shareRotation")}
        </p>
      ) : null}
      <OpenLoginSessions lang={lang} login={login} />
      <LoginSettings lang={lang} login={login} writable={writable} />
      <ProblemText problem={problem} />
      <AccountsSection lang={lang} login={login} definition={definition} writable={writable} />
      <LoginActivity lang={lang} login={login} />
      {editing ? (
        <EditLoginSheet lang={lang} login={login} onClose={() => setEditing(false)} />
      ) : null}
      {repinning ? (
        <RepinDialog lang={lang} login={login} onClose={() => setRepinning(false)} />
      ) : null}
      <ConfirmDeleteDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={t("logins:delete.title", { name: login.name })}
        description={t("logins:delete.description")}
        confirmToken={login.name}
        typePrompt={t("logins:delete.typePrompt")}
        copyAriaLabel={t("logins:delete.copyName")}
        isPending={remove.isPending}
        onConfirm={async () => {
          setProblem(null);
          try {
            await remove.mutateAsync({ id: login.id });
            toast.success(t("logins:delete.done"));
            invalidateLogins(queryClient);
            setDeleting(false);
            void navigate({ to: "/$lang/settings/logins", params: { lang } });
          } catch (error) {
            setDeleting(false);
            if (!redirect(error)) setProblem(loginProblem(error));
          }
        }}
      />
    </div>
  );
}

function LoginSettings({
  lang,
  login,
  writable,
}: {
  lang: string;
  login: LoginItem;
  writable: boolean;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const copyBackId = useId();
  const foreignId = useId();
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const [confirmingForeign, setConfirmingForeign] = useState(false);
  const policy = useMutation({
    ...orpc.logins.updateLoginPolicy.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSettled: () => invalidateLogins(queryClient),
  });
  const apply = async (body: { copyBack?: boolean; foreignAllowed?: boolean }) => {
    setProblem(null);
    try {
      await policy.mutateAsync({ id: login.id, ...body });
      toast.success(t("logins:settings.saved"));
      return true;
    } catch (error) {
      if (!redirect(error)) setProblem(loginProblem(error));
      return false;
    }
  };
  const copyBackApplies = login.mode === "EXCLUSIVE" && login.delivery === "GUEST";

  return (
    <section
      aria-labelledby="login-settings-heading"
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-sm"
    >
      <h2 id="login-settings-heading" className="font-heading text-lg font-semibold">
        {t("logins:settings.heading")}
      </h2>
      <dl className="grid min-w-0 gap-x-4 gap-y-2 sm:grid-cols-[max-content_1fr]">
        <dt className="text-muted-foreground">{t("logins:settings.mode")}</dt>
        <dd>{t(`logins:mode.${login.mode}`)}</dd>
        <dt className="text-muted-foreground">{t("logins:settings.delivery")}</dt>
        <dd>
          {t(`logins:delivery.${login.delivery}`)}{" "}
          <span className="text-muted-foreground">{t("logins:settings.deliveryFixed")}</span>
        </dd>
        <dt className="text-muted-foreground">{t("logins:settings.checkpoints")}</dt>
        <dd>
          {login.checkpointIntervalMin === null
            ? t("logins:settings.checkpointsOff")
            : t("logins:settings.checkpointsEvery", { minutes: login.checkpointIntervalMin })}
        </dd>
        <dt className="text-muted-foreground">{t("logins:settings.digest")}</dt>
        <dd className="break-all font-mono text-xs">{login.definitionDigest}</dd>
      </dl>
      {copyBackApplies ? (
        <div className="flex min-h-11 min-w-0 items-center justify-between gap-3">
          <label htmlFor={copyBackId} className="min-w-0 space-y-0.5">
            <span className="block font-medium">{t("logins:settings.copyBack")}</span>
            <span className="block text-muted-foreground">{t("logins:settings.copyBackHint")}</span>
          </label>
          <Switch
            id={copyBackId}
            checked={login.copyBack}
            disabled={!writable || policy.isPending}
            onCheckedChange={(checked) => void apply({ copyBack: checked })}
          />
        </div>
      ) : null}
      <div className="flex min-h-11 min-w-0 items-center justify-between gap-3">
        <label htmlFor={foreignId} className="min-w-0 space-y-0.5">
          <span className="block font-medium">{t("logins:settings.foreign")}</span>
          <span className="block text-muted-foreground">{t("logins:settings.foreignHint")}</span>
        </label>
        <Switch
          id={foreignId}
          checked={login.foreignAllowed}
          disabled={!writable || policy.isPending}
          onCheckedChange={(checked) =>
            checked ? setConfirmingForeign(true) : void apply({ foreignAllowed: false })
          }
        />
      </div>
      <ProblemText problem={problem} />
      <AlertDialog
        open={confirmingForeign}
        onOpenChange={(open) => (policy.isPending ? undefined : setConfirmingForeign(open))}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("logins:settings.foreignConfirmTitle")}</AlertDialogTitle>
            <AlertDialogDescription>{t("logins:warning.foreign")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={policy.isPending} className="min-h-11">
              {t("common:actions.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              className="min-h-11"
              disabled={policy.isPending}
              onClick={async (event) => {
                event.preventDefault();
                if (await apply({ foreignAllowed: true })) setConfirmingForeign(false);
              }}
            >
              {t("logins:settings.foreignConfirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}

function editLoginSchema(t: (key: string) => string) {
  return z.object({
    name: z.string().trim().min(1, t("logins:form.nameRequired")).max(80),
    checkpoint: z
      .string()
      .trim()
      .refine(
        (value) =>
          value === "" || (/^\d+$/.test(value) && Number(value) >= 5 && Number(value) <= 240),
        t("logins:form.checkpointRange"),
      ),
  });
}

function EditLoginSheet({
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
  const update = useMutation({
    ...orpc.logins.updateLogin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: {
      name: login.name,
      checkpoint: login.checkpointIntervalMin === null ? "" : String(login.checkpointIntervalMin),
    },
    validators: { onSubmit: editLoginSchema(t) },
    onSubmit: async ({ value }) => {
      setProblem(null);
      const checkpoint = value.checkpoint.trim() === "" ? null : Number(value.checkpoint.trim());
      try {
        await update.mutateAsync({
          id: login.id,
          name: value.name.trim(),
          ...(login.copyBack ? { checkpointIntervalMin: checkpoint } : {}),
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
          <SheetTitle>{t("logins:edit.title")}</SheetTitle>
          <SheetDescription>{t("logins:edit.description")}</SheetDescription>
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
                  label={t("logins:form.name")}
                  inputMode="text"
                  autoComplete="off"
                  inputClassName="min-h-11"
                  maxLength={80}
                />
              )}
            </form.Field>
            {login.copyBack ? (
              <form.Field name="checkpoint">
                {(field) => (
                  <TextField
                    field={field}
                    label={t("logins:form.checkpoint")}
                    description={t("logins:form.checkpointHint")}
                    inputMode="numeric"
                    autoComplete="off"
                    inputClassName="min-h-11"
                    maxLength={3}
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

function RepinDialog({
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
  const selectId = useId();
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const [needsErase, setNeedsErase] = useState(false);
  const definitions = useInfiniteQuery({
    ...orpc.logins.listDefinitions.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: DASHBOARD_PAGE_LIMIT, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const choices = (definitions.data?.pages.flatMap((page) => page.items) ?? []).filter(
    (definition) =>
      definition.slug === login.definition.slug &&
      definition.archivedAt === null &&
      definition.id !== login.definition.id,
  );
  const repin = useMutation({
    ...orpc.logins.repinLogin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { definitionId: "", confirmErase: "" },
    onSubmit: async ({ value }) => {
      if (!value.definitionId) return;
      setProblem(null);
      try {
        await repin.mutateAsync({
          id: login.id,
          definitionId: value.definitionId,
          ...(needsErase ? { confirmErase: value.confirmErase } : {}),
        });
      } catch (error) {
        if (redirect(error)) return;
        const next = loginProblem(error);
        if (next === "repinConfirmErase") setNeedsErase(true);
        setProblem(next);
        return;
      } finally {
        invalidateLogins(queryClient);
      }
      toast.success(t("logins:repin.done"));
      onClose();
    },
  });
  const values = useStore(form.store, (state) => state.values);
  const ready = values.definitionId !== "" && (!needsErase || values.confirmErase === login.name);

  return (
    <Dialog open onOpenChange={(open) => (open || repin.isPending ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("logins:repin.title", { name: login.name })}</DialogTitle>
          <DialogDescription>{t("logins:repin.description")}</DialogDescription>
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
          <form.Field name="definitionId">
            {(field) => (
              <div className="flex min-w-0 flex-col gap-2">
                <label htmlFor={selectId} className="text-sm font-medium">
                  {t("logins:repin.version")}
                </label>
                <FormSelect
                  id={selectId}
                  value={field.state.value}
                  optionsSettled={!definitions.isPending && !definitions.hasNextPage}
                  disabled={definitions.isPending}
                  onValueChange={(next) => {
                    field.handleChange(next);
                    setNeedsErase(false);
                    setProblem(null);
                  }}
                >
                  {choices.map((definition) => (
                    <SelectItem key={definition.id} value={definition.id}>
                      {t("logins:definitions.title", {
                        name: definition.displayName,
                        version: definition.version,
                      })}
                    </SelectItem>
                  ))}
                </FormSelect>
                {definitions.hasNextPage ? (
                  <Button
                    type="button"
                    size="touch"
                    variant="outline"
                    disabled={definitions.isFetchingNextPage}
                    onClick={() => void definitions.fetchNextPage()}
                  >
                    {t("logins:form.moreDefinitions")}
                  </Button>
                ) : null}
                {!definitions.isPending && !definitions.hasNextPage && choices.length === 0 ? (
                  <p className="text-sm text-muted-foreground">{t("logins:repin.noVersions")}</p>
                ) : null}
              </div>
            )}
          </form.Field>
          {needsErase ? (
            <form.Field name="confirmErase">
              {(field) => (
                <TextField
                  field={field}
                  label={t("logins:repin.confirmErase", { name: login.name })}
                  inputMode="text"
                  autoComplete="off"
                  inputClassName="min-h-11"
                  maxLength={80}
                />
              )}
            </form.Field>
          ) : null}
          <ProblemText problem={problem} />
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="touch"
              disabled={repin.isPending}
              onClick={onClose}
            >
              {t("common:actions.cancel")}
            </Button>
            <Button
              type="submit"
              size="touch"
              variant={needsErase ? "destructive" : "default"}
              disabled={!ready || repin.isPending}
            >
              {repin.isPending
                ? t("logins:repin.submitting")
                : needsErase
                  ? t("logins:repin.submitErase")
                  : t("logins:repin.submit")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
