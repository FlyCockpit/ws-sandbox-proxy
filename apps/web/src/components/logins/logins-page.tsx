import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
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
import { Checkbox } from "@wssp/ui/components/checkbox";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { SelectItem } from "@wssp/ui/components/select";
import { toast } from "@wssp/ui/components/sileo";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import { Plus } from "lucide-react";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { EmptyState } from "@/components/empty-state";
import { FormSelect } from "@/components/form-select";
import { LoadMore } from "@/components/load-more";
import {
  DefinitionIssues,
  type DefinitionItem,
  invalidateLogins,
  ProblemText,
  useLoginsAvailability,
} from "@/components/logins/logins-shared";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SettingsBackLink } from "@/components/settings/settings-back-link";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  checkDefinitionText,
  type DefinitionIssue,
  definitionProxyCapable,
  type LoginProblem,
  loginProblem,
  loginProblemIssues,
  readDefinition,
  shareRotationRisk,
} from "@/lib/login-rules";
import { orpc } from "@/utils/orpc";

/**
 * CLI logins overview (owner-scoped): the logins list and the definition
 * versions they pin. Definitions are pasted JSON, validated live with the
 * server's parser; logins are created from a definition in a Dialog. Values
 * never appear here: they are write-only and managed per instance on the
 * login's page.
 */

const pageInput = (cursor: string | undefined) => ({ limit: DASHBOARD_PAGE_LIMIT, cursor });
const pageOptions = {
  input: pageInput,
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

export function LoginsPage({ lang }: { lang: string }) {
  const { t } = useTranslation(["logins", "dashboard", "common"]);
  const availability = useLoginsAvailability();
  const readable = availability === "enabled" || availability === "readOnly";
  const writable = availability === "enabled";
  const logins = useInfiniteQuery({
    ...orpc.logins.listLogins.infiniteOptions(pageOptions),
    enabled: readable,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [logins.error]);
  const [creating, setCreating] = useState(false);
  const rows = logins.data?.pages.flatMap((page) => page.items);

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <PageHeader
        back={<SettingsBackLink lang={lang} />}
        title={t("logins:title")}
        description={t("logins:description")}
        actions={
          writable ? (
            <Button type="button" size="touch" onClick={() => setCreating(true)}>
              <Plus aria-hidden="true" />
              {t("logins:create.action")}
            </Button>
          ) : null
        }
      />
      {availability === "pending" ? (
        <SkeletonList layout="resource" count={2} className="rounded-xl border" />
      ) : availability === "unavailable" ? (
        <EmptyState
          className="rounded-xl border px-4"
          title={t("logins:unavailable.title")}
          description={t("logins:unavailable.description")}
        />
      ) : (
        <>
          {availability === "readOnly" ? (
            <p
              role="status"
              className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
            >
              {t("logins:readOnly")}
            </p>
          ) : null}
          <section aria-labelledby="logins-list-heading" className="flex min-w-0 flex-col gap-3">
            <h2 id="logins-list-heading" className="font-heading text-lg font-semibold">
              {t("logins:list.heading")}
            </h2>
            <QueryBoundary
              query={{
                data: rows,
                isPending: logins.isPending,
                isError: logins.isError,
                error: logins.error,
                refetch: logins.refetch,
              }}
              skeleton={<SkeletonList layout="resource" count={3} className="rounded-xl border" />}
              errorMessage={t("dashboard:list.loadFailed")}
              isEmpty={(items) => items.length === 0}
              empty={
                <EmptyState
                  className="rounded-xl border px-4"
                  title={t("logins:empty.title")}
                  description={t("logins:empty.description")}
                />
              }
            >
              {(items) => (
                <>
                  <ul aria-label={t("logins:list.label")} className="flex min-w-0 flex-col gap-3">
                    {items.map((login) => (
                      <li
                        key={login.id}
                        data-login-id={login.id}
                        className="flex min-w-0 flex-col gap-2 rounded-xl border bg-card p-4 text-card-foreground"
                      >
                        <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                          <Link
                            to="/$lang/settings/logins/$loginId"
                            params={{ lang, loginId: login.id }}
                            className="inline-flex min-h-11 min-w-0 items-center break-all font-medium underline underline-offset-4"
                          >
                            {login.name}
                          </Link>
                          <div className="flex flex-wrap gap-1.5">
                            <Badge>{t(`logins:mode.${login.mode}`)}</Badge>
                            <Badge>{t(`logins:delivery.${login.delivery}`)}</Badge>
                          </div>
                        </div>
                        <p className="break-words text-sm text-muted-foreground">
                          {t("logins:list.definition", {
                            name: login.definition.displayName,
                            version: login.definition.version,
                          })}
                        </p>
                      </li>
                    ))}
                  </ul>
                  <LoadMore
                    hasNextPage={logins.hasNextPage}
                    isFetchingNextPage={logins.isFetchingNextPage}
                    onLoadMore={() => void logins.fetchNextPage()}
                  />
                </>
              )}
            </QueryBoundary>
          </section>
          <DefinitionsSection lang={lang} writable={writable} />
        </>
      )}
      {creating ? <CreateLoginDialog lang={lang} onClose={() => setCreating(false)} /> : null}
    </div>
  );
}

function DefinitionsSection({ lang, writable }: { lang: string; writable: boolean }) {
  const { t } = useTranslation(["logins", "dashboard", "common"]);
  const definitions = useInfiniteQuery({
    ...orpc.logins.listDefinitions.infiniteOptions(pageOptions),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [definitions.error]);
  const [adding, setAdding] = useState(false);
  const [viewing, setViewing] = useState<DefinitionItem | null>(null);
  const [archiving, setArchiving] = useState<DefinitionItem | null>(null);
  const rows = definitions.data?.pages.flatMap((page) => page.items);

  return (
    <section aria-labelledby="definitions-heading" className="flex min-w-0 flex-col gap-3">
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <div className="min-w-0 space-y-1">
          <h2 id="definitions-heading" className="font-heading text-lg font-semibold">
            {t("logins:definitions.heading")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("logins:definitions.description")}</p>
        </div>
        {writable ? (
          <Button type="button" size="touch" variant="outline" onClick={() => setAdding(true)}>
            <Plus aria-hidden="true" />
            {t("logins:definitions.add")}
          </Button>
        ) : null}
      </div>
      <QueryBoundary
        query={{
          data: rows,
          isPending: definitions.isPending,
          isError: definitions.isError,
          error: definitions.error,
          refetch: definitions.refetch,
        }}
        skeleton={<SkeletonList count={2} className="rounded-xl border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={
          <EmptyState
            className="rounded-xl border px-4"
            title={t("logins:definitions.empty.title")}
            description={t("logins:definitions.empty.description")}
          />
        }
      >
        {(items) => (
          <>
            <ul
              aria-label={t("logins:definitions.label")}
              className="flex min-w-0 flex-col divide-y rounded-xl border bg-card"
            >
              {items.map((definition) => (
                <li
                  key={definition.id}
                  data-definition-id={definition.id}
                  className="flex min-w-0 flex-wrap items-center justify-between gap-2 px-4 py-3"
                >
                  <div className="min-w-0 space-y-0.5">
                    <p className="break-words font-medium">
                      {t("logins:definitions.title", {
                        name: definition.displayName,
                        version: definition.version,
                      })}
                    </p>
                    <p className="break-all font-mono text-xs text-muted-foreground">
                      {definition.slug} · {definition.digest.slice(0, 12)}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {definition.archivedAt ? (
                      <Badge>{t("logins:definitions.archived")}</Badge>
                    ) : null}
                    <Button
                      type="button"
                      size="touch"
                      variant="outline"
                      onClick={() => setViewing(definition)}
                    >
                      {t("logins:definitions.view")}
                    </Button>
                    {writable && !definition.archivedAt ? (
                      <Button
                        type="button"
                        size="touch"
                        variant="outline"
                        onClick={() => setArchiving(definition)}
                      >
                        {t("logins:definitions.archive")}
                      </Button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
            <LoadMore
              hasNextPage={definitions.hasNextPage}
              isFetchingNextPage={definitions.isFetchingNextPage}
              onLoadMore={() => void definitions.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      {adding ? <AddDefinitionDialog lang={lang} onClose={() => setAdding(false)} /> : null}
      {viewing ? (
        <ViewDefinitionDialog definition={viewing} onClose={() => setViewing(null)} />
      ) : null}
      {archiving ? (
        <ArchiveDefinitionDialog
          lang={lang}
          definition={archiving}
          onClose={() => setArchiving(null)}
        />
      ) : null}
    </section>
  );
}

function AddDefinitionDialog({ lang, onClose }: { lang: string; onClose: () => void }) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const [issues, setIssues] = useState<DefinitionIssue[]>([]);
  const create = useMutation({
    ...orpc.logins.createDefinition.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: { text: "" },
    onSubmit: async ({ value }) => {
      if (checkDefinitionText(value.text).state !== "valid") return;
      setProblem(null);
      setIssues([]);
      try {
        await create.mutateAsync({ text: value.text });
      } catch (error) {
        if (!redirect(error)) {
          setProblem(loginProblem(error));
          setIssues(loginProblemIssues(error));
        }
        return;
      } finally {
        invalidateLogins(queryClient);
      }
      toast.success(t("logins:definitions.added"));
      onClose();
    },
  });
  const text = useStore(form.store, (state) => state.values.text);
  const check = checkDefinitionText(text);

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent
        closeLabel={t("common:actions.close")}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle>{t("logins:definitions.addTitle")}</DialogTitle>
          <DialogDescription>{t("logins:definitions.addDescription")}</DialogDescription>
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
          <form.Field name="text">
            {(field) => (
              <TextareaField
                field={field}
                label={t("logins:definitions.json")}
                description={t("logins:definitions.jsonHint")}
                autoComplete="off"
                spellCheck={false}
                inputClassName="min-h-64 font-mono text-xs"
              />
            )}
          </form.Field>
          <div aria-live="polite" className="min-w-0 text-sm">
            {check.state === "valid" ? (
              <div className="flex min-w-0 flex-col gap-1">
                <p className="text-foreground">
                  {t("logins:definitions.valid", {
                    id: check.definition.id,
                    name: check.definition.displayName,
                  })}
                </p>
                {check.warnings.includes("login.method.browser_callback_unsupported") ? (
                  <p className="text-muted-foreground">
                    {t("logins:definitions.warning.browserCallback")}
                  </p>
                ) : null}
              </div>
            ) : check.state === "invalid" ? (
              <div className="flex min-w-0 flex-col gap-1 text-destructive">
                <p>
                  {check.code === "definition.schema_version_unsupported"
                    ? t("logins:problem.schemaVersionUnsupported")
                    : t("logins:problem.definitionInvalid")}
                </p>
                <DefinitionIssues issues={check.issues} />
              </div>
            ) : null}
          </div>
          <ProblemText problem={problem} issues={issues} />
          <div className="flex flex-wrap justify-end gap-2">
            <Button type="button" variant="outline" size="touch" onClick={onClose}>
              {t("common:actions.cancel")}
            </Button>
            <Button
              type="submit"
              size="touch"
              disabled={check.state !== "valid" || create.isPending}
            >
              {create.isPending ? t("logins:definitions.adding") : t("logins:definitions.add")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ViewDefinitionDialog({
  definition,
  onClose,
}: {
  definition: DefinitionItem;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "dashboard", "common"]);
  const detail = useQuery({
    ...orpc.logins.getDefinition.queryOptions({ input: { id: definition.id } }),
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent
        closeLabel={t("common:actions.close")}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-2xl"
      >
        <DialogHeader>
          <DialogTitle>
            {t("logins:definitions.title", {
              name: definition.displayName,
              version: definition.version,
            })}
          </DialogTitle>
          <DialogDescription className="break-all font-mono text-xs">
            {t("logins:definitions.digest", { digest: definition.digest })}
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
          skeleton={<SkeletonList count={1} className="rounded-xl border" />}
          errorMessage={t("dashboard:list.loadFailed")}
        >
          {(data) => (
            <div className="flex min-w-0 flex-col gap-2">
              {data.warnings.includes("credential.definition_corrupt") ? (
                <p role="alert" className="text-sm text-destructive">
                  {t("logins:problem.definitionCorrupt")}
                </p>
              ) : null}
              <CodeSnippet
                code={JSON.stringify(data.document, null, 2)}
                copyLabel={t("logins:definitions.copy")}
              />
            </div>
          )}
        </QueryBoundary>
      </DialogContent>
    </Dialog>
  );
}

function ArchiveDefinitionDialog({
  lang,
  definition,
  onClose,
}: {
  lang: string;
  definition: DefinitionItem;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const archive = useMutation({
    ...orpc.logins.archiveDefinition.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  return (
    <AlertDialog open onOpenChange={(open) => (open || archive.isPending ? undefined : onClose())}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {t("logins:definitions.archiveTitle", {
              name: definition.displayName,
              version: definition.version,
            })}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {t("logins:definitions.archiveDescription")}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <ProblemText problem={problem} />
        <AlertDialogFooter>
          <AlertDialogCancel disabled={archive.isPending} className="min-h-11">
            {t("common:actions.cancel")}
          </AlertDialogCancel>
          <AlertDialogAction
            className="min-h-11"
            disabled={archive.isPending}
            onClick={async (event) => {
              event.preventDefault();
              setProblem(null);
              try {
                await archive.mutateAsync({ id: definition.id });
              } catch (error) {
                if (!redirect(error)) setProblem(loginProblem(error));
                return;
              } finally {
                invalidateLogins(queryClient);
              }
              toast.success(t("logins:definitions.archivedDone"));
              onClose();
            }}
          >
            {t("logins:definitions.archive")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

function createLoginSchema(t: (key: string) => string) {
  return z.object({
    name: z.string().trim().min(1, t("logins:form.nameRequired")).max(80),
    definitionId: z.string().min(1, t("logins:form.definitionRequired")),
    // null: the definition's default (proxied whenever it supports it).
    delivery: z.enum(["GUEST", "PROXY"]).nullable(),
    copyBack: z.boolean(),
    foreignAllowed: z.boolean(),
  });
}

/** An explicit choice wins; otherwise proxied whenever the definition supports it. */
function effectiveDelivery(
  chosen: "GUEST" | "PROXY" | null,
  document: ReturnType<typeof readDefinition>,
): "GUEST" | "PROXY" {
  if (chosen) return chosen;
  return document && definitionProxyCapable(document) ? "PROXY" : "GUEST";
}

function CreateLoginDialog({ lang, onClose }: { lang: string; onClose: () => void }) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const definitionSelectId = useId();
  const [problem, setProblem] = useState<LoginProblem | null>(null);
  const [issues, setIssues] = useState<DefinitionIssue[]>([]);
  const definitions = useInfiniteQuery({
    ...orpc.logins.listDefinitions.infiniteOptions(pageOptions),
    meta: { skipGlobalErrorToast: true },
  });
  const choices = (definitions.data?.pages.flatMap((page) => page.items) ?? []).filter(
    (definition) => definition.archivedAt === null,
  );
  const create = useMutation({
    ...orpc.logins.createLogin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const form = useForm({
    defaultValues: {
      name: "",
      definitionId: "",
      delivery: null as "GUEST" | "PROXY" | null,
      copyBack: true,
      foreignAllowed: false,
    },
    validators: { onSubmit: createLoginSchema(t) },
    onSubmit: async ({ value }) => {
      setProblem(null);
      setIssues([]);
      try {
        // The picked definition decides the default delivery (proxied when it
        // can be) and whether copy-back applies (exclusive guest only). Load it
        // when the submit outruns the detail query, so the unsafe guest choice
        // is never sent by default.
        const pickedDetail = await queryClient.ensureQueryData(
          orpc.logins.getDefinition.queryOptions({ input: { id: value.definitionId } }),
        );
        const pickedDocument = readDefinition(pickedDetail.document);
        const delivery = effectiveDelivery(value.delivery, pickedDocument);
        const exclusiveGuest =
          delivery === "GUEST" && pickedDocument?.credentials.sharing === "exclusive";
        const login = await create.mutateAsync({
          name: value.name.trim(),
          definitionId: value.definitionId,
          delivery,
          ...(exclusiveGuest ? { copyBack: value.copyBack } : {}),
          ...(value.foreignAllowed ? { foreignAllowed: true } : {}),
        });
        toast.success(t("logins:create.done", { name: login.name }));
      } catch (error) {
        if (!redirect(error)) {
          setProblem(loginProblem(error));
          setIssues(loginProblemIssues(error));
        }
        return;
      } finally {
        invalidateLogins(queryClient);
      }
      onClose();
    },
  });
  const values = useStore(form.store, (state) => state.values);
  const picked = useQuery({
    ...orpc.logins.getDefinition.queryOptions({ input: { id: values.definitionId } }),
    enabled: values.definitionId !== "",
    meta: { skipGlobalErrorToast: true },
  });
  const document = picked.data ? readDefinition(picked.data.document) : null;
  const shareable = document?.credentials.sharing === "shareable";
  const proxyCapable = document ? definitionProxyCapable(document) : false;
  const delivery = effectiveDelivery(values.delivery, document);

  return (
    <Dialog open onOpenChange={(open) => (open || create.isPending ? undefined : onClose())}>
      <DialogContent
        closeLabel={t("common:actions.close")}
        className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-lg"
      >
        <DialogHeader>
          <DialogTitle>{t("logins:create.title")}</DialogTitle>
          <DialogDescription>{t("logins:create.description")}</DialogDescription>
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
                label={t("logins:form.name")}
                inputMode="text"
                autoComplete="off"
                inputClassName="min-h-11"
                maxLength={80}
              />
            )}
          </form.Field>
          <form.Field name="definitionId">
            {(field) => (
              <div className="flex min-w-0 flex-col gap-2">
                <label htmlFor={definitionSelectId} className="text-sm font-medium">
                  {t("logins:form.definition")}
                </label>
                <FormSelect
                  id={definitionSelectId}
                  value={field.state.value}
                  placeholder={t("logins:form.definitionPlaceholder")}
                  optionsSettled={!definitions.isPending && !definitions.hasNextPage}
                  onValueChange={(next) => {
                    field.handleChange(next);
                    // Back to the new definition's default (derived on render).
                    form.setFieldValue("delivery", null);
                  }}
                  disabled={definitions.isPending}
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
                {!definitions.isPending && choices.length === 0 ? (
                  <p className="text-sm text-muted-foreground">{t("logins:form.noDefinitions")}</p>
                ) : null}
                {field.state.meta.errors.length > 0 ? (
                  <p role="alert" className="text-sm text-destructive">
                    {t("logins:form.definitionRequired")}
                  </p>
                ) : null}
              </div>
            )}
          </form.Field>
          {document ? (
            <p className="text-sm text-muted-foreground">
              {t(shareable ? "logins:create.modeShareable" : "logins:create.modeExclusive")}
            </p>
          ) : null}
          {document && shareRotationRisk(document) ? (
            <p role="note" className="text-sm text-destructive">
              {t("logins:warning.shareRotation")}
            </p>
          ) : null}
          {proxyCapable ? (
            <form.Field name="delivery">
              {(field) => (
                <fieldset className="flex min-w-0 flex-col gap-1">
                  <legend className="mb-1 text-sm font-medium">{t("logins:form.delivery")}</legend>
                  {(["GUEST", "PROXY"] as const).map((choice) => (
                    <label key={choice} className="flex min-h-11 items-center gap-3 text-sm">
                      <input
                        type="radio"
                        name="login-delivery"
                        className="size-4"
                        checked={delivery === choice}
                        onChange={() => field.handleChange(choice)}
                      />
                      {t(`logins:delivery.${choice}`)}
                    </label>
                  ))}
                  <p className="text-xs text-muted-foreground">{t("logins:form.deliveryHint")}</p>
                </fieldset>
              )}
            </form.Field>
          ) : null}
          {document && !shareable && delivery === "GUEST" ? (
            <form.Field name="copyBack">
              {(field) => (
                <label className="flex min-h-11 items-center gap-3 text-sm">
                  <Checkbox
                    checked={field.state.value}
                    onCheckedChange={(checked) => field.handleChange(checked === true)}
                  />
                  {t("logins:form.copyBack")}
                </label>
              )}
            </form.Field>
          ) : null}
          <form.Field name="foreignAllowed">
            {(field) => (
              <div className="flex min-w-0 flex-col gap-1">
                <label className="flex min-h-11 items-center gap-3 text-sm">
                  <Checkbox
                    checked={field.state.value}
                    onCheckedChange={(checked) => field.handleChange(checked === true)}
                  />
                  {t("logins:form.foreignAllowed")}
                </label>
                {field.state.value ? (
                  <p role="note" className="text-sm text-destructive">
                    {t("logins:warning.foreign")}
                  </p>
                ) : null}
              </div>
            )}
          </form.Field>
          <ProblemText problem={problem} issues={issues} />
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
              {create.isPending ? t("logins:create.submitting") : t("logins:create.submit")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
