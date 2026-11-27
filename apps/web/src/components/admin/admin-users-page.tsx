import { useForm } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { hasRole } from "@wssp/auth/roles";
import { Button } from "@wssp/ui/components/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@wssp/ui/components/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@wssp/ui/components/dropdown-menu";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@wssp/ui/components/select";
import { toast } from "@wssp/ui/components/sileo";
import { FieldError, TextField } from "@wssp/ui/components/text-field";
import { useDebounce } from "@wssp/ui/hooks/use-async-search";
import { cn } from "@wssp/ui/lib/utils";
import {
  Archive,
  ArchiveRestore,
  HardDrive,
  MoreVertical,
  Plus,
  Shield,
  Trash,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";

import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { OneTimeSecretPanel } from "@/components/credentials/credential-parts";
import { EmptyState } from "@/components/empty-state";
import { LoadMore } from "@/components/load-more";
import { PageHeader, PageShell } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SegmentedControl } from "@/components/segmented-control";
import { SkeletonList } from "@/components/skeleton-list";
import { announceArchivedWithUndo } from "@/hooks/archive-undo";
import { isSupportedLocale, type Locale, SUPPORTED_LOCALES } from "@/i18n/config";
import { LOCALE_LABELS } from "@/i18n/labels";
import { type AdminProblem, adminProblem, adminProblemKey } from "@/lib/admin-errors";
import { orpc } from "@/utils/orpc";

import { AdminConfirmDialog } from "./admin-confirm-dialog";
import { AdminImageQuotaSheet } from "./admin-image-quota-sheet";

type StatusFilter = "all" | "active" | "archived";

const PAGE_LIMIT = 50;

type UserRow = {
  id: string;
  email: string;
  name: string;
  role: string;
  emailVerified: boolean;
  banned: boolean | null;
  banReason: string | null;
  createdAt: Date | string;
  /** Live CLI logins and their instances (counts only). */
  cliLogins: { logins: number; instances: number };
};

/** A change that waits for the admin's confirmation before it is sent. */
type PendingChange = { kind: "promote" | "demote" | "archive"; user: UserRow };

function buildInviteSchema() {
  return z.object({
    email: z.email(),
    name: z.string().trim().min(1).max(100),
    role: z.enum(["user", "admin"]),
    locale: z.enum(SUPPORTED_LOCALES),
  });
}

/**
 * Admin users: invite, change role, archive/restore, delete. Every change that
 * reaches beyond this page is confirmed first; every refusal is explained from
 * the server's typed error code (last admin, self-change, deletion blockers)
 * and the list is refetched so a stale row cannot linger.
 */
export function AdminUsersPage({ currentUserId }: { currentUserId: string }) {
  const queryClient = useQueryClient();
  const { t, i18n } = useTranslation(["admin", "common"]);
  // Dates follow the UI locale, not the browser default (M7-S16).
  const joinedDate = new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium" });

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [search, setSearch] = useState("");
  const [inviteOpen, setInviteOpen] = useState(false);
  const [reveal, setReveal] = useState<{
    email: string;
    tempPassword: string;
    emailSent: boolean;
  } | null>(null);
  const [pendingChange, setPendingChange] = useState<PendingChange | null>(null);
  const [changeProblem, setChangeProblem] = useState<AdminProblem | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<UserRow | null>(null);
  const [quotaTarget, setQuotaTarget] = useState<UserRow | null>(null);
  const [deleteProblem, setDeleteProblem] = useState<AdminProblem | null>(null);
  const debouncedSearch = useDebounce(search.trim(), 300);

  const listQuery = useInfiniteQuery(
    orpc.users.list.infiniteOptions({
      input: (cursor: string | undefined) => ({
        limit: PAGE_LIMIT,
        cursor,
        search: debouncedSearch || undefined,
        status: statusFilter,
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage) => lastPage.nextCursor ?? undefined,
    }),
  );
  const refreshUsers = () => void queryClient.invalidateQueries({ queryKey: orpc.users.key() });

  const closeChange = () => {
    setPendingChange(null);
    setChangeProblem(null);
  };
  const changeHandlers = (successKey: string) => ({
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setChangeProblem(null),
    onSuccess: () => {
      toast.success(t(successKey));
      closeChange();
      refreshUsers();
    },
    onError: (error: Error) => {
      setChangeProblem(adminProblem(error));
      refreshUsers();
    },
  });
  const setRole = useMutation({
    ...orpc.users.setRole.mutationOptions(),
    ...changeHandlers("admin:users.roleUpdated"),
  });
  const unarchive = useMutation({
    ...orpc.users.unarchive.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      toast.success(t("admin:users.userRestored"));
      refreshUsers();
    },
    onError: (error: Error) => {
      toast.error(t(`admin:${adminProblemKey(adminProblem(error))}`));
      refreshUsers();
    },
  });
  // The archive's success toast offers Undo, which is the row's Restore
  // (users.unarchive): it lifts the ban; ended sessions stay ended.
  const archive = useMutation({
    ...orpc.users.archive.mutationOptions(),
    ...changeHandlers("admin:users.userArchived"),
    onSuccess: (_data, variables) => {
      announceArchivedWithUndo({
        message: t("admin:users.userArchived"),
        undoLabel: t("common:actions.undo"),
        onUndo: () => unarchive.mutate({ userId: variables.userId }),
      });
      closeChange();
      refreshUsers();
    },
  });
  const remove = useMutation({
    ...orpc.users.remove.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setDeleteProblem(null),
    onSuccess: () => {
      toast.success(t("admin:users.userDeleted"));
      setDeleteTarget(null);
      refreshUsers();
    },
    onError: (error: Error) => {
      // The dialog stays open: a blocked deletion names what still exists.
      setDeleteProblem(adminProblem(error));
      refreshUsers();
    },
  });
  const changePending = setRole.isPending || archive.isPending;

  // Status is filtered server-side (see users.list), so every loaded row
  // already matches the active tab. Emptiness and pagination are decided on the
  // server result, never on a client-side slice of the pages we happen to hold.
  const allUsers = (listQuery.data?.pages.flatMap((page) => page.users) ?? []) as UserRow[];

  return (
    <PageShell inFrame width="wide">
      <PageHeader
        title={t("admin:users.title")}
        description={t("admin:users.description")}
        actions={
          <Button onClick={() => setInviteOpen(true)} className="min-h-[44px]">
            <Plus className="size-4" /> {t("admin:users.invite")}
          </Button>
        }
      />

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <SegmentedControl
          value={statusFilter}
          onChange={setStatusFilter}
          ariaLabel={t("admin:users.statusFilterAriaLabel")}
          items={[
            { value: "all", label: t("admin:users.tabAll") },
            { value: "active", label: t("admin:users.tabActive") },
            { value: "archived", label: t("admin:users.tabArchived") },
          ]}
        />
        <Input
          type="search"
          inputMode="search"
          autoComplete="off"
          aria-label={t("admin:users.searchPlaceholder")}
          placeholder={t("admin:users.searchPlaceholder")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="min-h-[44px] sm:max-w-xs"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("admin:users.allUsers")}</CardTitle>
          <CardDescription>
            {listQuery.isPending
              ? t("admin:users.loading")
              : listQuery.isError
                ? t("admin:users.loadFailedShort")
                : t("admin:users.shownCount", {
                    count: allUsers.length,
                    shown: allUsers.length,
                  })}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <QueryBoundary
            query={listQuery}
            skeleton={<SkeletonList count={6} />}
            errorMessage={t("admin:users.loadFailed")}
            errorClassName="py-12"
            isEmpty={(data) => data.pages.every((page) => page.users.length === 0)}
            empty={
              <EmptyState
                title={
                  search.trim()
                    ? t("admin:users.noMatch")
                    : statusFilter === "archived"
                      ? t("admin:users.noArchived")
                      : statusFilter === "active"
                        ? t("admin:users.noActive")
                        : t("admin:users.noUsersYet")
                }
                description={
                  search.trim() ? t("admin:users.tryDifferentQuery") : t("admin:users.inviteFirst")
                }
              />
            }
          >
            {() => (
              <>
                <ul className="divide-y">
                  {allUsers.map((user) => {
                    const isSelf = user.id === currentUserId;
                    const isAdmin = hasRole(user.role, "admin");
                    const isArchived = !!user.banned;
                    return (
                      <li
                        key={user.id}
                        data-user-id={user.id}
                        className="flex min-w-0 flex-wrap items-start justify-between gap-3 px-4 py-3 sm:items-center"
                      >
                        {/* The actions stay beside the name; they drop below it only
                            when the name column would go under 12rem (a large
                            browser font size on a phone). */}
                        <div className="min-w-0 grow basis-48">
                          <p className="flex flex-wrap items-center gap-2 font-medium">
                            <span className="truncate">{user.name || user.email}</span>
                            {isSelf && (
                              <span className="min-w-0 rounded-full border bg-muted px-1.5 py-0.5 text-xs font-medium uppercase text-muted-foreground [overflow-wrap:anywhere]">
                                {t("admin:users.youBadge")}
                              </span>
                            )}
                            <RolePill isAdmin={isAdmin} />
                            {isArchived && <ArchivedPill />}
                            {!user.emailVerified && <UnverifiedPill />}
                          </p>
                          <p className="mt-0.5 text-xs text-muted-foreground [overflow-wrap:anywhere] sm:truncate">
                            {user.email} · {t("admin:users.joined")}{" "}
                            <time dateTime={new Date(user.createdAt).toISOString()}>
                              {joinedDate.format(new Date(user.createdAt))}
                            </time>
                            {user.banReason ? ` · ${user.banReason}` : ""}
                          </p>
                          {user.cliLogins.logins > 0 ? (
                            <p data-cli-logins="" className="text-xs text-muted-foreground">
                              {t("admin:users.cliLogins", {
                                count: user.cliLogins.logins,
                                instances: user.cliLogins.instances,
                              })}
                            </p>
                          ) : null}
                          <p className="truncate font-mono text-xs text-muted-foreground">
                            {user.id}
                          </p>
                        </div>
                        <UserActions
                          user={user}
                          isSelf={isSelf}
                          isAdmin={isAdmin}
                          isArchived={isArchived}
                          restorePending={unarchive.isPending}
                          onPromote={() => setPendingChange({ kind: "promote", user })}
                          onDemote={() => setPendingChange({ kind: "demote", user })}
                          onArchive={() => setPendingChange({ kind: "archive", user })}
                          onUnarchive={() => unarchive.mutate({ userId: user.id })}
                          onDelete={() => {
                            setDeleteProblem(null);
                            setDeleteTarget(user);
                          }}
                          onImageQuota={() => setQuotaTarget(user)}
                        />
                      </li>
                    );
                  })}
                </ul>
                <LoadMore
                  hasNextPage={listQuery.hasNextPage}
                  isFetchingNextPage={listQuery.isFetchingNextPage}
                  onLoadMore={() => void listQuery.fetchNextPage()}
                />
              </>
            )}
          </QueryBoundary>
        </CardContent>
      </Card>

      {quotaTarget ? (
        <AdminImageQuotaSheet user={quotaTarget} onClose={() => setQuotaTarget(null)} />
      ) : null}

      <InviteUserDialog
        open={inviteOpen}
        onOpenChange={setInviteOpen}
        onInvited={(payload) => {
          setInviteOpen(false);
          setReveal(payload);
          refreshUsers();
        }}
      />

      <RevealInviteDialog reveal={reveal} onClose={() => setReveal(null)} />

      {pendingChange ? (
        <AdminConfirmDialog
          open
          onOpenChange={(open) => {
            if (!open) closeChange();
          }}
          title={t(`admin:users.confirm.${pendingChange.kind}Title`, {
            name: pendingChange.user.name || pendingChange.user.email,
          })}
          description={
            <>
              <span className="block">
                {t(`admin:users.confirm.${pendingChange.kind}Description`)}
              </span>
              <span className="block">{pendingChange.user.email}</span>
            </>
          }
          confirmLabel={t(`admin:users.confirm.${pendingChange.kind}Action`)}
          pendingLabel={t("admin:users.confirm.working")}
          destructive={pendingChange.kind !== "promote"}
          isPending={changePending}
          problem={changeProblem ? t(`admin:${adminProblemKey(changeProblem)}`) : null}
          onConfirm={() => {
            const userId = pendingChange.user.id;
            if (pendingChange.kind === "archive") archive.mutate({ userId });
            else
              setRole.mutate({ userId, role: pendingChange.kind === "promote" ? "admin" : "user" });
          }}
        />
      ) : null}

      <ConfirmDeleteDialog
        open={!!deleteTarget}
        onOpenChange={(open) => {
          if (!open && !remove.isPending) {
            setDeleteTarget(null);
            setDeleteProblem(null);
          }
        }}
        title={t("admin:users.deleteTitle")}
        description={
          <>
            <span className="block">{t("admin:users.deleteDescription")}</span>
            {deleteProblem ? <DeleteProblem problem={deleteProblem} /> : null}
          </>
        }
        confirmToken={deleteTarget?.email ?? ""}
        typePrompt={t("admin:users.typeEmailToConfirm")}
        copyAriaLabel={t("admin:users.copyEmailAriaLabel")}
        inputMode="email"
        isPending={remove.isPending}
        onConfirm={() => {
          if (!deleteTarget) return;
          remove.mutate({ userId: deleteTarget.id });
        }}
      />
    </PageShell>
  );
}

/**
 * A refused deletion, inside the delete dialog. Blockers are live state the
 * owner still has; nothing was deleted, and the account stays usable until
 * they are gone. Other refusals get their own one-line explanation.
 */
function DeleteProblem({ problem }: { problem: AdminProblem }) {
  const { t } = useTranslation("admin");
  if (problem.kind !== "deletionBlocked") {
    return (
      <span
        role="alert"
        className="mt-3 block rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive"
      >
        {t(adminProblemKey(problem))}
      </span>
    );
  }
  return (
    <span
      role="alert"
      data-deletion-blockers={problem.blockers.join(",")}
      className="mt-3 block rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm"
    >
      <span className="block font-medium text-destructive">{t("problems.deletionBlocked")}</span>
      <span className="mt-2 block space-y-1">
        {problem.blockers.map((blocker) => (
          <span key={blocker} className="block text-foreground">
            · {t(`blockers.${blocker}`)}
          </span>
        ))}
      </span>
      <span className="mt-2 block text-muted-foreground">{t("users.deleteBlockedHint")}</span>
    </span>
  );
}

function UserActions({
  user,
  isSelf,
  isAdmin,
  isArchived,
  restorePending,
  onPromote,
  onDemote,
  onArchive,
  onUnarchive,
  onDelete,
  onImageQuota,
}: {
  user: UserRow;
  isSelf: boolean;
  isAdmin: boolean;
  isArchived: boolean;
  restorePending: boolean;
  onPromote: () => void;
  onDemote: () => void;
  onArchive: () => void;
  onUnarchive: () => void;
  onDelete: () => void;
  onImageQuota: () => void;
}) {
  const { t } = useTranslation("admin");
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            variant="outline"
            size="sm"
            className="min-h-[44px] min-w-[44px] shrink-0"
            aria-label={t("users.actionsAriaLabel", { name: user.name || user.email })}
          />
        }
      >
        <MoreVertical aria-hidden className="size-4" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        {isAdmin ? (
          <DropdownMenuItem disabled={isSelf} onClick={onDemote}>
            <Shield className="size-4" />
            {t("users.demoteToUser")}
          </DropdownMenuItem>
        ) : (
          <DropdownMenuItem onClick={onPromote}>
            <Shield className="size-4" />
            {t("users.promoteToAdmin")}
          </DropdownMenuItem>
        )}
        {isArchived ? (
          <DropdownMenuItem disabled={restorePending} onClick={onUnarchive}>
            <ArchiveRestore className="size-4" />
            {t("users.restoreUser")}
          </DropdownMenuItem>
        ) : (
          <DropdownMenuItem disabled={isSelf} onClick={onArchive}>
            <Archive className="size-4" />
            {t("users.archiveUser")}
          </DropdownMenuItem>
        )}
        <DropdownMenuItem onClick={onImageQuota}>
          <HardDrive className="size-4" />
          {t("imageQuota.action")}
        </DropdownMenuItem>
        <DropdownMenuItem disabled={isSelf} onClick={onDelete}>
          <Trash className="size-4" />
          {t("users.deleteAction")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function RolePill({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useTranslation("admin");
  return (
    <span
      className={cn(
        "inline-flex min-w-0 items-center rounded-md px-1.5 py-0.5 text-xs font-medium uppercase [overflow-wrap:anywhere]",
        isAdmin
          ? "bg-violet-500/10 text-violet-700 dark:text-violet-400"
          : "bg-muted text-muted-foreground",
      )}
    >
      {isAdmin ? t("users.adminBadge") : t("users.userBadge")}
    </span>
  );
}

function ArchivedPill() {
  const { t } = useTranslation("admin");
  return (
    <span className="inline-flex min-w-0 items-center rounded-md bg-amber-500/10 px-1.5 py-0.5 text-xs font-medium uppercase text-amber-700 dark:text-amber-400 [overflow-wrap:anywhere]">
      {t("users.archivedBadge")}
    </span>
  );
}

function UnverifiedPill() {
  const { t } = useTranslation("admin");
  return (
    <span className="inline-flex min-w-0 items-center rounded-md bg-muted px-1.5 py-0.5 text-xs font-medium uppercase text-muted-foreground [overflow-wrap:anywhere]">
      {t("users.unverifiedBadge")}
    </span>
  );
}

function InviteUserDialog({
  open,
  onOpenChange,
  onInvited,
}: {
  open: boolean;
  onOpenChange: (next: boolean) => void;
  onInvited: (reveal: { email: string; tempPassword: string; emailSent: boolean }) => void;
}) {
  const { t, i18n } = useTranslation(["admin", "common"]);
  // The invitee's email language defaults to the admin's own; the admin
  // changes it when the invitee reads another one.
  const adminLocale: Locale = isSupportedLocale(i18n.language) ? i18n.language : "en-US";
  const [problem, setProblem] = useState<AdminProblem | null>(null);
  const invite = useMutation({
    ...orpc.users.invite.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onError: (error: Error) => setProblem(adminProblem(error)),
  });

  const form = useForm({
    defaultValues: {
      email: "",
      name: "",
      role: "user" as "user" | "admin",
      locale: adminLocale,
    },
    validators: { onChange: buildInviteSchema() },
    onSubmit: async ({ value }) => {
      try {
        const result = await invite.mutateAsync(value);
        onInvited({
          email: value.email,
          tempPassword: result.tempPassword,
          emailSent: result.emailSent,
        });
        form.reset();
      } catch {
        // Explained inline from the typed error (see `problem`).
      }
    },
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!invite.isPending) {
          if (!next) {
            form.reset();
            setProblem(null);
          }
          onOpenChange(next);
        }
      }}
    >
      <DialogContent closeLabel={t("common:actions.close")}>
        <DialogHeader>
          <DialogTitle>{t("admin:users.inviteTitle")}</DialogTitle>
          <DialogDescription>{t("admin:users.inviteDescription")}</DialogDescription>
        </DialogHeader>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            form.handleSubmit();
          }}
          className="space-y-3"
        >
          <form.Field name="name">
            {(field) => (
              <TextField
                field={field}
                label={t("admin:users.nameLabel")}
                inputMode="text"
                autoComplete="name"
                className="space-y-1.5"
              />
            )}
          </form.Field>

          <form.Field name="email">
            {(field) => (
              <TextField
                field={field}
                label={t("admin:users.emailLabel")}
                type="email"
                autoComplete="email"
                placeholder={t("admin:users.emailPlaceholder")}
                className="space-y-1.5"
              />
            )}
          </form.Field>

          <form.Field name="role">
            {(field) => (
              <div className="space-y-1.5">
                <Label htmlFor={field.name}>{t("admin:users.roleLabel")}</Label>
                <Select
                  value={field.state.value}
                  // Labels for the trigger, which otherwise shows the raw value (M7-S15).
                  items={[
                    { value: "user", label: t("admin:users.roleUser") },
                    { value: "admin", label: t("admin:users.roleAdmin") },
                  ]}
                  onValueChange={(v) => field.handleChange(v as "user" | "admin")}
                >
                  <SelectTrigger id={field.name} className="w-full min-h-[44px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user">{t("admin:users.roleUser")}</SelectItem>
                    <SelectItem value="admin">{t("admin:users.roleAdmin")}</SelectItem>
                  </SelectContent>
                </Select>
                <FieldError errors={field.state.meta.errors} />
              </div>
            )}
          </form.Field>

          <form.Field name="locale">
            {(field) => (
              <div className="space-y-1.5">
                <Label htmlFor={field.name}>{t("admin:users.localeLabel")}</Label>
                <Select
                  value={field.state.value}
                  items={SUPPORTED_LOCALES.map((locale) => ({
                    value: locale,
                    label: LOCALE_LABELS[locale],
                  }))}
                  onValueChange={(v) => {
                    if (isSupportedLocale(v)) field.handleChange(v);
                  }}
                >
                  <SelectTrigger
                    id={field.name}
                    aria-describedby={`${field.name}-description`}
                    className="w-full min-h-[44px]"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SUPPORTED_LOCALES.map((locale) => (
                      <SelectItem key={locale} value={locale} lang={locale}>
                        {LOCALE_LABELS[locale]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p id={`${field.name}-description`} className="text-xs text-muted-foreground">
                  {t("admin:users.localeDescription")}
                </p>
                <FieldError errors={field.state.meta.errors} />
              </div>
            )}
          </form.Field>

          {problem ? (
            <p role="alert" className="text-sm text-destructive">
              {t(`admin:${adminProblemKey(problem)}`)}
            </p>
          ) : null}

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              className="min-h-[44px]"
              onClick={() => onOpenChange(false)}
              disabled={invite.isPending}
            >
              {t("common:actions.cancel")}
            </Button>
            <form.Subscribe selector={(s) => [s.canSubmit, s.isSubmitting] as const}>
              {([canSubmit, isSubmitting]) => (
                <Button
                  type="submit"
                  className="min-h-[44px]"
                  disabled={!canSubmit || isSubmitting || invite.isPending}
                >
                  {isSubmitting || invite.isPending
                    ? t("admin:users.inviting")
                    : t("admin:users.sendInvite")}
                </Button>
              )}
            </form.Subscribe>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function RevealInviteDialog({
  reveal,
  onClose,
}: {
  reveal: { email: string; tempPassword: string; emailSent: boolean } | null;
  onClose: () => void;
}) {
  const { t } = useTranslation(["admin", "common", "errors"]);
  return (
    <Dialog
      open={!!reveal}
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent closeLabel={t("common:actions.close")}>
        <DialogHeader>
          <DialogTitle>{t("admin:users.revealTitle")}</DialogTitle>
          <DialogDescription>
            {reveal?.emailSent
              ? t("admin:users.revealEmailedDescription", { email: reveal.email })
              : t("admin:users.revealNotEmailedDescription", { email: reveal?.email ?? "" })}
          </DialogDescription>
        </DialogHeader>

        {/* Masked by default with Show and Copy, like every other secret. */}
        <OneTimeSecretPanel
          secret={reveal?.tempPassword ?? ""}
          label={t("admin:users.tempPasswordLabel")}
          warning={t("admin:users.tempPasswordHint")}
          doneLabel={t("admin:users.savedPassword")}
          copyLabel={t("admin:users.copyTempPasswordAriaLabel")}
          onDone={onClose}
        />
      </DialogContent>
    </Dialog>
  );
}
