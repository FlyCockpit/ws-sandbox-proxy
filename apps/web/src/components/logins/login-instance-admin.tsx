import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
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
import { Checkbox } from "@wssp/ui/components/checkbox";
import { Label } from "@wssp/ui/components/label";
import { toast } from "@wssp/ui/components/sileo";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { LoadMore } from "@/components/load-more";
import {
  type InstanceItem,
  instanceLabel,
  invalidateLogins,
  type LoginItem,
} from "@/components/logins/logins-shared";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * Owner recovery on one instance:
 * its live leases (holders) with their newest promotable checkpoint, force
 * release (AlertDialog: the guest's newest rotation may be lost; optionally
 * promote the checkpoint), and the quarantined (rejected) captures with
 * "Discard rejected captures" (AlertDialog, type-to-confirm). Metadata only.
 */

export type InstanceLease = Awaited<
  ReturnType<AppRouterClient["logins"]["listInstanceLeases"]>
>["items"][number];

const pages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

export function InstanceRecovery({
  lang,
  login,
  instance,
  writable,
}: {
  lang: string;
  login: LoginItem;
  instance: InstanceItem;
  writable: boolean;
}) {
  const { t, i18n } = useTranslation(["logins", "dashboard", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [releasing, setReleasing] = useState<InstanceLease | null>(null);
  const [discarding, setDiscarding] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const scope = { credentialId: login.id, instanceId: instance.id };
  const leases = useInfiniteQuery({
    ...orpc.logins.listInstanceLeases.infiniteOptions({
      ...pages,
      input: (cursor: string | undefined) => ({ ...scope, limit: DASHBOARD_PAGE_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const rejected = useInfiniteQuery({
    ...orpc.logins.listRejectedCaptures.infiniteOptions({
      ...pages,
      input: (cursor: string | undefined) => ({ ...scope, limit: DASHBOARD_PAGE_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [leases.error, rejected.error]);
  const discard = useMutation({
    ...orpc.logins.discardRejectedCaptures.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  const leaseRows = leases.data?.pages.flatMap((page) => page.items);
  const rejectedRows = rejected.data?.pages.flatMap((page) => page.items);
  const label = instanceLabel(t, instance);
  const now = Date.now();

  return (
    <div className="flex min-w-0 flex-col gap-3 rounded-lg border p-3" data-instance-recovery="">
      <h5 className="text-sm font-medium">{t("logins:leases.heading")}</h5>
      <QueryBoundary
        query={{
          data: leaseRows,
          isPending: leases.isPending,
          isError: leases.isError,
          error: leases.error,
          refetch: leases.refetch,
        }}
        skeleton={<SkeletonList count={1} className="rounded-lg border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={<p className="text-sm text-muted-foreground">{t("logins:leases.empty")}</p>}
      >
        {(items) => (
          <>
            <ul
              aria-label={t("logins:leases.label", { instance: label })}
              className="flex flex-col gap-2"
            >
              {items.map((lease) => (
                <li
                  key={lease.id}
                  data-lease-id={lease.id}
                  className="flex min-w-0 flex-wrap items-center justify-between gap-2 text-sm"
                >
                  <div className="flex min-w-0 flex-col gap-1">
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      <Badge
                        variant={lease.state === "RECOVERY_REQUIRED" ? "destructive" : "outline"}
                      >
                        {t(`logins:leases.state.${lease.state}`)}
                      </Badge>
                      <span>{t(`logins:leases.kind.${lease.kind}`)}</span>
                      {lease.sandboxId ? (
                        <Link
                          to="/$lang/dashboard/sandboxes/$sandboxId"
                          params={{ lang, sandboxId: lease.sandboxId }}
                          className="inline-flex min-h-11 items-center break-all font-mono text-xs underline underline-offset-4"
                        >
                          {lease.sandboxId}
                        </Link>
                      ) : null}
                    </div>
                    <span className="text-muted-foreground">
                      {lease.checkpoint
                        ? t("logins:leases.checkpoint", {
                            seq: lease.checkpoint.storageSeq,
                            when: formatRelativeTime(
                              Date.parse(lease.checkpoint.at),
                              i18n.language,
                              now,
                            ),
                          })
                        : t("logins:leases.noCheckpoint")}
                    </span>
                  </div>
                  {writable ? (
                    <Button
                      type="button"
                      size="touch"
                      variant="outline"
                      onClick={() => {
                        setProblem(null);
                        setReleasing(lease);
                      }}
                    >
                      {t("logins:leases.forceRelease")}
                    </Button>
                  ) : null}
                </li>
              ))}
            </ul>
            <LoadMore
              hasNextPage={leases.hasNextPage}
              isFetchingNextPage={leases.isFetchingNextPage}
              onLoadMore={() => void leases.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>

      <h5 className="text-sm font-medium">{t("logins:rejected.heading")}</h5>
      <p className="text-sm text-muted-foreground">{t("logins:rejected.description")}</p>
      <QueryBoundary
        query={{
          data: rejectedRows,
          isPending: rejected.isPending,
          isError: rejected.isError,
          error: rejected.error,
          refetch: rejected.refetch,
        }}
        skeleton={<SkeletonList count={1} className="rounded-lg border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={<p className="text-sm text-muted-foreground">{t("logins:rejected.empty")}</p>}
      >
        {(items) => (
          <>
            <ul aria-label={t("logins:rejected.label")} className="flex flex-col gap-1 text-sm">
              {items.map((capture) => (
                <li key={capture.captureId} className="break-words">
                  {t("logins:rejected.item", {
                    reason: capture.reason,
                    when: formatRelativeTime(Date.parse(capture.at), i18n.language, now),
                  })}
                </li>
              ))}
            </ul>
            <LoadMore
              hasNextPage={rejected.hasNextPage}
              isFetchingNextPage={rejected.isFetchingNextPage}
              onLoadMore={() => void rejected.fetchNextPage()}
            />
            {writable ? (
              <Button
                type="button"
                size="touch"
                variant="outline"
                className="self-start"
                onClick={() => {
                  setProblem(null);
                  setDiscarding(true);
                }}
              >
                {t("logins:rejected.discard")}
              </Button>
            ) : null}
          </>
        )}
      </QueryBoundary>
      {problem ? (
        <p role="alert" className="text-sm text-destructive">
          {problem}
        </p>
      ) : null}
      {releasing ? (
        <ForceReleaseDialog
          lang={lang}
          login={login}
          instance={instance}
          lease={releasing}
          onClose={() => setReleasing(null)}
        />
      ) : null}
      <ConfirmDeleteDialog
        open={discarding}
        onOpenChange={setDiscarding}
        title={t("logins:rejected.discardTitle", { name: label })}
        description={t("logins:rejected.discardDescription")}
        confirmToken={label}
        typePrompt={t("logins:instances.deletePrompt")}
        copyAriaLabel={t("logins:instances.copyName")}
        confirmLabel={t("logins:rejected.discardConfirm")}
        pendingLabel={t("logins:rejected.discarding")}
        isPending={discard.isPending}
        onConfirm={async () => {
          setProblem(null);
          try {
            const result = await discard.mutateAsync(scope);
            toast.success(t("logins:rejected.discarded", { count: result.discarded }));
          } catch (error) {
            if (!redirect(error)) setProblem(friendly(error));
          } finally {
            setDiscarding(false);
            invalidateLogins(queryClient);
          }
        }}
      />
    </div>
  );
}

/** Force release one lease, with the lost-rotation warning and optional checkpoint promotion. */
function ForceReleaseDialog({
  lang,
  login,
  instance,
  lease,
  onClose,
}: {
  lang: string;
  login: Pick<LoginItem, "id">;
  instance: Pick<InstanceItem, "id">;
  lease: InstanceLease;
  onClose: () => void;
}) {
  const { t } = useTranslation(["logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const promoteId = useId();
  const [promote, setPromote] = useState(lease.checkpoint !== null);
  const [problem, setProblem] = useState<string | null>(null);
  const release = useMutation({
    ...orpc.logins.forceRelease.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
  });

  return (
    <AlertDialog open onOpenChange={(open) => (open || release.isPending ? undefined : onClose())}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{t("logins:leases.forceReleaseTitle")}</AlertDialogTitle>
          <AlertDialogDescription>
            {t("logins:leases.forceReleaseDescription")}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <p className="text-sm text-amber-800 dark:text-amber-300" data-lost-rotation="">
          {t("logins:leases.lostRotation")}
        </p>
        {lease.checkpoint ? (
          <div className="flex min-h-11 items-center gap-3">
            <Checkbox
              id={promoteId}
              checked={promote}
              onCheckedChange={(checked) => setPromote(checked === true)}
            />
            <Label htmlFor={promoteId}>
              {t("logins:leases.promote", { seq: lease.checkpoint.storageSeq })}
            </Label>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">{t("logins:leases.noCheckpoint")}</p>
        )}
        {problem ? (
          <p role="alert" className="text-sm text-destructive">
            {problem}
          </p>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel className="min-h-11" disabled={release.isPending}>
            {t("common:actions.cancel")}
          </AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            className="min-h-11"
            disabled={release.isPending}
            onClick={async (event) => {
              event.preventDefault();
              setProblem(null);
              try {
                const result = await release.mutateAsync({
                  credentialId: login.id,
                  instanceId: instance.id,
                  leaseId: lease.id,
                  promoteCheckpoint: lease.checkpoint !== null && promote,
                });
                toast.success(
                  result.promoted
                    ? t("logins:leases.releasedPromoted", { seq: result.promoted.storageSeq })
                    : t("logins:leases.released"),
                );
                onClose();
              } catch (error) {
                if (!redirect(error)) setProblem(friendly(error));
              } finally {
                invalidateLogins(queryClient);
              }
            }}
          >
            {release.isPending ? t("logins:leases.releasing") : t("logins:leases.forceRelease")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
