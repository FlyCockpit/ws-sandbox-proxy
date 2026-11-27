import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { AppRouterClient } from "@wssp/api/routers/index";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@wssp/ui/components/alert-dialog";
import { Badge } from "@wssp/ui/components/badge";
import { Button } from "@wssp/ui/components/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { toast } from "@wssp/ui/components/sileo";
import { Plus } from "lucide-react";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { DASHBOARD_PAGE_LIMIT } from "@/components/dashboard/resource-list";
import { LoadMore } from "@/components/load-more";
import {
  EMPTY_LOGIN_CHOICE,
  type LoginChoice,
  LoginChoiceFields,
  loginRequest,
} from "@/components/logins/login-picker";
import {
  accountLabel,
  instanceLabel,
  useLoginsAvailability,
} from "@/components/logins/logins-shared";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { credentialErrorCode } from "@/lib/credential-errors";
import { IntentKeys } from "@/lib/sandbox-rules";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";

/**
 * The sandbox detail Credentials panel: the
 * logins attached to this sandbox (login → account → instance, lease state),
 * Attach (a READY sandbox installs it now; a STOPPED one records it for the
 * next start) and Free (its env leaves new commands, open terminals using it
 * close, its files are copied back unless discarded, then scrubbed). Every
 * action is a request; the list shows whatever the server reports next.
 */

export type SandboxCredential = Awaited<
  ReturnType<AppRouterClient["logins"]["listSandboxCredentials"]>
>["items"][number];

const ATTACHABLE_STATES = new Set(["READY", "STOPPED"]);

/** Poll cadence while some lease is moving, and otherwise. */
export const CREDENTIALS_BUSY_REFETCH_MS = 5_000;
export const CREDENTIALS_IDLE_REFETCH_MS = 15_000;

/** Lease states an attach, free or recovery is still moving. */
const MOVING_LEASE_STATES = new Set(["RESERVED", "INSTALLING", "RELEASING", "RECOVERING"]);

export function credentialsRefetchInterval(
  pages: readonly { items: readonly Pick<SandboxCredential, "lease">[] }[] | undefined,
): number {
  return pages?.some((page) =>
    page.items.some((row) => row.lease != null && MOVING_LEASE_STATES.has(row.lease.state)),
  )
    ? CREDENTIALS_BUSY_REFETCH_MS
    : CREDENTIALS_IDLE_REFETCH_MS;
}

/** True when the server answered (a lost response keeps the intent's key for a retry). */
function answered(error: unknown): boolean {
  return (
    !!error &&
    typeof error === "object" &&
    typeof (error as { status?: unknown }).status === "number"
  );
}

function invalidate(queryClient: ReturnType<typeof useQueryClient>) {
  void queryClient.invalidateQueries({ queryKey: orpc.logins.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
}

export function SandboxCredentials({
  lang,
  sandboxId,
  sandboxState,
}: {
  lang: string;
  sandboxId: string;
  sandboxState: string;
}) {
  const availability = useLoginsAvailability();
  if (availability !== "enabled" && availability !== "readOnly") return null;
  return (
    <SandboxCredentialsPanel
      lang={lang}
      sandboxId={sandboxId}
      sandboxState={sandboxState}
      writable={availability === "enabled"}
    />
  );
}

function SandboxCredentialsPanel({
  lang,
  sandboxId,
  sandboxState,
  writable,
}: {
  lang: string;
  sandboxId: string;
  sandboxState: string;
  writable: boolean;
}) {
  const { t } = useTranslation(["sandboxes", "logins", "dashboard"]);
  const [attaching, setAttaching] = useState(false);
  const [freeing, setFreeing] = useState<SandboxCredential | null>(null);
  const attached = useInfiniteQuery({
    ...orpc.logins.listSandboxCredentials.infiniteOptions({
      input: (cursor: string | undefined) => ({
        id: sandboxId,
        limit: DASHBOARD_PAGE_LIMIT,
        cursor,
      }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
    // Lease states move with attach/free operations: poll quickly only while
    // one is in flight.
    refetchInterval: (current) => credentialsRefetchInterval(current.state.data?.pages),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [attached.error]);
  const rows = attached.data?.pages.flatMap((page) => page.items);
  const canAttach = writable && ATTACHABLE_STATES.has(sandboxState);

  return (
    <section
      aria-labelledby="sandbox-credentials"
      data-sandbox-credentials=""
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
        <h2 id="sandbox-credentials" className="text-sm font-medium">
          {t("sandboxes:credentials.heading")}
        </h2>
        {canAttach ? (
          <Button type="button" size="touch" variant="outline" onClick={() => setAttaching(true)}>
            <Plus aria-hidden="true" />
            {t("sandboxes:credentials.attach")}
          </Button>
        ) : null}
      </div>
      <p className="text-sm text-muted-foreground">
        {sandboxState === "STOPPED"
          ? t("sandboxes:credentials.stoppedHint")
          : t("sandboxes:credentials.description")}
      </p>
      <QueryBoundary
        query={{
          data: rows,
          isPending: attached.isPending,
          isError: attached.isError,
          fetchStatus: attached.fetchStatus,
          error: attached.error,
          refetch: attached.refetch,
        }}
        skeleton={<SkeletonList count={1} className="rounded-lg border" />}
        errorMessage={t("dashboard:list.loadFailed")}
        isEmpty={(items) => items.length === 0}
        empty={<p className="text-sm text-muted-foreground">{t("sandboxes:credentials.empty")}</p>}
      >
        {(items) => (
          <>
            <ul
              aria-label={t("sandboxes:credentials.label")}
              className="flex min-w-0 flex-col divide-y rounded-lg border"
            >
              {items.map((row) => (
                <li
                  key={row.credentialId}
                  data-credential-id={row.credentialId}
                  className="flex min-w-0 flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm"
                >
                  <div className="flex min-w-0 flex-col gap-1">
                    <Link
                      to="/$lang/settings/logins/$loginId"
                      params={{ lang, loginId: row.credentialId }}
                      className="inline-flex min-h-11 items-center break-words font-medium underline underline-offset-4"
                    >
                      {row.name}
                    </Link>
                    <span className="break-words text-muted-foreground">
                      {[
                        row.account
                          ? accountLabel(t, row.account)
                          : t("sandboxes:credentials.anyAccount"),
                        row.instance
                          ? instanceLabel(t, row.instance)
                          : t("sandboxes:credentials.anyInstance"),
                      ].join(" · ")}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge
                      variant={row.lease?.state === "RECOVERY_REQUIRED" ? "destructive" : "outline"}
                      data-lease-state={row.lease?.state ?? "none"}
                    >
                      {row.lease
                        ? t(`logins:leases.state.${row.lease.state}`)
                        : t("sandboxes:credentials.notInstalled")}
                    </Badge>
                    {writable && ATTACHABLE_STATES.has(sandboxState) ? (
                      <Button
                        type="button"
                        size="touch"
                        variant="outline"
                        onClick={() => setFreeing(row)}
                      >
                        {t("sandboxes:credentials.free")}
                      </Button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
            <LoadMore
              hasNextPage={attached.hasNextPage}
              isFetchingNextPage={attached.isFetchingNextPage}
              onLoadMore={() => void attached.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      {attaching ? (
        <AttachLoginDialog
          lang={lang}
          sandboxId={sandboxId}
          attached={(rows ?? []).map((row) => row.credentialId)}
          onClose={() => setAttaching(false)}
        />
      ) : null}
      {freeing ? (
        <FreeLoginDialog
          lang={lang}
          sandboxId={sandboxId}
          credential={freeing}
          onClose={() => setFreeing(null)}
        />
      ) : null}
    </section>
  );
}

function AttachLoginDialog({
  lang,
  sandboxId,
  attached,
  onClose,
}: {
  lang: string;
  sandboxId: string;
  attached: readonly string[];
  onClose: () => void;
}) {
  const { t } = useTranslation(["sandboxes", "logins", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const intents = useRef(new IntentKeys());
  const [choice, setChoice] = useState<LoginChoice>(EMPTY_LOGIN_CHOICE);
  const [problem, setProblem] = useState<string | null>(null);
  const [proxyRefused, setProxyRefused] = useState(false);
  const attach = useMutation({
    ...orpc.logins.attachSandboxCredential.mutationOptions(),
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  const submit = async () => {
    setProblem(null);
    setProxyRefused(false);
    if (!choice.credentialId) {
      setProblem(t("logins:picker.loginRequired"));
      return;
    }
    const request = loginRequest(choice);
    try {
      await attach.mutateAsync(
        intents.current.for("credentialAttach", JSON.stringify([sandboxId, request]), (key) => ({
          id: sandboxId,
          idempotencyKey: key,
          ...request,
        })),
      );
      intents.current.settle();
      toast.success(t("sandboxes:credentials.attachRequested"));
      onClose();
    } catch (error) {
      if (redirect(error)) return;
      // A refusal is final for this intent; the next click is a new request.
      if (answered(error)) intents.current.settle();
      setProxyRefused(credentialErrorCode(error) === "proxy_not_enabled");
      setProblem(friendly(error));
    } finally {
      invalidate(queryClient);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => (open || attach.isPending ? undefined : onClose())}>
      <DialogContent closeLabel={t("common:actions.close")} className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("sandboxes:credentials.attachTitle")}</DialogTitle>
          <DialogDescription>{t("sandboxes:credentials.attachDescription")}</DialogDescription>
        </DialogHeader>
        {/* Disk offload §5: any login grant keeps the sandbox on own hosts, permanently. */}
        <p data-own-hosts-note="" className="text-sm text-muted-foreground">
          {t("sandboxes:credentials.ownHostsNote")}
        </p>
        <form
          noValidate
          className="flex min-w-0 flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void submit();
          }}
        >
          <LoginChoiceFields
            value={choice}
            onChange={setChoice}
            exclude={attached}
            disabled={attach.isPending}
          />
          {problem ? (
            <div role="alert" className="flex flex-col gap-1 text-sm text-destructive">
              <p>{problem}</p>
              {proxyRefused ? (
                <p className="text-muted-foreground" data-proxy-hint="">
                  {t("sandboxes:credentials.proxyHint")}
                </p>
              ) : null}
            </div>
          ) : null}
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="touch"
              disabled={attach.isPending}
              onClick={onClose}
            >
              {t("common:actions.cancel")}
            </Button>
            <Button type="submit" size="touch" disabled={attach.isPending}>
              {attach.isPending
                ? t("sandboxes:credentials.attaching")
                : t("sandboxes:credentials.attach")}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/** Free (copy back, then scrub) or "Free anyway (discard)" (`credentialCapture: "skip"`). */
function FreeLoginDialog({
  lang,
  sandboxId,
  credential,
  onClose,
}: {
  lang: string;
  sandboxId: string;
  credential: Pick<SandboxCredential, "credentialId" | "name">;
  onClose: () => void;
}) {
  const { t } = useTranslation(["sandboxes", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const intents = useRef(new IntentKeys());
  const [problem, setProblem] = useState<string | null>(null);
  const free = useMutation({
    ...orpc.logins.freeSandboxCredential.mutationOptions(),
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  const run = async (skip: boolean) => {
    setProblem(null);
    try {
      await free.mutateAsync(
        intents.current.for(
          skip ? "credentialFreeSkip" : "credentialFree",
          JSON.stringify([sandboxId, credential.credentialId]),
          (key) => ({
            id: sandboxId,
            credentialId: credential.credentialId,
            idempotencyKey: key,
            ...(skip ? { credentialCapture: "skip" as const } : {}),
          }),
        ),
      );
      intents.current.settle();
      toast.success(t("sandboxes:credentials.freeRequested"));
      onClose();
    } catch (error) {
      if (redirect(error)) return;
      if (answered(error)) intents.current.settle();
      setProblem(friendly(error));
    } finally {
      invalidate(queryClient);
    }
  };

  return (
    <AlertDialog open onOpenChange={(open) => (open || free.isPending ? undefined : onClose())}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {t("sandboxes:credentials.freeTitle", { name: credential.name })}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {t("sandboxes:credentials.freeDescription")}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <ul className="list-disc ps-5 text-sm">
          <li>{t("sandboxes:credentials.freeTerminals")}</li>
          <li>{t("sandboxes:credentials.freeRevocation")}</li>
          <li>{t("sandboxes:credentials.freeDiscardHint")}</li>
        </ul>
        {problem ? (
          <p role="alert" className="text-sm text-destructive">
            {problem}
          </p>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel className="min-h-11" disabled={free.isPending}>
            {t("common:actions.cancel")}
          </AlertDialogCancel>
          <Button
            type="button"
            size="touch"
            variant="outline"
            disabled={free.isPending}
            onClick={() => void run(true)}
          >
            {t("sandboxes:credentials.freeDiscard")}
          </Button>
          <Button
            type="button"
            size="touch"
            variant="destructive"
            disabled={free.isPending}
            onClick={() => void run(false)}
          >
            {free.isPending ? t("sandboxes:credentials.freeing") : t("sandboxes:credentials.free")}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
