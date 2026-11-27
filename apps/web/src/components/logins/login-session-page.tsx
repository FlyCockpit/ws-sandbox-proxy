import { skipToken, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
import { CopyField } from "@wssp/ui/components/copy-field";
import { toast } from "@wssp/ui/components/sileo";
import { ArrowLeft } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { EmptyState } from "@/components/empty-state";
import { invalidateLogins } from "@/components/logins/logins-shared";
import { PageHeader } from "@/components/page-shell";
import { QueryBoundary } from "@/components/query-boundary";
import { SandboxTerminal } from "@/components/sandboxes/sandbox-terminal";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { credentialErrorCode } from "@/lib/credential-errors";
import { dateTimeTitle } from "@/lib/format-date-time";
import { friendly } from "@/utils/friendly-error";
import { orpc } from "@/utils/orpc";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * One login session: its state, polled until it
 * settles (PROVISIONING → READY → SAVING → SAVED; FAILED, CANCELLED or
 * EXPIRED), the login command with Copy and "Type it for me", the login
 * sandbox's terminal (session-only; the ticket is minted by the same path as
 * any sandbox terminal), and Save, Check and Cancel. FAILED keeps the
 * sandbox: fix it in the terminal and save again. The page can be reopened
 * after a reload from the login page's open sessions.
 */

type LoginSession = Awaited<ReturnType<AppRouterClient["logins"]["getLoginSession"]>>;
export type LoginSessionState = LoginSession["state"];

/** States in which the session still holds its instance (cancel is allowed). */
const OPEN_SESSION_STATES: ReadonlySet<LoginSessionState> = new Set([
  "PROVISIONING",
  "READY",
  "SAVING",
  "FAILED",
]);
/** States in which the terminal, Save and Check are available. */
const WORKING_STATES: ReadonlySet<LoginSessionState> = new Set(["READY", "FAILED"]);

/** Poll quickly while the server is moving the session, slower while the user works. */
export function sessionPollMs(state: LoginSessionState | undefined): number | false {
  if (state === undefined || state === "PROVISIONING" || state === "SAVING") return 2_000;
  if (state === "READY" || state === "FAILED") return 5_000;
  return false;
}

const STATE_VARIANT: Record<LoginSessionState, "secondary" | "destructive" | "outline"> = {
  PROVISIONING: "outline",
  READY: "secondary",
  SAVING: "outline",
  SAVED: "secondary",
  FAILED: "destructive",
  CANCELLED: "outline",
  EXPIRED: "destructive",
};

const ACTIVE_OPERATION_STATES = new Set([
  "QUEUED",
  "DISPATCHED",
  "ACCEPTED",
  "RUNNING",
  "CANCEL_REQUESTED",
]);

export function LoginSessionPage({ lang, sessionId }: { lang: string; sessionId: string }) {
  const { t } = useTranslation(["logins", "dashboard"]);
  const session = useQuery({
    ...orpc.logins.getLoginSession.queryOptions({ input: { id: sessionId } }),
    refetchInterval: (query) => sessionPollMs(query.state.data?.state),
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [session.error]);
  const missing =
    session.isError && credentialErrorCode(session.error) === "login_session_not_found";

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
      {missing ? (
        <EmptyState className="rounded-xl border px-4" title={t("logins:session.notFound")} />
      ) : (
        <QueryBoundary
          query={{
            data: session.data,
            isPending: session.isPending,
            isError: session.isError,
            fetchStatus: session.fetchStatus,
            error: session.error,
            refetch: session.refetch,
          }}
          skeleton={<SkeletonList layout="resource" count={2} className="rounded-xl border" />}
          errorMessage={t("dashboard:list.loadFailed")}
        >
          {(data) => <SessionBody lang={lang} session={data} />}
        </QueryBoundary>
      )}
    </div>
  );
}

function SessionBody({ lang, session }: { lang: string; session: LoginSession }) {
  const { t, i18n } = useTranslation(["logins", "terminal", "common"]);
  const queryClient = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [cancelling, setCancelling] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [verifyOperationId, setVerifyOperationId] = useState<string | null>(null);
  const login = useQuery({
    ...orpc.logins.getLogin.queryOptions({ input: { id: session.credentialId } }),
    meta: { skipGlobalErrorToast: true },
  });
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: orpc.logins.getLoginSession.key() });
    invalidateLogins(queryClient);
  };
  const onError = (error: unknown) => {
    if (!redirect(error)) setProblem(friendly(error));
  };
  const finish = useMutation({
    ...orpc.logins.finishLogin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: () => toast.success(t("logins:session.saveRequested")),
    onError,
    onSettled: refresh,
  });
  const verify = useMutation({
    ...orpc.logins.verifyLogin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      setProblem(null);
      setVerifyOperationId(null);
    },
    onSuccess: (operation) => setVerifyOperationId(operation.operationId),
    onError,
  });
  const cancel = useMutation({
    ...orpc.logins.cancelLogin.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => setProblem(null),
    onSuccess: () => toast.success(t("logins:session.cancelled")),
    onError,
    onSettled: () => {
      setCancelling(false);
      refresh();
    },
  });
  const verifyOperation = useQuery({
    ...orpc.sandboxes.getOperationView.queryOptions({
      input: verifyOperationId ? { operationId: verifyOperationId } : skipToken,
    }),
    refetchInterval: (query) =>
      query.state.data && !ACTIVE_OPERATION_STATES.has(query.state.data.state) ? false : 2_000,
    meta: { skipGlobalErrorToast: true },
  });

  const state = session.state;
  const working = WORKING_STATES.has(state);
  const open = OPEN_SESSION_STATES.has(state);
  const instructions = session.login;
  const busy = finish.isPending || verify.isPending || cancel.isPending;
  const loginName = login.data?.name;
  const verifyResult = verifyOperation.data;

  return (
    <div className="flex min-w-0 flex-col gap-6" data-login-session-state={state}>
      <PageHeader
        title={
          loginName
            ? translateText(t, "logins:session.titleNamed", { name: loginName })
            : t("logins:session.title")
        }
        description={t("logins:session.description")}
      />
      <section
        aria-labelledby="login-session-state"
        className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
      >
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h2 id="login-session-state" className="font-medium">
            {t("logins:session.stateHeading")}
          </h2>
          <Badge variant={STATE_VARIANT[state]} data-session-state={state}>
            {t(`logins:session.state.${state}`)}
          </Badge>
        </div>
        <p role="status" aria-live="polite" className="text-sm">
          {t(`logins:session.stateHint.${state}`)}
        </p>
        {open ? (
          <p
            className="text-sm text-muted-foreground"
            title={dateTimeTitle(session.expiresAt, i18n.language)}
          >
            {t("logins:session.expires", {
              when: formatRelativeTime(Date.parse(session.expiresAt), i18n.language, Date.now()),
            })}
          </p>
        ) : null}
        {session.foreignConsent ? (
          <p className="text-sm text-amber-800 dark:text-amber-300">
            {t("logins:session.foreignHost")}
          </p>
        ) : null}
        {state === "SAVED" || state === "CANCELLED" || state === "EXPIRED" ? (
          <Link
            to="/$lang/settings/logins/$loginId"
            params={{ lang, loginId: session.credentialId }}
            className="inline-flex min-h-11 items-center text-sm underline underline-offset-4"
          >
            {t("logins:session.backToLogin")}
          </Link>
        ) : null}
      </section>

      {instructions && open ? (
        <section
          aria-labelledby="login-session-command"
          className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
        >
          <h2 id="login-session-command" className="font-medium">
            {t("logins:session.command.heading")}
          </h2>
          {instructions.supported ? (
            <>
              <p className="text-sm text-muted-foreground">{t("logins:session.command.hint")}</p>
              <CopyField
                value={instructions.command}
                copyLabel={t("logins:session.command.copy")}
                onCopyError={() => toast.error(t("errors:couldNotCopy"))}
              />
              {instructions.doneWhenCommandExits ? (
                <p className="text-sm text-muted-foreground">
                  {t("logins:session.command.doneWhenExits")}
                </p>
              ) : null}
            </>
          ) : (
            <p role="alert" data-login-unsupported="" className="text-sm text-destructive">
              {t("logins:session.command.unsupported")}
            </p>
          )}
        </section>
      ) : null}

      {open && session.sandboxId ? (
        <SandboxTerminal
          key={session.sandboxId}
          sandboxId={session.sandboxId}
          lang={lang}
          available={working}
          typeCommand={instructions?.supported ? instructions.command : undefined}
        />
      ) : null}

      {open ? (
        <section
          aria-labelledby="login-session-actions"
          className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
        >
          <h2 id="login-session-actions" className="font-medium">
            {t("logins:session.actions.heading")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("logins:session.actions.hint")}</p>
          <div className="flex min-w-0 flex-wrap gap-2">
            <Button
              type="button"
              size="touch"
              disabled={!working || busy}
              onClick={() => finish.mutate({ id: session.id })}
            >
              {finish.isPending
                ? t("logins:session.actions.saving")
                : t("logins:session.actions.save")}
            </Button>
            {instructions?.hasVerifyCommand ? (
              <Button
                type="button"
                size="touch"
                variant="outline"
                disabled={!working || busy}
                onClick={() => verify.mutate({ id: session.id })}
              >
                {t("logins:session.actions.verify")}
              </Button>
            ) : null}
            <Button
              type="button"
              size="touch"
              variant="outline"
              disabled={cancel.isPending}
              onClick={() => setCancelling(true)}
            >
              {t("logins:session.actions.cancel")}
            </Button>
          </div>
          {verifyOperationId ? (
            <p role="status" data-verify-result="" className="text-sm">
              {!verifyResult || ACTIVE_OPERATION_STATES.has(verifyResult.state)
                ? t("logins:session.verify.running")
                : verifyResult.exitCode === 0
                  ? t("logins:session.verify.passed")
                  : verifyResult.exitCode !== null
                    ? t("logins:session.verify.failed", { code: verifyResult.exitCode })
                    : t("logins:session.verify.unknown")}
            </p>
          ) : null}
          {problem ? (
            <p role="alert" className="text-sm text-destructive">
              {problem}
            </p>
          ) : null}
        </section>
      ) : null}

      <AlertDialog
        open={cancelling}
        onOpenChange={(next) => !cancel.isPending && setCancelling(next)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("logins:session.cancelTitle")}</AlertDialogTitle>
            <AlertDialogDescription>{t("logins:session.cancelDescription")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="min-h-11" disabled={cancel.isPending}>
              {t("logins:session.keepWorking")}
            </AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              className="min-h-11"
              disabled={cancel.isPending}
              onClick={(event) => {
                event.preventDefault();
                cancel.mutate({ id: session.id });
              }}
            >
              {t("logins:session.actions.cancel")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
