import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
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
import { Button } from "@wssp/ui/components/button";
import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { LoadMore } from "@/components/load-more";
import { QueryBoundary } from "@/components/query-boundary";
import { SkeletonList } from "@/components/skeleton-list";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { formatDateTime } from "@/lib/format-date-time";
import { PASTE_MAX_BYTES } from "@/lib/terminal-client";
import { orpc } from "@/utils/orpc";
import { HostTerminal } from "./host-detail-page";

type Host = Awaited<ReturnType<AppRouterClient["sandboxHosts"]["getHost"]>>;
export function HostAgentAccess({
  host,
  lang,
}: {
  host: Pick<
    Host,
    | "id"
    | "status"
    | "agentPolicy"
    | "agentAccess"
    | "terminalPolicy"
    | "agentHostCommandsVetoedAt"
    | "hostTerminalVetoedAt"
  >;
  lang: string;
}) {
  const { t } = useTranslation("agents");
  const client = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [target, setTarget] = useState<{
    setting: "commands" | "terminal";
    action: "lower" | "lift";
  } | null>(null);
  const lower = useMutation({
    mutationFn: (value: NonNullable<typeof target>) =>
      value.action === "lift"
        ? value.setting === "commands"
          ? orpc.sandboxHosts.liftAgentHostCommandsVeto.call({ id: host.id })
          : orpc.sandboxHosts.liftHostTerminalVeto.call({ id: host.id })
        : value.setting === "commands"
          ? orpc.sandboxHosts.lowerAgentHostCommands.call({ id: host.id })
          : orpc.sandboxHosts.lowerHostTerminal.call({ id: host.id }),
    meta: { skipGlobalErrorToast: true },
    onSuccess: () => {
      setTarget(null);
      void client.invalidateQueries({ queryKey: orpc.sandboxHosts.getHost.key() });
    },
    onError: (error) => {
      redirect(error);
    },
  });
  const rows = [
    {
      id: "commands" as const,
      on: host.agentPolicy?.nodeHostCommands ?? host.agentPolicy?.hostCommands,
      vetoed: host.agentHostCommandsVetoedAt,
      canLift: host.status === "CONNECTED" && host.agentPolicy?.nodeHostCommands === false,
      offCommand: "wssp host config set-agent-host-commands off",
      command: "wssp host config set-agent-host-commands on",
    },
    {
      id: "terminal" as const,
      on: host.terminalPolicy?.nodeHostTerminal ?? host.terminalPolicy?.hostTerminal,
      vetoed: host.hostTerminalVetoedAt,
      canLift: host.status === "CONNECTED" && host.terminalPolicy?.nodeHostTerminal === false,
      offCommand: "wssp host config set-host-terminal off",
      command: "wssp host config set-host-terminal on",
    },
  ];
  const liftUnavailable =
    target?.action === "lift" && !rows.find((row) => row.id === target.setting)?.canLift;
  return (
    <section className="flex min-w-0 flex-col gap-4 rounded-xl border p-4">
      <h2 className="font-semibold">{t("host.title")}</h2>
      <p
        role="note"
        className="rounded-lg border border-amber-500/50 p-3 text-sm text-amber-800 dark:text-amber-300"
      >
        {t("consent.hostWarning")}
      </p>
      {rows.map((row) => (
        <div key={row.id} className="flex min-w-0 flex-col gap-2">
          <h3>{t(`host.${row.id}`)}</h3>
          <p role="status">
            {t(row.on === undefined ? "host.unknown" : row.on ? "host.on" : "host.off")}
          </p>
          {row.vetoed ? (
            <>
              <p role="status">{t("host.vetoed")}</p>
              {row.on ? (
                <p role="alert">{t("host.tamperWarning", { command: row.offCommand })}</p>
              ) : null}
              {!row.canLift ? (
                <p id={`${host.id}-${row.id}-lift-help`}>
                  {t("host.liftUnavailable", { command: row.offCommand })}
                </p>
              ) : null}
              <Button
                size="touch"
                variant="outline"
                className="sm:self-start"
                aria-label={t("host.allowAgainNamed", { setting: t(`host.${row.id}`) })}
                disabled={!row.canLift}
                aria-describedby={!row.canLift ? `${host.id}-${row.id}-lift-help` : undefined}
                onClick={() => {
                  lower.reset();
                  setTarget({ setting: row.id, action: "lift" });
                }}
              >
                {t("host.allowAgain")}
              </Button>
            </>
          ) : (
            <Button
              size="touch"
              variant="outline"
              className="sm:self-start"
              aria-label={t("host.turnOffNamed", { setting: t(`host.${row.id}`) })}
              onClick={() => {
                lower.reset();
                setTarget({ setting: row.id, action: "lower" });
              }}
            >
              {t("host.turnOff")}
            </Button>
          )}
          <p className="text-sm text-muted-foreground">{t("host.enableAtNode")}</p>
          <code className="font-mono text-sm [overflow-wrap:anywhere]">{row.command}</code>
        </div>
      ))}
      <p>
        {t("host.files", {
          state: t(
            host.agentPolicy == null
              ? "host.unknown"
              : host.agentPolicy.hostFiles
                ? "host.on"
                : "host.off",
          ),
        })}
      </p>
      <code className="font-mono text-sm [overflow-wrap:anywhere]">{t("host.rootsCommand")}</code>
      <code className="font-mono text-sm [overflow-wrap:anywhere]">
        wssp host config set-host-command-max-time 600
      </code>
      {host.agentPolicy?.hostCommandMaxMs !== undefined ? (
        <p>{t("host.maxTime", { seconds: host.agentPolicy.hostCommandMaxMs / 1000 })}</p>
      ) : null}
      <AlertDialog
        open={target !== null}
        onOpenChange={(open) => {
          if (!open && !lower.isPending) setTarget(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t(target?.action === "lift" ? "host.liftTitle" : "host.confirmTitle")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t(target?.action === "lift" ? "host.liftDescription" : "host.confirmDescription")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          {lower.isError ? <p role="alert">{t("host.failed")}</p> : null}
          <AlertDialogFooter>
            <AlertDialogCancel className="min-h-11" disabled={lower.isPending}>
              {t("host.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="min-h-11"
              disabled={lower.isPending || liftUnavailable}
              onClick={(event) => {
                event.preventDefault();
                if (target && !liftUnavailable) lower.mutate(target);
              }}
            >
              {t(target?.action === "lift" ? "host.allowAgain" : "host.turnOff")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}

// Commands must be readable in full: wrap instead of scrolling under the copy button.
const WRAPPED_SNIPPET = "min-h-13 whitespace-pre-wrap [overflow-wrap:anywhere]";
export function canPretypeQueuedCommand(command: string, terminalAvailable: boolean): boolean {
  return terminalAvailable && command.length <= PASTE_MAX_BYTES && /^[\x20-\x7e]+$/.test(command);
}
export function QueuedHostCommands({
  hostId,
  lang,
  policy,
}: {
  hostId: string;
  lang: string;
  policy: Host["terminalPolicy"];
}) {
  const { t } = useTranslation("agents");
  const client = useQueryClient();
  const redirect = useTwoFactorRedirect(lang);
  const [handoff, setHandoff] = useState<{
    typedCommand: string;
    hostTerminalAvailable: boolean;
  } | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const queued = useInfiniteQuery({
    ...orpc.hostQueuedCommands.list.infiniteOptions({
      input: (cursor: string | undefined) => ({ hostId, limit: 20, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (page) => page.nextCursor ?? undefined,
    }),
    refetchInterval: 5000,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [queued.error]);
  const invalidate = () => {
    void client.invalidateQueries({ queryKey: orpc.hostQueuedCommands.list.key() });
  };
  const run = useMutation({
    ...orpc.hostQueuedCommands.run.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: (result) => {
      setHandoff(result);
      setCopied(false);
      setCopyFailed(false);
      invalidate();
    },
    onError: (error) => {
      redirect(error);
      invalidate();
    },
  });
  const dismiss = useMutation({
    ...orpc.hostQueuedCommands.dismiss.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onSuccess: invalidate,
    onError: (error) => {
      redirect(error);
      invalidate();
    },
  });
  const pretype =
    handoff &&
    canPretypeQueuedCommand(
      handoff.typedCommand,
      handoff.hostTerminalAvailable && policy?.hostTerminal === true,
    );
  return (
    <section className="flex min-w-0 flex-col gap-3">
      <h2 className="font-semibold">{t("queue.title")}</h2>
      <p>{t("queue.hint")}</p>
      <QueryBoundary
        query={{ ...queued, data: queued.data?.pages.flatMap((page) => page.items) }}
        skeleton={<SkeletonList count={2} />}
      >
        {(items) => (
          <>
            <ul className="flex min-w-0 flex-col gap-3">
              {items.map((row) => (
                <li key={row.id} className="flex min-w-0 flex-col gap-2 rounded-xl border p-4">
                  <CodeSnippet
                    code={row.command}
                    copyLabel={t("queue.copyCommand")}
                    preClassName={WRAPPED_SNIPPET}
                  />
                  <p className="break-words">{row.reason}</p>
                  <p className="break-words">
                    {t("queue.credential", {
                      name: row.credentialName ?? t("queue.deletedCredential"),
                    })}
                  </p>
                  <p>{t("queue.expires", { date: formatDateTime(row.expiresAt, lang) })}</p>
                  <p>{t(`queue.states.${row.state}`)}</p>
                  {row.state === "QUEUED" ? (
                    <div className="flex flex-wrap gap-2">
                      <Button
                        size="touch"
                        disabled={
                          run.isPending ||
                          dismiss.isPending ||
                          new Date(row.expiresAt).getTime() <= Date.now()
                        }
                        onClick={() => run.mutate({ id: row.id })}
                      >
                        {t("queue.run")}
                      </Button>
                      <Button
                        size="touch"
                        variant="outline"
                        disabled={run.isPending || dismiss.isPending}
                        onClick={() => dismiss.mutate({ id: row.id })}
                      >
                        {t("queue.dismiss")}
                      </Button>
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
            {items.length === 0 ? <p>{t("queue.empty")}</p> : null}
            <LoadMore
              hasNextPage={queued.hasNextPage}
              isFetchingNextPage={queued.isFetchingNextPage}
              onLoadMore={() => void queued.fetchNextPage()}
            />
          </>
        )}
      </QueryBoundary>
      {run.isError || dismiss.isError ? <p role="alert">{t("queue.failed")}</p> : null}
      <Dialog
        open={handoff !== null}
        onOpenChange={(open) => {
          if (!open) setHandoff(null);
        }}
      >
        <DialogContent
          closeLabel={t("queue.close")}
          className="max-h-[calc(100dvh-var(--safe-area-top)-var(--safe-area-bottom)-2rem)] overflow-x-hidden overflow-y-auto sm:max-w-3xl"
        >
          <DialogHeader>
            <DialogTitle>{t("queue.review")}</DialogTitle>
            <DialogDescription>
              {t(pretype ? "queue.reviewHint" : "queue.copyHint")}
            </DialogDescription>
          </DialogHeader>
          {handoff ? (
            <>
              <CodeSnippet
                code={handoff.typedCommand}
                copyLabel={t("queue.copy")}
                preClassName={WRAPPED_SNIPPET}
                onCopied={() => {
                  setCopied(true);
                  setCopyFailed(false);
                }}
                onCopyError={() => setCopyFailed(true)}
              />
              {pretype ? (
                <HostTerminal
                  hostId={hostId}
                  lang={lang}
                  policy={policy}
                  typeCommand={handoff.typedCommand}
                  pretypeOnAttach
                  maximizable={false}
                />
              ) : (
                <>
                  {copied ? <p role="status">{t("queue.copied")}</p> : null}
                  {copyFailed ? <p role="alert">{t("queue.copyFailed")}</p> : null}
                </>
              )}
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </section>
  );
}
