import { skipToken, useMutation, useQuery } from "@tanstack/react-query";
import {
  classifyKillOutcome,
  FS_PROCESS_LIMITS,
  type ProcessInfo,
  type ProcessRef,
} from "@wssp/api/sandbox/contracts";
import { Button } from "@wssp/ui/components/button";
import { ResponsiveDialog } from "@wssp/ui/components/responsive-dialog";
import { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { ConfirmDeleteDialog } from "@/components/confirm-delete-dialog";
import { CommandOutputView } from "@/components/operations/command-output-view";
import { observationProblem, useSandboxObservation } from "@/hooks/use-sandbox-observation";
import { useSensitiveAccessUnavailable } from "@/hooks/use-sensitive-access-unavailable";
import { displayText } from "@/lib/command-output-buffer";
import { formatTimestamp } from "@/lib/operation-rules";
import { isOperationActive } from "@/lib/sandbox-rules";
import { orpc } from "@/utils/orpc";
import { ObservationError, ObservationNotice } from "./sandbox-observation";

export function SandboxProcesses({
  sandboxId,
  available,
}: {
  sandboxId: string;
  available: boolean;
}) {
  const { t } = useTranslation(["sandboxes"]);
  const unavailable = useSensitiveAccessUnavailable();
  return (
    <section
      aria-labelledby="sandbox-processes-title"
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id="sandbox-processes-title" className="font-heading text-sm font-semibold">
        {t("sandboxes:observations.processesTitle")}
      </h2>
      {unavailable ? (
        <p role="status" data-sensitive-unavailable="" className="text-sm text-muted-foreground">
          {t("sandboxes:sensitiveAccessUnavailable")}
        </p>
      ) : !available ? (
        <ObservationNotice state="unavailable" />
      ) : (
        <AuthorizedProcesses key={sandboxId} sandboxId={sandboxId} />
      )}
    </section>
  );
}

function AuthorizedProcesses({ sandboxId }: { sandboxId: string }) {
  const { t, i18n } = useTranslation(["sandboxes", "common"]);
  const outputTrigger = useRef<HTMLButtonElement | null>(null);
  const [operationId, setOperationId] = useState<string | null>(null);
  const [view, setView] = useState<ProcessRef | null>(null);
  const [kill, setKill] = useState<ProcessInfo | null>(null);
  const [controlTarget, setControlTarget] = useState<{
    operationId: string;
    state: string;
    kind: "kill" | "signal";
  } | null>(null);
  const capabilities = useQuery({
    ...orpc.sandboxes.getSandboxCapabilities.queryOptions({ input: { id: sandboxId } }),
    staleTime: 0,
    retry: false,
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  const result = useSandboxObservation(operationId);
  const list = useMutation({
    ...orpc.sandboxes.listProcesses.mutationOptions(),
    retry: false,
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      setOperationId(null);
      setView(null);
      setKill(null);
    },
    onSuccess: (receipt) => setOperationId(receipt.operationId),
  });
  const terminate = useMutation({
    ...orpc.sandboxes.killProcess.mutationOptions(),
    retry: false,
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      signal.reset();
      setControlTarget(null);
      return kill?.operationId;
    },
    onSuccess: (receipt, _input, targetOperationId) => {
      // killProcess returns an action receipt. Browser getOperation reads only
      // operations: follow the listed command, never the action receipt ID.
      if (targetOperationId)
        setControlTarget({ operationId: targetOperationId, state: receipt.state, kind: "kill" });
      setKill(null);
    },
  });
  const signal = useMutation({
    ...orpc.sandboxes.signalProcess.mutationOptions(),
    retry: false,
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      terminate.reset();
      setControlTarget(null);
    },
    onSuccess: (receipt) =>
      setControlTarget({ operationId: receipt.operationId, state: receipt.state, kind: "signal" }),
  });
  const control = useQuery({
    ...orpc.sandboxes.getOperation.queryOptions({
      input: controlTarget ? { operationId: controlTarget.operationId } : skipToken,
    }),
    retry: false,
    gcTime: 0,
    refetchOnWindowFocus: false,
    refetchInterval: (query) =>
      query.state.status === "error"
        ? false
        : !query.state.data || isOperationActive(query.state.data.state)
          ? 2_000
          : false,
    meta: { skipGlobalErrorToast: true },
  });
  const controlState =
    controlTarget?.kind === "kill" && control.data && isOperationActive(control.data.state)
      ? "CANCEL_REQUESTED"
      : (control.data?.state ?? controlTarget?.state);
  const killOutcome =
    controlTarget?.kind === "kill" && control.data && !isOperationActive(control.data.state)
      ? classifyKillOutcome(control.data)
      : null;
  const page =
    !result.isError &&
    result.data?.outcome === "succeeded" &&
    result.data.result?.type === "process.list"
      ? result.data.result
      : null;
  const busy =
    list.isPending ||
    (operationId !== null &&
      (!result.data || result.data.outcome === "pending") &&
      !result.isError);
  const available =
    !capabilities.isError &&
    capabilities.data?.unavailableReason === null &&
    capabilities.data.features.includes("processes.list");
  const submit = (cursor?: string) =>
    list.mutate({
      id: sandboxId,
      limit: FS_PROCESS_LIMITS.listMaxLimit,
      cursor,
      idempotencyKey: crypto.randomUUID(),
    });
  if (
    [
      capabilities.error,
      list.error,
      result.error,
      terminate.error,
      signal.error,
      control.error,
    ].some((error) => error && observationProblem(error) === "unavailable")
  )
    return <ObservationNotice state="unavailable" />;
  return (
    <>
      <p className="text-sm text-muted-foreground">{t("sandboxes:observations.trackedOnly")}</p>
      <p className="text-sm text-muted-foreground">
        {t("sandboxes:observations.livePage", { limit: FS_PROCESS_LIMITS.listMaxLimit })}
      </p>
      {(!available || capabilities.isError) && !capabilities.isPending ? (
        <Button
          type="button"
          size="touch"
          className="self-start"
          variant="outline"
          disabled={capabilities.isFetching}
          onClick={() => void capabilities.refetch()}
        >
          {t("sandboxes:observations.refreshCapabilities")}
        </Button>
      ) : null}
      {capabilities.isError ? (
        <ObservationError error={capabilities.error} />
      ) : !capabilities.data ? (
        <ObservationNotice state="pending" />
      ) : !available ? (
        <ObservationNotice state="unavailable" />
      ) : (
        <>
          <Button
            type="button"
            size="touch"
            className="self-start"
            variant="outline"
            disabled={busy}
            onClick={() => submit()}
          >
            {t("sandboxes:observations.refreshProcesses")}
          </Button>
          {terminate.isError ? (
            <ObservationError error={terminate.error} />
          ) : signal.isError ? (
            <ObservationError error={signal.error} />
          ) : control.isError ? (
            controlTarget?.kind === "kill" ? (
              <ObservationNotice state="unknown" />
            ) : (
              <ObservationError error={control.error} />
            )
          ) : controlTarget ? (
            <>
              <p
                className="text-sm text-muted-foreground"
                role="status"
                data-process-control-state={controlState ?? "QUEUED"}
              >
                {t("sandboxes:observations.controlState", {
                  state: t(`sandboxes:receipt.state.${controlState ?? "QUEUED"}`),
                })}
              </p>
              {killOutcome && killOutcome !== "unknown" ? (
                <p
                  className="text-sm text-muted-foreground"
                  role="status"
                  data-kill-outcome={killOutcome}
                >
                  {t(`sandboxes:observations.${killOutcome}`)}
                </p>
              ) : null}
              {killOutcome === "unknown" || control.data?.state === "UNKNOWN_OUTCOME" ? (
                <ObservationNotice state="unknown" />
              ) : null}
              {controlTarget.kind === "signal" &&
              control.data?.errorCode &&
              control.data.state !== "UNKNOWN_OUTCOME" ? (
                <ObservationError error={{ code: control.data.errorCode }} />
              ) : null}
            </>
          ) : null}
          {list.isError ? (
            <ObservationError error={list.error} />
          ) : result.isError ? (
            <ObservationError error={result.error} />
          ) : busy ? (
            <ObservationNotice state="pending" list />
          ) : result.data && !page ? (
            <ObservationNotice state={result.data.outcome === "unknown" ? "unknown" : "failed"} />
          ) : null}
          {page ? (
            <>
              {page.items.length === 0 ? (
                <ObservationNotice state="emptyProcesses" />
              ) : (
                <ul className="flex min-w-0 flex-col gap-3">
                  {page.items.map((item) => (
                    <li
                      key={item.process.processId}
                      className="flex min-w-0 flex-col gap-3 rounded-lg border p-3"
                    >
                      <p className="whitespace-pre-wrap break-words [overflow-wrap:anywhere] font-mono text-sm">
                        {[item.cmd, ...item.args]
                          .map((argument) => JSON.stringify(displayText(argument)))
                          .join(" ")}
                      </p>
                      <dl className="grid min-w-0 gap-3 text-sm sm:grid-cols-3">
                        <div className="min-w-0">
                          <dt className="text-xs text-muted-foreground">
                            {t("sandboxes:observations.pidLabel")}
                          </dt>
                          <dd className="font-mono tabular-nums">{item.process.pid}</dd>
                        </div>
                        <div className="min-w-0">
                          <dt className="text-xs text-muted-foreground">
                            {t("sandboxes:observations.identityLabel")}
                          </dt>
                          <dd className="break-words font-mono [overflow-wrap:anywhere]">
                            {t("sandboxes:observations.identity", {
                              processId: item.process.processId,
                              generation: item.process.generation,
                              attempt: item.process.attempt,
                            })}
                          </dd>
                        </div>
                        <div className="min-w-0">
                          <dt className="text-xs text-muted-foreground">
                            {t("sandboxes:observations.startedAtLabel")}
                          </dt>
                          <dd>{formatTimestamp(item.startedAt, i18n.language)}</dd>
                        </div>
                      </dl>
                      {item.argsTruncated ? (
                        <p className="text-sm text-muted-foreground">
                          {t("sandboxes:observations.argsTruncated")}
                        </p>
                      ) : null}
                      <div className="flex flex-wrap gap-2">
                        <Button
                          type="button"
                          size="touch"
                          variant="outline"
                          onClick={(event) => {
                            outputTrigger.current = event.currentTarget;
                            setView(item.process);
                          }}
                        >
                          {t("sandboxes:observations.output")}
                        </Button>
                        {capabilities.data?.guestApi.supportedSignals.map((name) =>
                          name === "SIGKILL" ? (
                            <Button
                              key={name}
                              type="button"
                              size="touch"
                              variant="destructive"
                              disabled={terminate.isPending || signal.isPending}
                              onClick={() => {
                                terminate.reset();
                                setKill(item);
                              }}
                            >
                              {t("sandboxes:observations.kill")}
                            </Button>
                          ) : (
                            <Button
                              key={name}
                              type="button"
                              size="touch"
                              variant="outline"
                              disabled={terminate.isPending || signal.isPending}
                              onClick={() =>
                                signal.mutate({
                                  process: item.process,
                                  signal: name,
                                  idempotencyKey: crypto.randomUUID(),
                                })
                              }
                            >
                              {t(`sandboxes:signals.${name}`)}
                            </Button>
                          ),
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
              {page.nextCursor ? (
                <Button
                  type="button"
                  size="touch"
                  className="self-start"
                  variant="outline"
                  disabled={busy}
                  onClick={() => submit(page.nextCursor ?? undefined)}
                >
                  {t("sandboxes:observations.nextPage")}
                </Button>
              ) : null}
            </>
          ) : null}
          <ConfirmDeleteDialog
            key={kill?.process.processId ?? "closed"}
            open={kill !== null}
            onOpenChange={(open) => {
              if (!open) setKill(null);
            }}
            title={t("sandboxes:observations.killTitle")}
            description={t("sandboxes:observations.killDescription")}
            confirmToken={kill?.process.processId ?? ""}
            typePrompt={t("sandboxes:observations.killPrompt")}
            copyAriaLabel={t("sandboxes:observations.copyProcessId")}
            confirmLabel={t("sandboxes:observations.killConfirm")}
            pendingLabel={t("sandboxes:observations.killPending")}
            isPending={terminate.isPending}
            onConfirm={() => {
              if (kill)
                terminate.mutate({ process: kill.process, idempotencyKey: crypto.randomUUID() });
            }}
          />
          <ResponsiveDialog
            finalFocus={outputTrigger}
            closeLabel={t("common:actions.close")}
            title={t("sandboxes:observations.output")}
            description={t("sandboxes:observations.connectDescription")}
            className="md:max-w-3xl"
            footer={
              <Button type="button" size="touch" variant="outline" onClick={() => setView(null)}>
                {t("common:actions.close")}
              </Button>
            }
            open={view !== null && page !== null}
            onOpenChange={(open) => {
              if (!open) setView(null);
            }}
          >
            {view && page ? <ProcessOutput key={view.processId} process={view} /> : null}
          </ResponsiveDialog>
        </>
      )}
    </>
  );
}

function ProcessOutput({ process }: { process: ProcessRef }) {
  const { i18n, t } = useTranslation(["sandboxes"]);
  const connection = useQuery({
    ...orpc.sandboxes.connectProcess.queryOptions({ input: { process } }),
    retry: false,
    gcTime: 0,
    refetchInterval: (query) =>
      query.state.status === "error"
        ? false
        : !query.state.data || isOperationActive(query.state.data.state)
          ? 2_000
          : false,
    meta: { skipGlobalErrorToast: true },
  });
  if (connection.isError) return <ObservationError error={connection.error} />;
  if (!connection.data) return <ObservationNotice state="pending" />;
  if (connection.data.state === "UNKNOWN_OUTCOME") return <ObservationNotice state="unknown" />;
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <p className="text-sm text-muted-foreground" role="status">
        {t(`sandboxes:receipt.state.${connection.data.state}`)}
      </p>
      {connection.data.exitCode !== null ? (
        <p className="text-sm text-muted-foreground">
          {t("sandboxes:observations.exitCode", { code: connection.data.exitCode })}
        </p>
      ) : null}
      <CommandOutputView
        operationId={connection.data.outputOperationId}
        settled={!isOperationActive(connection.data.state)}
        locale={i18n.language}
      />
    </div>
  );
}
