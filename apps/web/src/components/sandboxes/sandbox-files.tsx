import { skipToken, useMutation, useQuery } from "@tanstack/react-query";
import { env } from "@wssp/env/web";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import { useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { InlineRetry } from "@/components/inline-retry";
import { useAbortOnUnmount } from "@/hooks/use-abort-on-unmount";
import { useSensitiveAccessUnavailable } from "@/hooks/use-sensitive-access-unavailable";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import {
  formatBytes,
  IntentKeys,
  isGuestPath,
  isOperationActive,
  type OperationState,
  sandboxProblem,
  TRANSFER_MAX_BYTES,
} from "@/lib/sandbox-rules";
import {
  downloadUrl,
  probeDownload,
  TransferError,
  type TransferProblem,
  uploadToSandbox,
} from "@/lib/sandbox-transfers";
import { orpc } from "@/utils/orpc";
import { SandboxFileList } from "./sandbox-file-list";

/**
 * Upload and download controls for one READY sandbox (C47). Both go through
 * the cookie-session binary plane (`lib/sandbox-transfers.ts`), bounded by
 * the transfer cap; no SDK key is involved. An accepted upload or a capture
 * is an operation receipt: the panel shows its server state until it
 * settles, and only a SUCCEEDED capture that the server still serves is
 * offered for saving.
 */

export const OPERATION_POLL_MS = 2_000;

/** A receipt read refused for good: polling again cannot change the answer. */
const TERMINAL_RECEIPT_PROBLEMS: ReadonlySet<TransferProblem> = new Set([
  "notFound",
  "forbidden",
  "signedOut",
]);

function operationRefetch(query: {
  state: { data?: { state: OperationState }; status: string; error: unknown };
}) {
  if (
    query.state.status === "error" &&
    TERMINAL_RECEIPT_PROBLEMS.has(toTransferProblem(query.state.error))
  )
    return false;
  const state = query.state.data?.state;
  return state == null || isOperationActive(state) ? OPERATION_POLL_MS : false;
}

function toTransferProblem(error: unknown): TransferProblem {
  if (error instanceof TransferError) return error.problem;
  const shape = (error && typeof error === "object" ? error : {}) as {
    code?: unknown;
    status?: unknown;
  };
  if (shape.code === "UNAUTHORIZED" || shape.status === 401) return "signedOut";
  const problem = sandboxProblem(error);
  if (problem === "notFound") return "notFound";
  if (problem === "stateChanged") return "conflict";
  if (problem === "forbidden") return "forbidden";
  if (problem === "invalid") return "invalid";
  return "generic";
}

export function SandboxFiles({ sandboxId, lang }: { sandboxId: string; lang: string }) {
  const { t, i18n } = useTranslation(["sandboxes"]);
  const unavailable = useSensitiveAccessUnavailable();
  return (
    <section
      aria-labelledby="sandbox-files-title"
      className="flex min-w-0 flex-col gap-4 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <div className="min-w-0">
        <h2 id="sandbox-files-title" className="font-heading text-sm font-semibold">
          {t("sandboxes:files.title")}
        </h2>
        <p className="text-sm text-muted-foreground">
          {t("sandboxes:files.description", {
            max: formatBytes(TRANSFER_MAX_BYTES, i18n.language),
          })}
        </p>
      </div>
      {unavailable ? (
        <p role="status" data-sensitive-unavailable="" className="text-sm text-muted-foreground">
          {t("sandboxes:sensitiveAccessUnavailable")}
        </p>
      ) : (
        <>
          <SandboxFileList key={sandboxId} sandboxId={sandboxId} />
          <div className="grid min-w-0 gap-4 lg:grid-cols-2">
            <UploadForm sandboxId={sandboxId} lang={lang} />
            <DownloadForm sandboxId={sandboxId} lang={lang} />
          </div>
        </>
      )}
    </section>
  );
}

type UploadPhase =
  | { kind: "idle" }
  | { kind: "uploading"; sent: number; total: number }
  | { kind: "accepted"; operationId: string }
  | { kind: "failed"; problem: TransferProblem };

/** A receipt the page could not read: say so (never a silent pending state) and offer a re-check. */
function ReceiptProblem({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const { t } = useTranslation(["sandboxes"]);
  const problem = toTransferProblem(error);
  return (
    <div role="alert" data-receipt-problem={problem}>
      <InlineRetry
        variant="destructive"
        message={`${t("sandboxes:files.receiptFailed")} ${t(`sandboxes:files.problem.${problem}`)}`}
        onRetry={onRetry}
      />
    </div>
  );
}

function UploadForm({ sandboxId, lang }: { sandboxId: string; lang: string }) {
  const { t, i18n } = useTranslation(["sandboxes"]);
  const pathId = useId();
  const fileId = useId();
  const nextController = useAbortOnUnmount();
  const controller = useRef<AbortController | null>(null);
  const [path, setPath] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [attempted, setAttempted] = useState(false);
  const [phase, setPhase] = useState<UploadPhase>({ kind: "idle" });
  const operation = useQuery({
    ...orpc.sandboxes.getOperation.queryOptions({
      input: phase.kind === "accepted" ? { operationId: phase.operationId } : skipToken,
    }),
    refetchInterval: operationRefetch,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [operation.error]);
  const pathOk = isGuestPath(path);
  const tooLarge = file != null && file.size > TRANSFER_MAX_BYTES;
  const uploading = phase.kind === "uploading";
  const max = formatBytes(TRANSFER_MAX_BYTES, i18n.language);

  const start = async () => {
    setAttempted(true);
    if (uploading || !pathOk || !file || tooLarge) return;
    const signal = nextController();
    controller.current = signal;
    setPhase({ kind: "uploading", sent: 0, total: file.size });
    try {
      const receipt = await uploadToSandbox(
        { serverUrl: env.VITE_SERVER_URL },
        {
          sandboxId,
          guestPath: path,
          file,
          signal: signal.signal,
          onProgress: (sent, total) => setPhase({ kind: "uploading", sent, total }),
        },
      );
      setPhase({ kind: "accepted", operationId: receipt.operationId });
    } catch (error) {
      setPhase({ kind: "failed", problem: toTransferProblem(error) });
    } finally {
      controller.current = null;
    }
  };

  return (
    <form
      noValidate
      aria-labelledby={`${fileId}-title`}
      className="flex min-w-0 flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        void start();
      }}
    >
      <h3 id={`${fileId}-title`} className="text-sm font-medium">
        {t("sandboxes:files.upload.title")}
      </h3>
      <div className="flex min-w-0 flex-col gap-2">
        <Label htmlFor={fileId}>{t("sandboxes:files.upload.file")}</Label>
        <input
          id={fileId}
          type="file"
          disabled={uploading}
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          className="min-h-11 w-full min-w-0 text-sm file:mr-3 file:min-h-11 file:rounded-md file:border file:bg-background file:px-3"
        />
      </div>
      <div className="flex min-w-0 flex-col gap-2">
        <Label htmlFor={pathId}>{t("sandboxes:files.guestPath")}</Label>
        <Input
          id={pathId}
          value={path}
          disabled={uploading}
          autoComplete="off"
          inputMode="url"
          maxLength={4096}
          placeholder={t("sandboxes:files.pathPlaceholder")}
          className="min-h-11 font-mono"
          onChange={(event) => setPath(event.target.value)}
        />
        <p className="text-xs text-muted-foreground">{t("sandboxes:files.guestPathHint")}</p>
      </div>
      {attempted && (!pathOk || !file || tooLarge) ? (
        <ul role="alert" className="list-disc pl-5 text-sm text-destructive">
          {!file ? <li>{t("sandboxes:files.upload.noFile")}</li> : null}
          {tooLarge ? <li>{t("sandboxes:files.upload.tooLarge", { max })}</li> : null}
          {!pathOk ? <li>{t("sandboxes:files.badPath")}</li> : null}
        </ul>
      ) : null}
      {phase.kind === "uploading" ? (
        <div className="flex min-w-0 flex-col gap-2">
          <progress
            max={phase.total || 1}
            value={phase.total ? phase.sent : 0}
            className="h-2 w-full"
            aria-label={t("sandboxes:files.upload.title")}
          />
          <p role="status" data-upload="pending" className="text-sm text-muted-foreground">
            {t("sandboxes:files.upload.pending", {
              sent: formatBytes(phase.sent, i18n.language),
              total: formatBytes(phase.total, i18n.language),
            })}
          </p>
        </div>
      ) : null}
      {phase.kind === "accepted" && operation.isError ? (
        <ReceiptProblem error={operation.error} onRetry={() => void operation.refetch()} />
      ) : phase.kind === "accepted" ? (
        <p role="status" data-upload="accepted" className="text-sm">
          {t("sandboxes:files.upload.accepted", {
            state: t(`sandboxes:receipt.state.${operation.data?.state ?? "QUEUED"}`),
          })}
        </p>
      ) : null}
      {phase.kind === "failed" ? (
        <p role="alert" data-upload-problem={phase.problem} className="text-sm text-destructive">
          {t(`sandboxes:files.problem.${phase.problem}`)}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="touch" disabled={uploading}>
          {t("sandboxes:files.upload.submit")}
        </Button>
        {uploading ? (
          <Button
            type="button"
            variant="outline"
            size="touch"
            onClick={() => controller.current?.abort()}
          >
            {t("sandboxes:files.upload.cancel")}
          </Button>
        ) : null}
      </div>
    </form>
  );
}

function DownloadForm({ sandboxId, lang }: { sandboxId: string; lang: string }) {
  const { t, i18n } = useTranslation(["sandboxes"]);
  const redirect = useTwoFactorRedirect(lang);
  const pathId = useId();
  const intents = useRef(new IntentKeys());
  const [path, setPath] = useState("");
  const [attempted, setAttempted] = useState(false);
  const [operationId, setOperationId] = useState<string | null>(null);
  const [problem, setProblem] = useState<TransferProblem | null>(null);
  // The capture whose one save has started (TQ-UX1, E-29): its link is gone.
  const [saved, setSaved] = useState<string | null>(null);
  const capture = useMutation({
    ...orpc.sandboxes.readFile.mutationOptions(),
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      setProblem(null);
      setOperationId(null);
    },
    onSuccess: (receipt) => {
      intents.current.settle();
      setOperationId(receipt.operationId);
    },
    onError: (error) => {
      if (redirect(error)) return;
      const next = toTransferProblem(error);
      if (next !== "generic" && next !== "network") intents.current.settle();
      setProblem(next);
    },
  });
  const operation = useQuery({
    ...orpc.sandboxes.getOperation.queryOptions({
      input: operationId ? { operationId } : skipToken,
    }),
    refetchInterval: operationRefetch,
    meta: { skipGlobalErrorToast: true },
  });
  useTwoFactorRedirectOnError(lang, [operation.error]);
  const succeeded = operation.data?.state === "SUCCEEDED" ? operationId : null;
  const probe = useQuery({
    queryKey: ["sandboxDownloadProbe", succeeded],
    queryFn: succeeded
      ? ({ signal }) => probeDownload({ serverUrl: env.VITE_SERVER_URL }, succeeded, signal)
      : skipToken,
    retry: false,
    staleTime: 0,
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
  });
  const pathOk = isGuestPath(path);
  const state = operation.data?.state;
  const settledFailure =
    state != null && !isOperationActive(state) && state !== "SUCCEEDED" ? state : null;

  return (
    <form
      noValidate
      aria-labelledby={`${pathId}-title`}
      className="flex min-w-0 flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        setAttempted(true);
        if (!pathOk || capture.isPending) return;
        capture.mutate(
          intents.current.for("download", path, (idempotencyKey) => ({
            id: sandboxId,
            path,
            idempotencyKey,
          })),
        );
      }}
    >
      <h3 id={`${pathId}-title`} className="text-sm font-medium">
        {t("sandboxes:files.download.title")}
      </h3>
      <div className="flex min-w-0 flex-col gap-2">
        <Label htmlFor={pathId}>{t("sandboxes:files.guestPath")}</Label>
        <Input
          id={pathId}
          value={path}
          autoComplete="off"
          inputMode="url"
          maxLength={4096}
          placeholder={t("sandboxes:files.pathPlaceholder")}
          className="min-h-11 font-mono"
          onChange={(event) => setPath(event.target.value)}
        />
      </div>
      {attempted && !pathOk ? (
        <p role="alert" className="text-sm text-destructive">
          {t("sandboxes:files.badPath")}
        </p>
      ) : null}
      {operationId && operation.isError ? (
        <ReceiptProblem error={operation.error} onRetry={() => void operation.refetch()} />
      ) : null}
      {operationId && !operation.isError && state && isOperationActive(state) ? (
        <p role="status" data-download="pending" className="text-sm text-muted-foreground">
          {t("sandboxes:files.download.pending", {
            state: t(`sandboxes:receipt.state.${state}`),
          })}
        </p>
      ) : null}
      {settledFailure ? (
        <p role="alert" data-download="failed" className="text-sm text-destructive">
          {t("sandboxes:files.download.failed", {
            state: t(`sandboxes:receipt.state.${settledFailure}`),
          })}
        </p>
      ) : null}
      {succeeded && saved === succeeded ? (
        <p role="status" data-download="saved" className="text-sm text-muted-foreground">
          {t("sandboxes:files.download.saved")}
        </p>
      ) : null}
      {succeeded && probe.data && !probe.isError && saved !== succeeded ? (
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <p role="status" data-download="ready" className="text-sm">
            {t("sandboxes:files.download.ready", {
              size:
                probe.data.sizeBytes == null
                  ? "—"
                  : formatBytes(probe.data.sizeBytes, i18n.language),
            })}
          </p>
          <a
            href={downloadUrl({ serverUrl: env.VITE_SERVER_URL }, succeeded)}
            download
            rel="noreferrer"
            data-download-link=""
            className={buttonVariants({ variant: "outline", size: "touch" })}
            onClick={async (event) => {
              const link = event.currentTarget;
              // Second pass: the content was just checked; let the browser save it.
              if (link.dataset.checked) {
                delete link.dataset.checked;
                setSaved(succeeded);
                return;
              }
              // A capture is saved once. Check it is still there first, so a
              // gone capture shows its problem instead of a silent failed save.
              event.preventDefault();
              try {
                const result = await probe.refetch();
                if (result.isError || !link.isConnected) return;
                link.dataset.checked = "1";
                link.click();
              } catch {
                // Query state renders the failure; never start an unchecked save.
              }
            }}
          >
            {t("sandboxes:files.download.save")}
          </a>
        </div>
      ) : null}
      {problem || (succeeded && probe.isError) ? (
        <p
          role="alert"
          data-download-problem={problem ?? toTransferProblem(probe.error)}
          className="text-sm text-destructive"
        >
          {t(`sandboxes:files.problem.${problem ?? toTransferProblem(probe.error)}`)}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="touch" disabled={capture.isPending}>
          {t("sandboxes:files.download.submit")}
        </Button>
      </div>
    </form>
  );
}
