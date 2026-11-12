import { Button } from "@wssp/ui/components/button";
import { cn } from "@wssp/ui/lib/utils";
import { ClipboardPaste, Copy, Keyboard, Plug, Unplug } from "lucide-react";
import { type ReactNode, useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { type ClipboardOutcome, useTerminalSession } from "@/hooks/use-terminal-session";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";

export function TerminalPanel({
  sandboxId,
  hostId,
  lang,
  available,
  unavailableMessage,
  beforeAttach,
  attachCode,
  onAttempt,
  typeCommand,
}: {
  sandboxId?: string;
  hostId?: string;
  lang: string;
  available: boolean;
  unavailableMessage?: string;
  beforeAttach?: ReactNode;
  attachCode?: () => string | undefined;
  onAttempt?: () => void;
  /** Known text the "Type it for me" button types into the attached terminal. */
  typeCommand?: string;
}) {
  const { t } = useTranslation(["terminal"]);
  const redirect = useTwoFactorRedirect(lang);
  const headingId = useId();
  const [proofProblem, setProofProblem] = useState<string | null>(null);
  // A copy/paste result belongs to the status it was reported under (E-22):
  // once the terminal leaves that status (taken over, ended) it is no longer
  // shown, so a "Pasted" line never sits beside the reason the session ended.
  const [clipboard, setClipboard] = useState<{ text: string; status: string } | null>(null);
  const terminal = useTerminalSession({
    sandboxId,
    hostId,
    onCreateError: (error) => {
      if (redirect(error)) return;
      const data = error && typeof error === "object" && "data" in error ? error.data : null;
      const reason = data && typeof data === "object" && "reason" in data ? data.reason : null;
      if (hostId)
        setProofProblem(
          reason === "enrollment" || reason === "cooldown" || reason === "locked"
            ? reason
            : "refused",
        );
    },
    onPaste: (outcome) =>
      report(outcome, t("terminal:clipboard.pasted"), t("terminal:clipboard.pasteEmpty")),
  });
  const { status, notice, warning, size } = terminal.snapshot;
  const report = (outcome: ClipboardOutcome, done: string, empty: string) => {
    const text =
      outcome === "done"
        ? done
        : outcome === "empty"
          ? empty
          : outcome === "tooLarge"
            ? t("terminal:clipboard.pasteTooLarge")
            : // The session ended during the paste: the notice says why.
              outcome === "ended"
              ? null
              : t("terminal:clipboard.unavailable");
    setClipboard(text === null ? null : { text, status });
  };
  const active = status !== "idle" && status !== "ended";
  const attached = status === "attached";
  const shown = status !== "idle";
  // The owner's own disconnect and leaving the page are not failures.
  const quiet = notice?.kind === "client" || notice?.kind === "pageLeft";
  const clipboardText = clipboard?.status === status ? clipboard.text : null;

  return (
    <section
      aria-labelledby={headingId}
      data-terminal-status={status}
      className="flex min-w-0 flex-col gap-3 rounded-xl border bg-card p-4 text-card-foreground"
    >
      <h2 id={headingId} className="text-sm font-medium">
        {t(hostId ? "terminal:host.title" : "terminal:title")}
      </h2>
      <p className="text-sm text-muted-foreground">
        {t(hostId ? "terminal:host.warning" : "terminal:description")}
      </p>
      {!active ? beforeAttach : null}
      {proofProblem ? <p role="alert">{t(`terminal:host.${proofProblem}`)}</p> : null}
      <div
        role="group"
        aria-label={t("terminal:actionsLabel")}
        className="flex min-w-0 flex-wrap gap-2"
      >
        {/* One element for attach and disconnect, so keyboard focus stays on it. */}
        <Button
          type="button"
          size="touch"
          variant={active ? "outline" : "default"}
          data-terminal-toggle={active ? "detach" : "attach"}
          disabled={!active && !available}
          onClick={() => {
            setClipboard(null);
            if (active) terminal.detach();
            else {
              setProofProblem(null);
              const code = attachCode?.();
              onAttempt?.();
              terminal.attach(code);
            }
          }}
        >
          {active ? (
            <Unplug aria-hidden="true" className="size-4" />
          ) : (
            <Plug aria-hidden="true" className="size-4" />
          )}
          {active
            ? t("terminal:actions.detach")
            : status === "ended"
              ? t("terminal:actions.reattach")
              : t("terminal:actions.attach")}
        </Button>
        <Button
          type="button"
          size="touch"
          variant="outline"
          data-terminal-copy=""
          disabled={!shown}
          onClick={() =>
            void terminal
              .copySelection()
              .then((outcome) =>
                report(outcome, t("terminal:clipboard.copied"), t("terminal:clipboard.copyEmpty")),
              )
          }
        >
          <Copy aria-hidden="true" className="size-4" />
          {t("terminal:actions.copy")}
        </Button>
        <Button
          type="button"
          size="touch"
          variant="outline"
          data-terminal-paste=""
          disabled={!attached}
          onClick={() =>
            void terminal
              .paste()
              .then((outcome) =>
                report(outcome, t("terminal:clipboard.pasted"), t("terminal:clipboard.pasteEmpty")),
              )
          }
        >
          <ClipboardPaste aria-hidden="true" className="size-4" />
          {t("terminal:actions.paste")}
        </Button>
        {typeCommand ? (
          <Button
            type="button"
            size="touch"
            variant="outline"
            data-terminal-type=""
            disabled={!attached}
            onClick={() =>
              report(
                terminal.typeText(typeCommand),
                t("terminal:clipboard.typed"),
                t("terminal:clipboard.pasteEmpty"),
              )
            }
          >
            <Keyboard aria-hidden="true" className="size-4" />
            {t("terminal:actions.type")}
          </Button>
        ) : null}
      </div>
      {!available && !active ? (
        <p className="text-sm text-muted-foreground">
          {unavailableMessage ?? t(hostId ? "terminal:host.unavailable" : "terminal:unavailable")}
        </p>
      ) : null}
      <p role="status" aria-live="polite" data-terminal-state="" className="text-sm">
        {attached && size
          ? t("terminal:status.attached", { rows: size.rows, cols: size.cols })
          : t(`terminal:status.${status}`)}
        {clipboardText ? <span className="ms-2 text-muted-foreground">{clipboardText}</span> : null}
      </p>
      {status === "ended" && notice ? (
        <p
          role={quiet ? undefined : "alert"}
          data-terminal-notice={notice.kind}
          className={cn("text-sm", quiet ? "text-muted-foreground" : "text-destructive")}
        >
          {t(`terminal:notice.${notice.kind}`, {
            exitCode: notice.exitCode,
            code: notice.code ?? "",
          })}
        </p>
      ) : null}
      {warning ? (
        <p data-terminal-warning={warning} className="text-sm text-amber-800 dark:text-amber-300">
          {t(`terminal:warning.${warning}`)}
        </p>
      ) : null}
      <div
        ref={terminal.containerRef}
        role="region"
        aria-label={t(hostId ? "terminal:host.regionLabel" : "terminal:regionLabel")}
        data-terminal-view=""
        hidden={!shown}
        className="h-[min(28rem,50svh)] min-h-40 w-full min-w-0 overflow-hidden overscroll-contain rounded-md border bg-black p-1"
      />
    </section>
  );
}
