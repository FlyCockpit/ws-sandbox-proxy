import { Button } from "@wssp/ui/components/button";
import { cn } from "@wssp/ui/lib/utils";
import { ClipboardPaste, Copy, Keyboard, Plug, Unplug } from "lucide-react";
import { type ReactNode, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { TerminalKeyRow } from "@/components/terminal-key-row";
import { type PhotoTarget, TerminalUtilities } from "@/components/terminal-utilities";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { type ClipboardOutcome, useTerminalSession } from "@/hooks/use-terminal-session";
import { useKeyboardInset, useTerminalPinch } from "@/hooks/use-terminal-utilities";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { effectiveFontSize, useTerminalPreferences } from "@/stores/terminal-preferences";

/** How long the text-size badge stays on the terminal. */
const SIZE_BADGE_MS = 1_400;

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
  pretypeOnAttach = false,
  photo,
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
  /** Queued host command handoff: type once after the person connects. */
  pretypeOnAttach?: boolean;
  /** Sandbox terminals with file access: where Utilities › Photo uploads to. */
  photo?: PhotoTarget;
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
    pretypeCommand: pretypeOnAttach ? typeCommand : undefined,
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

  // Terminal utilities (design D): key row, text size, pinch.
  const keysShown = useTerminalPreferences((state) => state.keysShown);
  const setKeysShown = useTerminalPreferences((state) => state.setKeysShown);
  const storedFontSize = useTerminalPreferences((state) => state.fontSize);
  const storeFontSize = useTerminalPreferences((state) => state.setFontSize);
  const fontSize = effectiveFontSize(storedFontSize);
  // The size on screen now, which a pinch changes before it is remembered.
  const liveFontSize = useRef(fontSize);
  const [badge, setBadge] = useState<{ text: string; until: number } | null>(null);
  useRerenderAt(badge?.until ?? null);
  const badgeText = badge && Date.now() < badge.until ? badge.text : null;
  const applyFontSize = (size: number) => {
    liveFontSize.current = size;
    terminal.setFontSize(size, (fitted) =>
      setBadge({
        text: fitted
          ? t("terminal:utilities.badge", { size, cols: fitted.cols, rows: fitted.rows })
          : t("terminal:utilities.px", { size }),
        until: Date.now() + SIZE_BADGE_MS,
      }),
    );
  };
  const chooseFontSize = (size: number | null) => {
    storeFontSize(size);
    applyFontSize(effectiveFontSize(useTerminalPreferences.getState().fontSize));
  };
  const viewRef = useRef<HTMLDivElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  useTerminalPinch(viewRef, {
    enabled: shown,
    currentSize: () => liveFontSize.current,
    onPreview: applyFontSize,
    onCommit: (size) => chooseFontSize(size),
  });
  const keysVisible = keysShown && shown;
  const keyboardInset = useKeyboardInset(wrapRef, keysVisible);
  const setViewRef = (element: HTMLDivElement | null) => {
    viewRef.current = element;
    terminal.containerRef.current = element;
  };

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
        <TerminalUtilities
          terminal={terminal}
          attached={attached}
          keysShown={keysShown}
          onKeysShown={setKeysShown}
          fontSize={fontSize}
          fontSizeIsDefault={storedFontSize === null}
          onFontSize={chooseFontSize}
          size={attached ? size : null}
          photo={hostId ? undefined : photo}
          onOutcome={(outcome) =>
            report(outcome, t("terminal:clipboard.pasted"), t("terminal:clipboard.pasteEmpty"))
          }
        />
        {typeCommand && !pretypeOnAttach ? (
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
      <div ref={wrapRef} hidden={!shown} className="flex min-w-0 flex-col gap-1">
        <div className="relative min-w-0">
          <div
            ref={setViewRef}
            role="region"
            aria-label={t(hostId ? "terminal:host.regionLabel" : "terminal:regionLabel")}
            data-terminal-view=""
            className={cn(
              // Pinch on the terminal is text size, never page zoom (one finger scrolls).
              "h-[min(28rem,50svh)] min-h-40 w-full min-w-0 touch-pan-x touch-pan-y overflow-hidden overscroll-contain rounded-md border bg-black p-1",
              keyboardInset > 0 && "[&_textarea]:scroll-mb-16",
            )}
          />
          {badgeText ? (
            // An overlay, so it never refits the terminal (a refit resizes the PTY).
            <p
              role="status"
              data-terminal-size-badge=""
              className="pointer-events-none absolute top-2 right-2 rounded-md bg-background/90 px-2 py-1 font-mono text-xs text-foreground shadow"
            >
              {badgeText}
            </p>
          ) : null}
        </div>
        {keysVisible ? (
          // One instance whether pinned or not, so its latches survive the keyboard.
          <TerminalKeyRow
            terminal={terminal}
            className={
              keyboardInset > 0
                ? "fixed inset-x-0 z-40 border-t bg-background px-[max(0.25rem,var(--safe-area-left))] py-1"
                : undefined
            }
            style={keyboardInset > 0 ? { bottom: keyboardInset } : undefined}
          />
        ) : null}
        {keysVisible && keyboardInset > 0 ? (
          // Keeps the panel's height while the row sits above the keyboard.
          <div aria-hidden="true" data-terminal-keys-placeholder="" className="h-11" />
        ) : null}
      </div>
    </section>
  );
}
