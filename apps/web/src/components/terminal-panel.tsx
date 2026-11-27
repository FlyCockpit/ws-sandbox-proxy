import { Button } from "@wssp/ui/components/button";
import { toast } from "@wssp/ui/components/sileo";
import { cn } from "@wssp/ui/lib/utils";
import { ClipboardPaste, Copy, Keyboard, Plug, Power } from "lucide-react";
import { type ReactNode, type Ref, useId, useImperativeHandle, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  EndSessionDialog,
  MaximizeButton,
  PHONE_TERMINAL_QUERY,
  SelectTextOverlay,
  TerminalAreaMessage,
  TerminalHeaderRow,
} from "@/components/terminal-header";
import { TerminalKeyRow } from "@/components/terminal-key-row";
import {
  type PhotoTarget,
  TerminalUtilities,
  type UtilityDialog,
  UtilityDialogs,
} from "@/components/terminal-utilities";
import { useMediaQuery } from "@/hooks/use-media-query";
import { useMobileKeyboard } from "@/hooks/use-mobile-keyboard";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { type ClipboardOutcome, useTerminalSession } from "@/hooks/use-terminal-session";
import { useKeyboardInset, useTerminalPinch } from "@/hooks/use-terminal-utilities";
import { useTwoFactorRedirect } from "@/hooks/use-two-factor-redirect";
import { effectiveFontSize, useTerminalPreferences } from "@/stores/terminal-preferences";

/** How long the text-size badge stays on the terminal. */
const SIZE_BADGE_MS = 1_400;

export type TerminalPanelHandle = { attach: () => void };

export function TerminalPanel({
  ref,
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
  name,
  maximizable = true,
}: {
  /**
   * False where the panel sits inside a dialog (the queued host-command
   * handoff): a transformed popup traps `position: fixed`, so it cannot fill
   * the screen there.
   */
  ref?: Ref<TerminalPanelHandle>;
  maximizable?: boolean;
  /** The terminal's name in the phone header's picker (the sandbox or host). */
  name?: string;
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
  // Phones: one header row, no status line; messages go into
  // the terminal area or a toast.
  const phone = useMediaQuery(PHONE_TERMINAL_QUERY);
  const mobileKeyboardOpen = useMobileKeyboard();
  const [maximized, setMaximized] = useState(false);
  const [ending, setEnding] = useState(false);
  const [selectText, setSelectText] = useState<string | null>(null);
  // A Paste/Photo dialog opened from the phone ⋯ menu, and whether to give the
  // terminal its focus (phone keyboard) back when it closes.
  const [dialog, setDialog] = useState<{ kind: UtilityDialog; refocus: boolean }>({
    kind: null,
    refocus: false,
  });
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
    if (header) {
      if (text !== null) toast.message(text);
      return;
    }
    setClipboard(text === null ? null : { text, status });
  };
  const active = status !== "idle" && status !== "ended";
  const attached = status === "attached";
  const shown = status !== "idle";
  const header = phone && shown;
  const fullscreen = maximizable && maximized && shown;
  const terminalName = name ?? t(hostId ? "terminal:host.title" : "terminal:title");
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
  // Measured for the key row, and for a maximized terminal with or without it.
  const keyboard = useKeyboardInset(wrapRef, keysVisible || fullscreen);
  const keyboardInset = keyboard.bottom;
  // Maximized above the keyboard: the panel ends where the keyboard starts
  // (browsers that shrink only the visual viewport), so xterm refits there;
  // the key row then stays in the panel instead of being pinned.
  const pinKeys = keysVisible && keyboardInset > 0 && !fullscreen;
  const setViewRef = (element: HTMLDivElement | null) => {
    viewRef.current = element;
    terminal.containerRef.current = element;
  };
  const attach = () => {
    // A confirmation left open when the last session ended by itself is not for this one.
    setEnding(false);
    setClipboard(null);
    setSelectText(null);
    setProofProblem(null);
    const code = attachCode?.();
    onAttempt?.();
    terminal.attach(code);
  };
  useImperativeHandle(ref, () => ({
    attach: () => {
      if (available && (status === "idle" || status === "ended")) attach();
    },
  }));
  const copyText = async (text: string): Promise<ClipboardOutcome> => {
    if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) return "unavailable";
    try {
      await navigator.clipboard.writeText(text);
      return "done";
    } catch {
      return "unavailable";
    }
  };
  const copySelection = () =>
    void terminal
      .copySelection()
      .then((outcome) =>
        report(outcome, t("terminal:clipboard.copied"), t("terminal:clipboard.copyEmpty")),
      );
  const utilityItems = {
    attached,
    keysShown,
    onKeysShown: setKeysShown,
    fontSize,
    fontSizeIsDefault: storedFontSize === null,
    onFontSize: chooseFontSize,
    size: attached ? size : null,
  };
  const photoTarget = hostId ? undefined : photo;
  const onUtilityOutcome = (outcome: ClipboardOutcome) =>
    report(outcome, t("terminal:clipboard.pasted"), t("terminal:clipboard.pasteEmpty"));
  const noticeText =
    status === "ended" && notice
      ? t(`terminal:notice.${notice.kind}`, { exitCode: notice.exitCode, code: notice.code ?? "" })
      : null;

  return (
    <section
      // The Terminals page links here (`#terminal`); a panel inside a dialog
      // (queued host commands) is never a page's hash target.
      id={maximizable ? "terminal" : undefined}
      aria-labelledby={headingId}
      data-terminal-status={status}
      data-terminal-layout={header ? "phone" : "wide"}
      data-terminal-maximized={fullscreen ? "" : undefined}
      // The terminal, its key row and swipe pad own their vertical gestures:
      // a swipe down in them never starts the dashboard's pull-to-refresh.
      data-pull-to-refresh="off"
      // Maximized with the keyboard open: exactly the visible area (the browser
      // may shrink and pan only the visual viewport).
      style={
        fullscreen && (keyboard.bottom > 0 || keyboard.top > 0)
          ? { top: keyboard.top, bottom: keyboard.bottom }
          : undefined
      }
      className={cn(
        "flex min-w-0 flex-col gap-3 bg-card text-card-foreground",
        fullscreen
          ? // Explicit user choice (Maximize): the terminal fills the screen, inside the
            // safe areas, over the page header; the mobile BottomNav stays visible below
            // it (shell rule) unless the keyboard has hidden it.
            cn(
              "fixed inset-0 z-50 gap-2 overflow-hidden pt-[max(0.25rem,var(--safe-area-top))] pr-[max(0.25rem,var(--safe-area-right))] pb-[max(0.25rem,var(--safe-area-bottom))] pl-[max(0.25rem,var(--safe-area-left))]",
              !mobileKeyboardOpen && "max-md:pb-[calc(3.5rem+var(--safe-area-bottom))]",
            )
          : // Phones: 12 px padding so the header row (picker ≥ 150 px, ⋯, Maximize) fits at 320 px.
            cn("rounded-xl border", header ? "p-3" : "p-4"),
      )}
    >
      <h2 id={headingId} className={cn("text-sm font-medium", fullscreen && "sr-only")}>
        {t(hostId ? "terminal:host.title" : "terminal:title")}
      </h2>
      {fullscreen ? null : (
        <p className="text-sm text-muted-foreground">
          {t(hostId ? "terminal:host.warning" : "terminal:description")}
        </p>
      )}
      {!active ? beforeAttach : null}
      {proofProblem ? <p role="alert">{t(`terminal:host.${proofProblem}`)}</p> : null}
      {header ? (
        <TerminalHeaderRow
          name={terminalName}
          status={status}
          notice={notice}
          lang={lang}
          newTerminal={hostId ? "hosts" : "sandboxes"}
          maximized={fullscreen}
          onMaximize={maximizable ? () => setMaximized(!fullscreen) : undefined}
          hasFocus={terminal.hasFocus}
          focus={terminal.focus}
          utilities={{
            ...utilityItems,
            photo: photoTarget !== undefined,
            onDialog: (kind, refocus) => setDialog({ kind, refocus }),
          }}
          canSelect={shown}
          onSelectText={() => setSelectText(terminal.bufferText())}
          onCopySelection={copySelection}
          typeCommand={
            typeCommand && !pretypeOnAttach
              ? {
                  enabled: attached,
                  onType: () =>
                    report(
                      terminal.typeText(typeCommand),
                      t("terminal:clipboard.typed"),
                      t("terminal:clipboard.pasteEmpty"),
                    ),
                }
              : undefined
          }
          session={{
            live: active,
            onEndSession: () => setEnding(true),
            canAttach: available,
            onAttach: attach,
            onClose: () => {
              setSelectText(null);
              setMaximized(false);
              terminal.close();
            },
          }}
        />
      ) : (
        <div
          role="group"
          aria-label={t("terminal:actionsLabel")}
          className="flex min-w-0 flex-wrap gap-2"
        >
          {/* One element for attach and End session, so keyboard focus stays on it. */}
          <Button
            type="button"
            size="touch"
            variant={active ? "outline" : "default"}
            data-terminal-toggle={active ? "detach" : "attach"}
            disabled={!active && !available}
            className={active ? "text-destructive" : undefined}
            onClick={() => {
              if (active) setEnding(true);
              else attach();
            }}
          >
            {active ? (
              <Power aria-hidden="true" className="size-4" />
            ) : (
              <Plug aria-hidden="true" className="size-4" />
            )}
            {active
              ? t("terminal:actions.endSession")
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
            onClick={copySelection}
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
                  report(
                    outcome,
                    t("terminal:clipboard.pasted"),
                    t("terminal:clipboard.pasteEmpty"),
                  ),
                )
            }
          >
            <ClipboardPaste aria-hidden="true" className="size-4" />
            {t("terminal:actions.paste")}
          </Button>
          <TerminalUtilities
            terminal={terminal}
            {...utilityItems}
            photo={photoTarget !== undefined}
            onDialog={(kind, refocus) => setDialog({ kind, refocus })}
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
          {shown && maximizable ? (
            <MaximizeButton maximized={fullscreen} onToggle={() => setMaximized(!fullscreen)} />
          ) : null}
        </div>
      )}
      <UtilityDialogs
        dialog={dialog.kind}
        terminal={terminal}
        photo={photoTarget}
        refocus={dialog.refocus}
        onClose={() => setDialog({ kind: null, refocus: false })}
        onOutcome={onUtilityOutcome}
      />
      <EndSessionDialog
        open={ending && active}
        onOpenChange={setEnding}
        name={terminalName}
        host={hostId !== undefined}
        onConfirm={() => {
          setClipboard(null);
          terminal.detach();
        }}
      />
      {!available && !active ? (
        <p className="text-sm text-muted-foreground">
          {unavailableMessage ?? t(hostId ? "terminal:host.unavailable" : "terminal:unavailable")}
        </p>
      ) : null}
      <p
        role="status"
        aria-live="polite"
        data-terminal-state=""
        // Phones have no status line; screen readers still hear it.
        className={header ? "sr-only" : "text-sm"}
      >
        {attached && size
          ? t("terminal:status.attached", { rows: size.rows, cols: size.cols })
          : t(`terminal:status.${status}`)}
        {clipboardText ? <span className="ms-2 text-muted-foreground">{clipboardText}</span> : null}
      </p>
      {!header && noticeText && notice ? (
        <p
          role={quiet ? undefined : "alert"}
          data-terminal-notice={notice.kind}
          className={cn("text-sm", quiet ? "text-muted-foreground" : "text-destructive")}
        >
          {noticeText}
        </p>
      ) : null}
      {!header && warning ? (
        <p data-terminal-warning={warning} className="text-sm text-amber-800 dark:text-amber-300">
          {t(`terminal:warning.${warning}`)}
        </p>
      ) : null}
      <div
        ref={wrapRef}
        hidden={!shown}
        className={cn("flex min-w-0 flex-col gap-1", fullscreen && "min-h-0 flex-1")}
      >
        <div className={cn("relative min-w-0", fullscreen && "min-h-0 flex-1")}>
          <div
            ref={setViewRef}
            role="region"
            aria-label={t(hostId ? "terminal:host.regionLabel" : "terminal:regionLabel")}
            data-terminal-view=""
            className={cn(
              // Pinch on the terminal is text size, never page zoom (one finger scrolls).
              fullscreen ? "h-full min-h-0" : "h-[min(28rem,50svh)] min-h-40",
              "w-full min-w-0 touch-pan-x touch-pan-y overflow-hidden overscroll-contain rounded-md border bg-black p-1",
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
          {selectText !== null ? (
            <SelectTextOverlay
              text={selectText}
              onDone={() => {
                setSelectText(null);
                terminal.focus();
              }}
              onCopy={(text) =>
                void copyText(text).then((outcome) =>
                  report(
                    outcome,
                    t("terminal:clipboard.copied"),
                    t("terminal:clipboard.copyEmpty"),
                  ),
                )
              }
            />
          ) : null}
          {header && (noticeText || warning) ? (
            // Phones: what the status line said, inside the terminal area.
            <div className="pointer-events-none absolute inset-x-2 bottom-2 z-10 flex flex-col gap-1">
              {warning ? (
                <TerminalAreaMessage tone="warning" data-terminal-warning={warning}>
                  {t(`terminal:warning.${warning}`)}
                </TerminalAreaMessage>
              ) : null}
              {noticeText && notice ? (
                <TerminalAreaMessage
                  tone={quiet ? "quiet" : "alert"}
                  data-terminal-notice={notice.kind}
                >
                  <p>{noticeText}</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Button
                      type="button"
                      size="touch"
                      data-terminal-toggle="attach"
                      disabled={!available}
                      onClick={attach}
                    >
                      <Plug aria-hidden="true" className="size-4" />
                      {t("terminal:actions.reattach")}
                    </Button>
                  </div>
                </TerminalAreaMessage>
              ) : null}
            </div>
          ) : null}
        </div>
        {keysVisible ? (
          // One instance whether pinned or not, so its latches survive the keyboard.
          <TerminalKeyRow
            terminal={terminal}
            className={
              pinKeys
                ? "fixed inset-x-0 z-40 border-t bg-background px-[max(0.25rem,var(--safe-area-left))] py-1"
                : undefined
            }
            style={pinKeys ? { bottom: keyboardInset } : undefined}
          />
        ) : null}
        {pinKeys ? (
          // Keeps the panel's height while the row sits above the keyboard.
          <div aria-hidden="true" data-terminal-keys-placeholder="" className="h-11" />
        ) : null}
      </div>
    </section>
  );
}
