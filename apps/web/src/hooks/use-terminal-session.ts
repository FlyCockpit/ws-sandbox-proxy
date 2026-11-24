import { hostTerminalPath } from "@wssp/config/browser-terminal";
import { env } from "@wssp/env/web";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  IDLE_TERMINAL,
  PASTE_MAX_BYTES,
  TerminalClient,
  type TerminalClientOptions,
  type TerminalSnapshot,
} from "@/lib/terminal-client";
import { useTerminalPreferences } from "@/stores/terminal-preferences";
import { orpc } from "@/utils/orpc";

export type ClipboardOutcome = "done" | "empty" | "unavailable" | "tooLarge" | "ended";

/**
 * Lifetime of the sandbox terminal (C54). Nothing connects on mount: `attach`
 * is the owner's explicit action, and it is the only path that loads xterm
 * (a dynamic import) and mints a ticket. Each attach is a new
 * `TerminalClient`: a new session, a new ticket, a new PTY. The only automatic
 * reconnect is a sandbox terminal reattaching its own detached PTY after a
 * relay drop or server restart (WP8, bounded attempts within the grace).
 *
 * The ticket is minted by a direct call of the `sandboxTerminals.createSession`
 * client, NOT through TanStack Query: a mutation or query would keep the
 * response (and the ticket in it) in the client cache (C53-CO-6).
 *
 * Unmount (including Strict Mode's simulated one) sends the CloseIntent,
 * closes the socket, removes every listener and disposes xterm.
 */
export function useTerminalSession({
  sandboxId = "",
  hostId,
  onCreateError,
  onPaste,
  pretypeCommand,
}: {
  sandboxId?: string;
  hostId?: string;
  /** One printable line, typed once after an explicit host-terminal attach. */
  pretypeCommand?: string;
  onCreateError?: (error: unknown) => void;
  /** The outcome of a native paste (Ctrl/Cmd+V, context menu) in the terminal. */
  onPaste?: (outcome: ClipboardOutcome) => void;
}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const clientRef = useRef<TerminalClient | null>(null);
  const onCreateErrorRef = useRef(onCreateError);
  const onPasteRef = useRef(onPaste);
  const [snapshot, setSnapshot] = useState<TerminalSnapshot>(IDLE_TERMINAL);
  // Terminal utilities state outlives one client: a re-attach keeps them.
  const fontSizeRef = useRef<number | null>(null);
  const keyFilterRef = useRef<((data: string) => string) | null>(null);
  // Read by the long-lived client; synced after every render.
  useEffect(() => {
    onCreateErrorRef.current = onCreateError;
    onPasteRef.current = onPaste;
  });

  useEffect(
    () => () => {
      clientRef.current?.dispose();
      clientRef.current = null;
    },
    [],
  );

  const attach = useCallback(
    (code?: string) => {
      const container = containerRef.current;
      if (!container) return;
      const status = clientRef.current?.state.status;
      if (status && status !== "idle" && status !== "ended") return;
      // A re-attach starts over: the previous buffer goes with its view.
      clientRef.current?.dispose();
      let pretyped = false;
      const command =
        hostId &&
        pretypeCommand &&
        pretypeCommand.length <= PASTE_MAX_BYTES &&
        /^[\x20-\x7e]+$/.test(pretypeCommand)
          ? pretypeCommand
          : undefined;
      const options: TerminalClientOptions = {
        sandboxId,
        serverUrl: env.VITE_SERVER_URL,
        container,
        // Host terminals stay v1 and are never reattached (WP8): only a
        // sandbox terminal mints v2 tickets and resumes after a relay drop.
        ...(hostId
          ? { terminalPath: hostTerminalPath(hostId), retryRefusedUpgrade: false }
          : { resumable: true }),
        createSession: (input, call) => {
          // A reattach attempt abandons a stalled mint at its timeout or grace.
          if (!hostId)
            return call?.signal
              ? orpc.sandboxTerminals.createSession.call(input, { signal: call.signal })
              : orpc.sandboxTerminals.createSession.call(input);
          const request = orpc.hostTerminals.createSession.call({
            hostId,
            rows: input.rows,
            cols: input.cols,
            ...(code ? { code } : {}),
          });
          code = undefined;
          return request;
        },
        loadView: () => import("@/lib/xterm-view").then((module) => module.createTerminalView),
        onChange: (next) => {
          if (clientRef.current !== client) return;
          setSnapshot(next);
          if (next.status === "attached" && command && !pretyped) {
            pretyped = true;
            client.paste(command);
          }
        },
        onCreateError: (error) => onCreateErrorRef.current?.(error),
        onPaste: (outcome) => {
          if (clientRef.current === client) onPasteRef.current?.(outcome);
        },
      };
      const client = new TerminalClient(options);
      clientRef.current = client;
      // The size on screen, else the one remembered on this device.
      const fontSize = fontSizeRef.current ?? useTerminalPreferences.getState().fontSize;
      if (fontSize !== null) client.setFontSize(fontSize);
      client.setKeyFilter(keyFilterRef.current);
      void client.start();
    },
    [sandboxId, hostId, pretypeCommand],
  );

  const detach = useCallback(() => {
    clientRef.current?.detach();
  }, []);

  /** Copy the terminal selection: the explicit Copy button only. */
  const copySelection = useCallback(async (): Promise<ClipboardOutcome> => {
    const text = clientRef.current?.selection() ?? "";
    if (text.length === 0) return "empty";
    if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) return "unavailable";
    try {
      await navigator.clipboard.writeText(text);
      return "done";
    } catch {
      return "unavailable";
    } finally {
      clientRef.current?.focus();
    }
  }, []);

  /** The Paste button: read the clipboard, then the same path as a native paste. */
  const paste = useCallback(async (): Promise<ClipboardOutcome> => {
    if (typeof navigator === "undefined" || !navigator.clipboard?.readText) return "unavailable";
    let text: string;
    try {
      text = await navigator.clipboard.readText();
    } catch {
      return "unavailable";
    }
    return clientRef.current?.paste(text) ?? "unavailable";
  }, []);

  /**
   * Type known text into the attached terminal (the login page's "Type it for
   * me", the Paste dialog, a photo's path): the same path as a paste, so
   * nothing runs until the user presses Enter.
   */
  const typeText = useCallback(
    (text: string): ClipboardOutcome => clientRef.current?.paste(text) ?? "unavailable",
    [],
  );

  /** On-screen key bytes, sent as typed input. */
  const sendKeys = useCallback(
    (data: string): boolean => clientRef.current?.sendKeys(data) ?? false,
    [],
  );

  const setKeyFilter = useCallback((filter: ((data: string) => string) | null) => {
    keyFilterRef.current = filter;
    clientRef.current?.setKeyFilter(filter);
  }, []);

  /** Text size; refits so cols × rows follow (and the PTY is resized). */
  const setFontSize = useCallback(
    (size: number, onFit?: (fitted: { rows: number; cols: number } | null) => void) => {
      fontSizeRef.current = size;
      clientRef.current?.setFontSize(size, onFit);
    },
    [],
  );

  const focus = useCallback(() => clientRef.current?.focus(), []);
  const hasFocus = useCallback(() => clientRef.current?.hasFocus() ?? false, []);
  const applicationCursorKeys = useCallback(
    () => clientRef.current?.applicationCursorKeys() ?? false,
    [],
  );
  const bracketedPaste = useCallback(() => clientRef.current?.bracketedPaste() ?? false, []);

  return {
    containerRef,
    snapshot,
    attach,
    detach,
    copySelection,
    paste,
    typeText,
    sendKeys,
    setKeyFilter,
    setFontSize,
    focus,
    hasFocus,
    applicationCursorKeys,
    bracketedPaste,
  };
}
