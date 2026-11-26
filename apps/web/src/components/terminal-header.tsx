import { Link } from "@tanstack/react-router";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@wssp/ui/components/dropdown-menu";
import { cn } from "@wssp/ui/lib/utils";
import {
  Check,
  ChevronDown,
  Copy,
  Ellipsis,
  Eye,
  Keyboard,
  Maximize2,
  Minimize2,
  Plug,
  Plus,
  Power,
  TextSelect,
  X,
} from "lucide-react";
import { type ReactNode, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  type UtilityDialog,
  type UtilityItemsProps,
  UtilityMenuItems,
} from "@/components/terminal-utilities";
import type { TerminalNotice } from "@/lib/terminal-protocol";

/** Phones get the one-row terminal header; wider screens keep the actions row. */
export const PHONE_TERMINAL_QUERY = "(max-width: 640px)";

type Status =
  | "idle"
  | "loading"
  | "connecting"
  | "verifying"
  | "attached"
  | "reconnecting"
  | "ended";

/**
 * The picker's status icon. Icon: keyboard = what you type reaches the
 * shell; eye = view only (wssp: reconnecting, scrollback shown and input
 * stopped; a second attach elsewhere replaces a terminal rather than
 * sharing it). Colour: green connected, amber opening, red refused, grey
 * ended.
 */
export type TerminalIndicator = {
  mode: "typing" | "viewing";
  tone: "connected" | "opening" | "refused" | "ended";
};

/** Ends that mean the terminal never opened (or could not reopen): red. */
const REFUSED: ReadonlySet<string> = new Set([
  "signedOut",
  "forbidden",
  "notFound",
  "notReady",
  "rateLimited",
  "unavailable",
  "createFailed",
  "couldNotConnect",
  "insecure",
  "loadFailed",
  "noTerminalIdentity",
  "hostCapacity",
  "hostRefused",
  "openTimedOut",
  "hostTerminalsDisabled",
]);

export function terminalIndicator(
  status: Status,
  notice: TerminalNotice | null,
): TerminalIndicator {
  if (status === "attached") return { mode: "typing", tone: "connected" };
  if (status === "reconnecting") return { mode: "viewing", tone: "opening" };
  if (status === "ended" || status === "idle")
    return { mode: "typing", tone: notice && REFUSED.has(notice.kind) ? "refused" : "ended" };
  return { mode: "typing", tone: "opening" };
}

// Important: a focused menu item recolours its icons (`focus:**:text-accent-foreground`
// in the shared dropdown); the status colour must survive that.
const TONE_CLASS: Record<TerminalIndicator["tone"], string> = {
  connected: "text-emerald-600! dark:text-emerald-400!",
  opening: "text-amber-600! dark:text-amber-400!",
  refused: "text-destructive!",
  ended: "text-muted-foreground!",
};

export function TerminalStatusIcon({ indicator }: { indicator: TerminalIndicator }) {
  const Icon = indicator.mode === "viewing" ? Eye : Keyboard;
  return (
    <Icon
      aria-hidden="true"
      data-terminal-indicator={`${indicator.mode}-${indicator.tone}`}
      className={cn("size-4 shrink-0", TONE_CLASS[indicator.tone])}
    />
  );
}

/** "Connected · typing", "Reconnecting · viewing", "Opening…", "Refused", "Ended". */
function indicatorText(indicator: TerminalIndicator): string {
  if (indicator.tone === "connected") return "terminal:header.state.typing";
  if (indicator.mode === "viewing") return "terminal:header.state.viewing";
  return `terminal:header.state.${indicator.tone}`;
}

/** Where wssp opens terminals: a sandbox's or a host's detail page. */
export type NewTerminalTarget = "sandboxes" | "hosts";

function TerminalPicker({
  name,
  indicator,
  lang,
  newTerminal,
  live,
}: {
  name: string;
  indicator: TerminalIndicator;
  lang: string;
  newTerminal: NewTerminalTarget;
  live: boolean;
}) {
  const { t } = useTranslation(["terminal"]);
  const state = t(indicatorText(indicator));
  const newItem = (
    <>
      <Plus aria-hidden="true" />
      <span className="flex min-w-0 flex-1 flex-col">
        <span>{t("terminal:header.newTerminal")}</span>
        <small className="text-xs text-muted-foreground">
          {t(
            live
              ? "terminal:header.newTerminalLeaves"
              : newTerminal === "hosts"
                ? "terminal:header.newTerminalHosts"
                : "terminal:header.newTerminalSandboxes",
          )}
        </small>
      </span>
    </>
  );
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            type="button"
            size="touch"
            variant="ghost"
            data-terminal-picker=""
            aria-label={t("terminal:header.picker", { name, state })}
            title={`${name} · ${state}`}
            className="min-w-[150px] flex-1 justify-start gap-2 px-2"
          />
        }
      >
        <TerminalStatusIcon indicator={indicator} />
        <span className="min-w-0 flex-1 truncate text-start font-medium">{name}</span>
        <ChevronDown aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-80 max-w-[calc(100vw-1rem)]">
        <DropdownMenuGroup>
          <DropdownMenuLabel>{t("terminal:header.openTerminals")}</DropdownMenuLabel>
          {/* wssp shows one terminal per page: this one. */}
          <DropdownMenuItem
            role="menuitemradio"
            aria-checked="true"
            data-terminal-picker-item="current"
          >
            <TerminalStatusIcon indicator={indicator} />
            <span className="flex min-w-0 flex-1 flex-col">
              <span className="truncate font-medium">{name}</span>
              <small className="text-xs text-muted-foreground">{state}</small>
            </span>
            <Check aria-hidden="true" />
          </DropdownMenuItem>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        {newTerminal === "hosts" ? (
          <DropdownMenuItem
            data-terminal-new=""
            render={<Link to="/$lang/settings/hosts" params={{ lang }} />}
          >
            {newItem}
          </DropdownMenuItem>
        ) : (
          <DropdownMenuItem
            data-terminal-new=""
            render={<Link to="/$lang/dashboard/sandboxes" params={{ lang }} />}
          >
            {newItem}
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** What the ⋯ menu's Session group can do. */
type SessionActions = {
  /** The terminal is open or opening: End session… (asks first). */
  live: boolean;
  onEndSession: () => void;
  /** Ended: Attach again, and Close (clears the ended view). */
  canAttach: boolean;
  onAttach: () => void;
  onClose: () => void;
};

function TerminalMoreMenu({
  hasFocus,
  focus,
  utilities,
  onSelectText,
  canSelect,
  onCopySelection,
  typeCommand,
  session,
}: {
  hasFocus: () => boolean;
  focus: () => void;
  utilities: Omit<UtilityItemsProps, "onDone" | "onDialog"> & {
    /** `refocus`: the terminal had focus (phone keyboard up) before the menu opened. */
    onDialog: (dialog: Exclude<UtilityDialog, null>, refocus: boolean) => void;
  };
  onSelectText: () => void;
  canSelect: boolean;
  onCopySelection: () => void;
  /** The CLI-login page's "Type it for me", when offered. */
  typeCommand?: { enabled: boolean; onType: () => void };
  session: SessionActions;
}) {
  const { t } = useTranslation(["terminal"]);
  const refocus = useRef(false);
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            type="button"
            size="icon-touch"
            variant="ghost"
            data-terminal-more=""
            aria-label={t("terminal:header.more")}
            title={t("terminal:header.more")}
            onPointerDown={() => {
              refocus.current = hasFocus();
            }}
          />
        }
      >
        <Ellipsis aria-hidden="true" className="size-4" />
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        className="w-72 max-w-[calc(100vw-1rem)]"
        finalFocus={() => !refocus.current}
      >
        <DropdownMenuGroup data-menu-group="type-view">
          <DropdownMenuLabel>{t("terminal:header.typeView")}</DropdownMenuLabel>
          <UtilityMenuItems
            {...utilities}
            onDialog={(dialog) => utilities.onDialog(dialog, refocus.current)}
            onDone={() => {
              if (refocus.current) focus();
            }}
          />
          <DropdownMenuItem data-utility="select" disabled={!canSelect} onClick={onSelectText}>
            <TextSelect aria-hidden="true" />
            {t("terminal:header.selectText")}
          </DropdownMenuItem>
          <DropdownMenuItem data-utility="copy" disabled={!canSelect} onClick={onCopySelection}>
            <Copy aria-hidden="true" />
            {t("terminal:actions.copy")}
          </DropdownMenuItem>
          {typeCommand ? (
            <DropdownMenuItem
              data-utility="type"
              disabled={!typeCommand.enabled}
              onClick={typeCommand.onType}
            >
              <Keyboard aria-hidden="true" />
              {t("terminal:actions.type")}
            </DropdownMenuItem>
          ) : null}
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuGroup data-menu-group="session">
          <DropdownMenuLabel>{t("terminal:header.session")}</DropdownMenuLabel>
          {session.live ? (
            <DropdownMenuItem
              data-session="end"
              data-danger=""
              // Red. Not variant="destructive": this app's menus render
              // that variant in the neutral foreground colour.
              className="text-destructive! *:[svg]:text-destructive!"
              onClick={session.onEndSession}
            >
              <Power aria-hidden="true" />
              {t("terminal:header.endSession")}
            </DropdownMenuItem>
          ) : (
            <>
              <DropdownMenuItem
                data-session="attach"
                disabled={!session.canAttach}
                onClick={session.onAttach}
              >
                <Plug aria-hidden="true" />
                {t("terminal:actions.reattach")}
              </DropdownMenuItem>
              <DropdownMenuItem data-session="close" onClick={session.onClose}>
                <X aria-hidden="true" />
                {t("terminal:header.close")}
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function MaximizeButton({
  maximized,
  onToggle,
}: {
  maximized: boolean;
  onToggle: () => void;
}) {
  const { t } = useTranslation(["terminal"]);
  const label = t(maximized ? "terminal:header.restore" : "terminal:header.maximize");
  return (
    <Button
      type="button"
      size="icon-touch"
      variant="ghost"
      data-terminal-maximize={maximized ? "restore" : "maximize"}
      aria-pressed={maximized}
      aria-label={label}
      title={label}
      onClick={onToggle}
    >
      {maximized ? (
        <Minimize2 aria-hidden="true" className="size-4" />
      ) : (
        <Maximize2 aria-hidden="true" className="size-4" />
      )}
    </Button>
  );
}

/**
 * The phone terminal header: one
 * fixed row at every phone width — the terminal picker, ⋯ with the Type &
 * view and Session groups, and Maximize/Restore in the corner. Nothing
 * moves into an overflow as the screen narrows.
 */
export function TerminalHeaderRow({
  name,
  status,
  notice,
  lang,
  newTerminal,
  maximized,
  onMaximize,
  ...menu
}: {
  name: string;
  status: Status;
  notice: TerminalNotice | null;
  lang: string;
  newTerminal: NewTerminalTarget;
  maximized: boolean;
  /** Absent where the terminal cannot be maximized (inside a dialog). */
  onMaximize?: () => void;
} & Parameters<typeof TerminalMoreMenu>[0]) {
  const { t } = useTranslation(["terminal"]);
  const indicator = terminalIndicator(status, notice);
  return (
    <div
      role="group"
      aria-label={t("terminal:actionsLabel")}
      data-terminal-header=""
      className="flex min-w-0 items-center gap-0.5"
    >
      <TerminalPicker
        name={name}
        indicator={indicator}
        lang={lang}
        newTerminal={newTerminal}
        live={menu.session.live}
      />
      <TerminalMoreMenu {...menu} />
      {onMaximize ? <MaximizeButton maximized={maximized} onToggle={onMaximize} /> : null}
    </div>
  );
}

/** End session asks first, at every width. */
export function EndSessionDialog({
  open,
  onOpenChange,
  name,
  host,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  name: string;
  host: boolean;
  onConfirm: () => void;
}) {
  const { t } = useTranslation(["terminal"]);
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent data-terminal-end-dialog="">
        <AlertDialogHeader>
          <AlertDialogTitle>{t("terminal:endDialog.title")}</AlertDialogTitle>
          <AlertDialogDescription>
            {t(host ? "terminal:endDialog.hostDescription" : "terminal:endDialog.description", {
              name,
            })}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel className="min-h-11" data-end-cancel="">
            {t("terminal:endDialog.cancel")}
          </AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            className="min-h-11"
            data-end-confirm=""
            onClick={() => {
              onOpenChange(false);
              onConfirm();
            }}
          >
            {t("terminal:endDialog.confirm")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/**
 * Select text: the terminal's text as of opening, in a box where it can be
 * selected by touch. Copying stays an explicit button (as on the terminal,
 * native copy is cancelled), and nothing here is sent to the shell.
 */
export function SelectTextOverlay({
  text,
  onDone,
  onCopy,
}: {
  text: string;
  onDone: () => void;
  onCopy: (text: string) => void;
}) {
  const { t } = useTranslation(["terminal"]);
  const boxRef = useRef<HTMLDivElement | null>(null);
  const [empty, setEmpty] = useState(false);
  // Cancels native copy/cut in the box, and keeps the selection when Copy is tapped.
  const block = (event: { preventDefault: () => void }) => event.preventDefault();
  return (
    <div
      data-terminal-select=""
      className="absolute inset-0 z-10 flex min-h-0 min-w-0 flex-col gap-1 rounded-md border bg-background p-1"
    >
      <div className="flex min-w-0 flex-wrap items-center gap-1">
        <p role="status" className="min-w-0 flex-1 px-1 text-xs text-muted-foreground">
          {t(empty ? "terminal:clipboard.copyEmpty" : "terminal:selectText.hint")}
        </p>
        <Button
          type="button"
          size="touch"
          variant="outline"
          data-select-copy=""
          // Keep the selection: the button must not take it away on tap.
          onPointerDown={block}
          onMouseDown={block}
          onClick={() => {
            const selection = typeof window === "undefined" ? null : window.getSelection();
            const box = boxRef.current;
            const inside =
              selection && box && selection.anchorNode && box.contains(selection.anchorNode)
                ? selection.toString()
                : "";
            setEmpty(inside.length === 0);
            if (inside.length > 0) onCopy(inside);
          }}
        >
          <Copy aria-hidden="true" className="size-4" />
          {t("terminal:selectText.copy")}
        </Button>
        <Button type="button" size="touch" data-select-done="" onClick={onDone}>
          {t("terminal:selectText.done")}
        </Button>
      </div>
      <div
        ref={boxRef}
        role="textbox"
        aria-readonly="true"
        aria-multiline="true"
        tabIndex={0}
        aria-label={t("terminal:selectText.label")}
        onCopy={block}
        onCut={block}
        className="min-h-0 min-w-0 flex-1 overflow-x-auto overflow-y-auto overscroll-contain rounded-sm bg-black p-2 font-mono text-xs whitespace-pre text-white select-text"
      >
        {text}
      </div>
    </div>
  );
}

/** A message the phone layout shows inside the terminal area instead of a status line. */
export function TerminalAreaMessage({
  children,
  tone,
  ...rest
}: {
  children: ReactNode;
  tone: "alert" | "quiet" | "warning";
} & Record<`data-${string}`, string>) {
  return (
    <div
      role={tone === "alert" ? "alert" : "status"}
      {...rest}
      className={cn(
        "pointer-events-auto rounded-md border bg-background/95 px-3 py-2 text-sm shadow",
        tone === "alert" && "text-destructive",
        tone === "quiet" && "text-muted-foreground",
        tone === "warning" && "text-amber-800 dark:text-amber-300",
      )}
    >
      {children}
    </div>
  );
}
