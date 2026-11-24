import { env } from "@wssp/env/web";
import { Button } from "@wssp/ui/components/button";
import { Checkbox } from "@wssp/ui/components/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@wssp/ui/components/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@wssp/ui/components/dropdown-menu";
import { Label } from "@wssp/ui/components/label";
import { Textarea } from "@wssp/ui/components/textarea";
import { Camera, ClipboardPaste, ImagePlus, Keyboard, Wrench } from "lucide-react";
import { type ReactNode, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAbortOnUnmount } from "@/hooks/use-abort-on-unmount";
import type { ClipboardOutcome } from "@/hooks/use-terminal-session";
import { formatBytes, isOperationActive, type OperationState } from "@/lib/sandbox-rules";
import { type TransferProblem, toTransferProblem, uploadToSandbox } from "@/lib/sandbox-transfers";
import {
  FONT_SIZE_MAX,
  FONT_SIZE_MIN,
  PHOTO_MAX_BYTES,
  PHOTO_TYPES,
  photoGuestPath,
  shellQuote,
} from "@/lib/terminal-keys";
import { orpc } from "@/utils/orpc";

/** What the Utilities menu needs from the terminal session. */
export type UtilitiesTerminal = {
  typeText: (text: string) => ClipboardOutcome;
  sendKeys: (data: string) => boolean;
  focus: () => void;
  hasFocus: () => boolean;
  bracketedPaste: () => boolean;
};

/** Where a photo goes: the sandbox and its guest user's home. */
export type PhotoTarget = { sandboxId: string; guestHome: string };

export type UtilityDialog = "paste" | "photo" | null;

/** The Type & view controls: shared by the wide Utilities button and the phone ⋯ menu. */
export type UtilityItemsProps = {
  attached: boolean;
  keysShown: boolean;
  onKeysShown: (shown: boolean) => void;
  fontSize: number;
  fontSizeIsDefault: boolean;
  /** A size in px, or null for the default. */
  onFontSize: (size: number | null) => void;
  size: { rows: number; cols: number } | null;
  /** Sandbox terminals only: whether Photo is offered. */
  photo: boolean;
  onDialog: (dialog: Exclude<UtilityDialog, null>) => void;
  /** Called after Show/Hide keys (puts the phone keyboard back when it was up). */
  onDone: () => void;
};

/**
 * Show/Hide keys, Paste…, Photo / camera… and the text size (A− / A+ /
 * Reset, which keep the menu open), as items of an open dropdown menu.
 */
export function UtilityMenuItems({
  attached,
  keysShown,
  onKeysShown,
  fontSize,
  fontSizeIsDefault,
  onFontSize,
  size,
  photo,
  onDialog,
  onDone,
}: UtilityItemsProps) {
  const { t } = useTranslation(["terminal"]);
  return (
    <>
      <DropdownMenuItem
        data-utility="keys"
        onClick={() => {
          onKeysShown(!keysShown);
          onDone();
        }}
      >
        <Keyboard aria-hidden="true" />
        <span className="flex-1">
          {t(keysShown ? "terminal:utilities.hideKeys" : "terminal:utilities.showKeys")}
        </span>
      </DropdownMenuItem>
      <DropdownMenuItem data-utility="paste" disabled={!attached} onClick={() => onDialog("paste")}>
        <ClipboardPaste aria-hidden="true" />
        {t("terminal:utilities.paste")}
      </DropdownMenuItem>
      {photo ? (
        <DropdownMenuItem
          data-utility="photo"
          disabled={!attached}
          onClick={() => onDialog("photo")}
        >
          <Camera aria-hidden="true" />
          {t("terminal:utilities.photo")}
        </DropdownMenuItem>
      ) : null}
      <DropdownMenuSeparator />
      <DropdownMenuGroup>
        <DropdownMenuLabel>{t("terminal:utilities.textSize")}</DropdownMenuLabel>
        <div className="flex min-w-0 items-center gap-1 px-1 pb-1">
          <DropdownMenuItem
            closeOnClick={false}
            data-utility="smaller"
            aria-label={t("terminal:utilities.smaller")}
            disabled={fontSize <= FONT_SIZE_MIN}
            className="justify-center border px-3"
            onClick={() => onFontSize(fontSize - 1)}
          >
            {t("terminal:utilities.smallerShort")}
          </DropdownMenuItem>
          <p
            aria-live="polite"
            data-utility-size=""
            className="flex min-w-0 flex-1 flex-col items-center text-sm font-medium"
          >
            <span>{t("terminal:utilities.px", { size: fontSize })}</span>
            {size ? (
              <span className="text-xs font-normal text-muted-foreground">
                {size.cols}×{size.rows}
              </span>
            ) : null}
          </p>
          <DropdownMenuItem
            closeOnClick={false}
            data-utility="larger"
            aria-label={t("terminal:utilities.larger")}
            disabled={fontSize >= FONT_SIZE_MAX}
            className="justify-center border px-3"
            onClick={() => onFontSize(fontSize + 1)}
          >
            {t("terminal:utilities.largerShort")}
          </DropdownMenuItem>
          <DropdownMenuItem
            closeOnClick={false}
            data-utility="reset"
            disabled={fontSizeIsDefault}
            className="justify-center border px-3"
            onClick={() => onFontSize(null)}
          >
            {t("terminal:utilities.reset")}
          </DropdownMenuItem>
        </div>
        <p className="px-1.5 pb-1 text-xs text-muted-foreground">
          {t("terminal:utilities.pinchHint")}
        </p>
      </DropdownMenuGroup>
    </>
  );
}

/** The Paste and Photo dialogs, opened from either menu. */
export function UtilityDialogs({
  dialog,
  terminal,
  photo,
  refocus,
  onClose,
  onOutcome,
}: {
  dialog: UtilityDialog;
  terminal: UtilitiesTerminal;
  photo?: PhotoTarget;
  /** Whether the terminal had focus (phone keyboard up) before the menu took it. */
  refocus: boolean;
  onClose: () => void;
  /** A paste or photo's result, reported by the panel. */
  onOutcome: (outcome: ClipboardOutcome) => void;
}) {
  // Closed any way (Cancel, Escape, ×, done): the terminal gets its focus,
  // and the phone keyboard, back when it had them. After the dialog has let
  // go of focus, so its own restore cannot take it again.
  const close = () => {
    onClose();
    if (refocus) requestAnimationFrame(() => terminal.focus());
  };
  if (dialog === "paste")
    return (
      <PasteDialog terminal={terminal} refocus={refocus} onClose={close} onOutcome={onOutcome} />
    );
  if (dialog === "photo" && photo)
    return (
      <PhotoDialog
        terminal={terminal}
        target={photo}
        refocus={refocus}
        onClose={close}
        onOutcome={onOutcome}
      />
    );
  return null;
}

/**
 * The terminal's Utilities button (wide layout): the Type & view items in
 * their own menu. Its Paste/Photo dialogs open in the panel's one
 * `UtilityDialogs`, so crossing the phone breakpoint (rotation) keeps them.
 */
export function TerminalUtilities({
  terminal,
  onDialog,
  ...items
}: Omit<UtilityItemsProps, "onDialog" | "onDone"> & {
  terminal: Pick<UtilitiesTerminal, "focus" | "hasFocus">;
  /** `refocus`: the terminal had focus (phone keyboard up) before the menu opened. */
  onDialog: (dialog: Exclude<UtilityDialog, null>, refocus: boolean) => void;
}) {
  const { t } = useTranslation(["terminal"]);
  const refocus = useRef(false);

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button
            type="button"
            size="touch"
            variant="outline"
            data-terminal-utilities=""
            onPointerDown={() => {
              refocus.current = terminal.hasFocus();
            }}
          />
        }
      >
        <Wrench aria-hidden="true" className="size-4" />
        {t("terminal:utilities.button")}
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        className="w-72 max-w-[calc(100vw-1rem)]"
        finalFocus={() => !refocus.current}
      >
        <UtilityMenuItems
          {...items}
          onDialog={(dialog) => onDialog(dialog, refocus.current)}
          onDone={() => {
            if (refocus.current) terminal.focus();
          }}
        />
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function PasteDialog({
  terminal,
  refocus,
  onClose,
  onOutcome,
}: {
  terminal: UtilitiesTerminal;
  refocus: boolean;
  onClose: () => void;
  onOutcome: (outcome: ClipboardOutcome) => void;
}) {
  const { t } = useTranslation(["terminal"]);
  const textId = useId();
  const enterId = useId();
  const [text, setText] = useState("");
  const [enter, setEnter] = useState(false);
  const [message, setMessage] = useState<{ key: string; tone: "ok" | "warn" } | null>(null);
  const lines = text === "" ? 0 : text.split(/\r\n|\r|\n/).length;
  const bytes = new TextEncoder().encode(text).byteLength;

  const readClipboard = async () => {
    setMessage(null);
    if (typeof navigator === "undefined" || !navigator.clipboard?.readText) {
      setMessage({ key: "terminal:pasteDialog.clipboardUnsupported", tone: "warn" });
      return;
    }
    try {
      const value = await navigator.clipboard.readText();
      if (!value) {
        setMessage({ key: "terminal:pasteDialog.clipboardEmpty", tone: "warn" });
        return;
      }
      setText(value);
      setMessage({ key: "terminal:pasteDialog.clipboardLoaded", tone: "ok" });
    } catch {
      setMessage({ key: "terminal:pasteDialog.clipboardBlocked", tone: "warn" });
    }
  };

  const send = () => {
    if (!text) {
      setMessage({ key: "terminal:pasteDialog.nothing", tone: "warn" });
      return;
    }
    const outcome = terminal.typeText(text);
    // Anything but a sent paste keeps the dialog and the draft, with the reason.
    if (outcome !== "done") {
      setMessage({
        key:
          outcome === "tooLarge"
            ? "terminal:clipboard.pasteTooLarge"
            : outcome === "empty"
              ? "terminal:pasteDialog.nothing"
              : "terminal:pasteDialog.notAttached",
        tone: "warn",
      });
      return;
    }
    if (enter) terminal.sendKeys("\r");
    onOutcome(outcome);
    onClose();
    if (refocus) terminal.focus();
  };

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())}>
      <DialogContent
        closeLabel={t("terminal:pasteDialog.close")}
        finalFocus={() => !refocus}
        data-terminal-paste-dialog=""
      >
        <DialogHeader>
          <DialogTitle>{t("terminal:pasteDialog.title")}</DialogTitle>
          <DialogDescription>{t("terminal:pasteDialog.description")}</DialogDescription>
        </DialogHeader>
        <div className="flex min-w-0 flex-col gap-3">
          <Label htmlFor={textId}>{t("terminal:pasteDialog.text")}</Label>
          <Textarea
            id={textId}
            rows={6}
            value={text}
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            placeholder={t("terminal:pasteDialog.placeholder")}
            className="font-mono"
            onChange={(event) => {
              setText(event.target.value);
              setMessage(null);
            }}
          />
          <div>
            <Button
              type="button"
              size="touch"
              variant="outline"
              data-paste-clipboard=""
              onClick={() => void readClipboard()}
            >
              <ClipboardPaste aria-hidden="true" className="size-4" />
              {t("terminal:pasteDialog.fromClipboard")}
            </Button>
          </div>
          {message ? (
            <p
              role="status"
              data-paste-message={message.tone}
              className={
                message.tone === "warn"
                  ? "text-sm text-amber-800 dark:text-amber-300"
                  : "text-sm text-muted-foreground"
              }
            >
              {t(message.key)}
            </p>
          ) : null}
          <p className="text-sm text-muted-foreground" data-paste-info="">
            {lines === 0
              ? t("terminal:pasteDialog.empty")
              : `${t("terminal:pasteDialog.size", { count: lines, bytes })} ${t(
                  terminal.bracketedPaste()
                    ? "terminal:pasteDialog.bracketed"
                    : "terminal:pasteDialog.unbracketed",
                )}`}
          </p>
          <div className="flex min-h-11 items-center gap-2">
            <Checkbox
              id={enterId}
              checked={enter}
              data-paste-enter=""
              onCheckedChange={(checked) => setEnter(checked === true)}
            />
            <Label htmlFor={enterId}>{t("terminal:pasteDialog.enterAfter")}</Label>
          </div>
        </div>
        <DialogFooter>
          <Button type="button" size="touch" variant="outline" onClick={onClose}>
            {t("terminal:pasteDialog.cancel")}
          </Button>
          <Button type="button" size="touch" data-paste-send="" onClick={send}>
            {t("terminal:pasteDialog.send")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** How long a photo's write into the VM is waited for before giving up. */
const PHOTO_WRITE_WAIT_MS = 60_000;
const PHOTO_POLL_MS = 1_000;

/** Longest edge of the dialog's thumbnail, in CSS px (drawn at 2×). */
const THUMBNAIL_PX = 64;

/**
 * A small `data:` JPEG of the photo, or null when the browser cannot decode
 * it. Not a `blob:` URL: the CSP allows images only from `'self'` and
 * `data:`. `createImageBitmap` decodes without any URL, and only the small
 * canvas is encoded.
 */
async function photoThumbnail(file: Blob): Promise<string | null> {
  if (typeof createImageBitmap !== "function") return null;
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    return null;
  }
  try {
    const scale = Math.min(1, (THUMBNAIL_PX * 2) / Math.max(bitmap.width, bitmap.height, 1));
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const context = canvas.getContext("2d");
    if (!context) return null;
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL("image/jpeg", 0.8);
  } catch {
    return null;
  } finally {
    bitmap.close();
  }
}

type PhotoPhase =
  | { kind: "idle" }
  | { kind: "uploading"; sent: number; total: number }
  | { kind: "writing" }
  /** In the sandbox, but the terminal could not take the path (not attached). */
  | { kind: "placed"; path: string }
  | { kind: "failed"; problem: TransferProblem | "writeFailed" | "writeSlow" };

function PhotoDialog({
  terminal,
  target,
  refocus,
  onClose,
  onOutcome,
}: {
  terminal: UtilitiesTerminal;
  target: PhotoTarget;
  refocus: boolean;
  onClose: () => void;
  onOutcome: (outcome: ClipboardOutcome) => void;
}) {
  const { t, i18n } = useTranslation(["terminal", "sandboxes"]);
  const nextController = useAbortOnUnmount();
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const picks = useRef(0);
  const [phase, setPhase] = useState<PhotoPhase>({ kind: "idle" });
  const busy = phase.kind === "uploading" || phase.kind === "writing";
  const badType = file !== null && !(file.type in PHOTO_TYPES);
  const tooLarge = file !== null && file.size > PHOTO_MAX_BYTES;

  const choose = (input: HTMLInputElement) => {
    const picked = input.files?.[0] ?? null;
    input.value = "";
    if (!picked) return;
    const pick = ++picks.current;
    setFile(picked);
    setPreview(null);
    setPhase({ kind: "idle" });
    if (picked.type in PHOTO_TYPES && picked.size <= PHOTO_MAX_BYTES)
      void photoThumbnail(picked).then((url) => {
        if (picks.current === pick) setPreview(url);
      });
  };

  const close = onClose;

  /** Type the photo's path: done closes the dialog, otherwise the path is kept for a retry. */
  const typePath = (path: string) => {
    // Like a coding agent expects: the quoted path and a space, as a paste.
    const outcome = terminal.typeText(`${shellQuote(path)} `);
    if (outcome !== "done") {
      setPhase({ kind: "placed", path });
      return;
    }
    onOutcome(outcome);
    close();
    if (refocus) terminal.focus();
  };

  const send = async () => {
    if (!file || badType || tooLarge || busy) return;
    const controller = nextController();
    const path = photoGuestPath(
      target.guestHome,
      file.type,
      new Date(),
      crypto.randomUUID().slice(0, 8),
    );
    setPhase({ kind: "uploading", sent: 0, total: file.size });
    let operationId: string;
    try {
      const receipt = await uploadToSandbox(
        { serverUrl: env.VITE_SERVER_URL },
        {
          sandboxId: target.sandboxId,
          guestPath: path,
          file,
          signal: controller.signal,
          onProgress: (sent, total) => setPhase({ kind: "uploading", sent, total }),
        },
      );
      operationId = receipt.operationId;
    } catch (error) {
      if (!controller.signal.aborted)
        setPhase({ kind: "failed", problem: toTransferProblem(error) });
      return;
    }
    // The commit is an operation: type the path only once the file is in the VM.
    setPhase({ kind: "writing" });
    const deadline = Date.now() + PHOTO_WRITE_WAIT_MS;
    for (;;) {
      let state: OperationState;
      try {
        state = (
          await orpc.sandboxes.getOperation.call({ operationId }, { signal: controller.signal })
        ).state;
      } catch (error) {
        if (!controller.signal.aborted)
          setPhase({ kind: "failed", problem: toTransferProblem(error) });
        return;
      }
      if (controller.signal.aborted) return;
      if (state === "SUCCEEDED") break;
      if (!isOperationActive(state)) {
        setPhase({ kind: "failed", problem: "writeFailed" });
        return;
      }
      if (Date.now() >= deadline) {
        setPhase({ kind: "failed", problem: "writeSlow" });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, PHOTO_POLL_MS));
      if (controller.signal.aborted) return;
    }
    typePath(path);
  };

  const problem =
    phase.kind === "failed"
      ? phase.problem === "writeFailed" || phase.problem === "writeSlow"
        ? t(`terminal:photo.${phase.problem}`)
        : t(`sandboxes:files.problem.${phase.problem}`)
      : null;

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : close())}>
      <DialogContent
        closeLabel={t("terminal:photo.close")}
        finalFocus={() => !refocus}
        data-terminal-photo-dialog=""
      >
        <DialogHeader>
          <DialogTitle>{t("terminal:photo.title")}</DialogTitle>
          <DialogDescription>
            {t("terminal:photo.description", {
              max: formatBytes(PHOTO_MAX_BYTES, i18n.language),
            })}
          </DialogDescription>
        </DialogHeader>
        <div className="flex min-w-0 flex-col gap-3">
          <div className="flex min-w-0 flex-wrap gap-2">
            <PhotoInput
              label={t("terminal:photo.choose")}
              icon={<ImagePlus aria-hidden="true" className="size-4" />}
              disabled={busy}
              data="choose"
              onPick={choose}
            />
            <PhotoInput
              label={t("terminal:photo.take")}
              icon={<Camera aria-hidden="true" className="size-4" />}
              disabled={busy}
              capture
              data="take"
              onPick={choose}
            />
          </div>
          {file ? (
            <div className="flex min-w-0 items-center gap-3" data-photo-picked="">
              {preview ? (
                <img
                  src={preview}
                  alt={t("terminal:photo.thumbnail")}
                  className="size-16 shrink-0 border object-cover"
                />
              ) : null}
              <div className="min-w-0 text-sm">
                <p className="truncate">{file.name || t("terminal:photo.unnamed")}</p>
                <p className="text-muted-foreground">{formatBytes(file.size, i18n.language)}</p>
              </div>
            </div>
          ) : null}
          {badType ? (
            <p role="alert" data-photo-problem="type" className="text-sm text-destructive">
              {t("terminal:photo.badType")}
            </p>
          ) : tooLarge ? (
            <p role="alert" data-photo-problem="size" className="text-sm text-destructive">
              {t("terminal:photo.tooLarge", { max: formatBytes(PHOTO_MAX_BYTES, i18n.language) })}
            </p>
          ) : null}
          {phase.kind === "uploading" ? (
            <p role="status" data-photo-phase="uploading" className="text-sm text-muted-foreground">
              {t("terminal:photo.uploading", {
                percent: phase.total ? Math.floor((phase.sent / phase.total) * 100) : 0,
              })}
            </p>
          ) : phase.kind === "writing" ? (
            <p role="status" data-photo-phase="writing" className="text-sm text-muted-foreground">
              {t("terminal:photo.writing")}
            </p>
          ) : null}
          {phase.kind === "placed" ? (
            <p role="status" data-photo-phase="placed" className="text-sm">
              {t("terminal:photo.placed")}{" "}
              <code className="break-all font-mono text-xs">{phase.path}</code>
            </p>
          ) : null}
          {problem ? (
            <p
              role="alert"
              data-photo-problem={phase.kind === "failed" ? phase.problem : undefined}
              className="text-sm text-destructive"
            >
              {problem}
            </p>
          ) : null}
        </div>
        <DialogFooter>
          <Button type="button" size="touch" variant="outline" onClick={close}>
            {t("terminal:photo.cancel")}
          </Button>
          {phase.kind === "placed" ? (
            <Button
              type="button"
              size="touch"
              data-photo-type-path=""
              onClick={() => typePath(phase.path)}
            >
              {t("terminal:photo.typePath")}
            </Button>
          ) : (
            <Button
              type="button"
              size="touch"
              data-photo-send=""
              disabled={!file || badType || tooLarge || busy}
              onClick={() => void send()}
            >
              {t("terminal:photo.send")}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** A file button: a real `<input type=file>` behind a 44 px label. */
function PhotoInput({
  label,
  icon,
  disabled,
  capture = false,
  data,
  onPick,
}: {
  label: string;
  icon: ReactNode;
  disabled: boolean;
  capture?: boolean;
  data: string;
  onPick: (input: HTMLInputElement) => void;
}) {
  const id = useId();
  return (
    <div className="relative">
      <input
        id={id}
        type="file"
        // `image/*`: iOS then hands HEIC photos over as JPEG.
        accept="image/*"
        capture={capture ? "environment" : undefined}
        disabled={disabled}
        data-photo-input={data}
        className="peer sr-only"
        onChange={(event) => onPick(event.currentTarget)}
      />
      <Label
        htmlFor={id}
        className="inline-flex min-h-11 cursor-pointer items-center gap-1.5 border px-3.5 text-xs font-medium peer-focus-visible:ring-2 peer-focus-visible:ring-ring peer-disabled:pointer-events-none peer-disabled:opacity-50"
      >
        {icon}
        {label}
      </Label>
    </div>
  );
}
