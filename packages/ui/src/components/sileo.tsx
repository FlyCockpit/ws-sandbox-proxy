import { useEffect, useLayoutEffect, useRef } from "react";
import { type SileoState, Toaster as SileoToaster, sileo } from "sileo";
import "sileo/styles.css";

type ToastKind = "message" | "success" | "error" | "info" | "warning";

const toastActions = new Map<string, () => void>();
const useIsomorphicLayoutEffect = typeof window !== "undefined" ? useLayoutEffect : useEffect;

/** @internal Shared with Toaster click delegation, which invokes the action when the toast control is activated. */
export function invokeToastAction(id: string): void {
  toastActions.get(id)?.();
}

/**
 * Renders the toast action inside `description` as a non-interactive pill so
 * `sileo`'s root `<button data-sileo-toast>` stays a single control with no
 * nested interactive descendants inside it, while preserving the full
 * accessible name on that `<button>`.
 */
function ToastAction({
  id,
  state,
  title,
  label,
  onClick,
}: {
  id: string;
  state: SileoState;
  title: string;
  label: string;
  onClick: () => void;
}) {
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    toastActions.set(id, onClick);
    return () => {
      if (toastActions.get(id) === onClick) toastActions.delete(id);
    };
  }, [id, onClick]);

  useIsomorphicLayoutEffect(() => {
    const toastEl = ref.current?.closest("[data-sileo-toast]");
    if (!toastEl) return;
    toastEl.setAttribute("aria-label", title ? `${title} — ${label}` : label);
    return () => {
      toastEl.removeAttribute("aria-label");
    };
  }, [title, label]);

  return (
    <span ref={ref} data-sileo-button="" data-state={state} data-toast-action-id={id}>
      {label}
    </span>
  );
}

/**
 * Sileo draws its pill inside a fixed 350px SVG (`--sileo-width`) and never
 * wraps the title; globals.css caps the header row and ellipsises a longer
 * title. A message that would be cut off moves into the wrapping description
 * and the pill shows a short per-kind title instead. Whether it fits depends
 * on the glyphs and the root font size (the app scales up on large screens),
 * not on a character count, so it is measured at the title's font. Where
 * nothing can be measured (SSR, tests without canvas) a length rule stands in.
 */
const SILEO_WIDTH_PX = 350;
const MAX_PILL_TITLE_CHARS = 40;

/** Room for the title: the pill minus sileo's 10px padding, the 24px badge,
 *  the header's 0.5rem padding on each side and the 0.5rem gap (all at `rootPx`). */
export function pillTitleBudget(rootPx: number): number {
  return SILEO_WIDTH_PX - 10 - 24 - rootPx * 1.5;
}

type TitleMeasure = (message: string) => { width: number; budget: number } | null;

let measureContext: CanvasRenderingContext2D | null | undefined;
const measureTitle: TitleMeasure = (message) => {
  if (typeof document === "undefined") return null;
  if (measureContext === undefined) {
    try {
      measureContext = document.createElement("canvas").getContext("2d");
    } catch {
      measureContext = null;
    }
  }
  if (!measureContext) return null;
  const rootPx = Number.parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
  const family = getComputedStyle(document.body).fontFamily || "sans-serif";
  // sileo's title: 0.825rem, weight 500.
  measureContext.font = `500 ${0.825 * rootPx}px ${family}`;
  return { width: measureContext.measureText(message).width, budget: pillTitleBudget(rootPx) };
};

/** True when the message would be cut off in the pill. A 5% margin covers
 *  sub-pixel and font-loading differences. Exported for the tests. */
export function titleOverflowsPill(message: string, measure: TitleMeasure = measureTitle): boolean {
  const measured = measure(message);
  if (!measured) return message.length > MAX_PILL_TITLE_CHARS;
  return measured.width > measured.budget * 0.95;
}

let kindTitles: Partial<Record<ToastKind, string>> = {};

interface ToasterProps {
  /** Translated short pill titles used when a message is too long for the pill. */
  titles?: Record<ToastKind, string>;
  position?:
    | "top-left"
    | "top-center"
    | "top-right"
    | "bottom-left"
    | "bottom-center"
    | "bottom-right";
}

/**
 * Sileo draws each toast's shape as an SVG titled "sileo notification" inside
 * the toast's button, so every toast's accessible name started with those
 * words, and its state icons carry English titles ("Check", "X"). The toast's
 * own title and description are its name; hide the decorative SVGs from
 * assistive technology as Sileo renders them.
 */
export function hideDecorativeSvgs(root: ParentNode): void {
  for (const svg of root.querySelectorAll("[data-sileo-viewport] svg")) {
    if (svg.getAttribute("aria-hidden") !== "true") svg.setAttribute("aria-hidden", "true");
  }
}

// No `theme`: sileo's themes invert the page (a light pill on a dark app).
// The toast takes the app's popover tokens from globals.css instead, so it
// follows `.dark` like every other surface, with no JS theme state.
const Toaster = ({ position = "bottom-center", titles, ...props }: ToasterProps) => {
  const rootRef = useRef<HTMLDivElement>(null);
  if (titles) kindTitles = titles;

  useEffect(() => {
    const root = rootRef.current;
    if (!root || typeof MutationObserver === "undefined") return;
    hideDecorativeSvgs(root);
    const observer = new MutationObserver(() => hideDecorativeSvgs(root));
    observer.observe(root, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, []);

  return (
    // `contents`: no box of its own, so Sileo's fixed viewports lay out as before.
    <div
      ref={rootRef}
      className="contents"
      data-toaster-root=""
      onClick={(event) => {
        const toastEl = (event.target as Element | null)?.closest("[data-sileo-toast]");
        if (!toastEl || toastEl.getAttribute("data-exiting") === "true") return;
        const actionId = toastEl
          .querySelector("[data-toast-action-id]")
          ?.getAttribute("data-toast-action-id");
        if (!actionId) return;
        event.preventDefault();
        event.stopPropagation();
        invokeToastAction(actionId);
      }}
    >
      <SileoToaster position={position} {...props} />
    </div>
  );
};

type ToastOptions = {
  duration?: number;
  action?: {
    label: string;
    onClick: () => void;
  };
};

// sileo keys toasts by `id` and defaults every one to "sileo-default", so a
// second toast replaced (morphed into) the first: two messages merged into
// one pill and the first was lost. Each toast gets its own id, so they stack.
let toastCount = 0;
const nextToastId = () => `toast-${++toastCount}`;

/** The pill title and description for a message (see titleOverflowsPill). */
function toastText(kind: ToastKind, message: string): { title: string; description?: string } {
  if (!titleOverflowsPill(message)) return { title: message };
  // No translated short title (no Toaster `titles`): keep the message as the
  // title, which globals.css ellipsises inside the pill, and repeat it in full
  // in the description so nothing is lost.
  return { title: kindTitles[kind] ?? message, description: message };
}

function createToastMethod(kind: ToastKind) {
  const method = kind === "message" ? "show" : kind;
  const sileoState: SileoState = kind === "message" ? "success" : kind;
  return (message: string, options?: ToastOptions): string => {
    const id = nextToastId();
    const { title, description: text } = toastText(kind, message);
    const action = options?.action;
    if (action && typeof window !== "undefined") {
      toastActions.set(id, action.onClick);
    }
    const actionNode = action ? (
      <ToastAction
        id={id}
        state={sileoState}
        title={text ?? title}
        label={action.label}
        onClick={action.onClick}
      />
    ) : null;
    const description = actionNode ? (
      text ? (
        <>
          {text}
          {actionNode}
        </>
      ) : (
        actionNode
      )
    ) : (
      text
    );
    // `id` is read by sileo at runtime but missing from its published types.
    return sileo[method]({
      id,
      title,
      ...(description !== undefined ? { description } : {}),
      ...(options?.duration != null ? { duration: options.duration } : {}),
    } as Parameters<typeof sileo.show>[0]);
  };
}

const toast = {
  /** Neutral, polite notice — no success/error severity styling. */
  message: createToastMethod("message"),
  success: createToastMethod("success"),
  error: createToastMethod("error"),
  info: createToastMethod("info"),
  warning: createToastMethod("warning"),
  dismiss: sileo.dismiss,
  clear: () => {
    toastActions.clear();
    sileo.clear();
  },
};

export { Toaster, toast };
