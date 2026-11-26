import { useEffect, useRef } from "react";
import { Toaster as SileoToaster, sileo } from "sileo";
import "sileo/styles.css";

type ToastKind = "message" | "success" | "error" | "info" | "warning";

/**
 * Sileo draws its pill at a fixed 350px and never wraps the title, so a long
 * message spills past the pill. Past this length the message moves into the
 * wrapping description and the pill shows a short per-kind title instead.
 */
const MAX_PILL_TITLE_CHARS = 40;

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
    <div ref={rootRef} className="contents" data-toaster-root="">
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

function createToastMethod(kind: ToastKind) {
  const method = kind === "message" ? "show" : kind;
  return (message: string, options?: ToastOptions) => {
    const kindTitle = kindTitles[kind];
    const tooLong = message.length > MAX_PILL_TITLE_CHARS && kindTitle != null;
    return sileo[method]({
      ...(tooLong ? { title: kindTitle, description: message } : { title: message }),
      ...(options?.duration != null ? { duration: options.duration } : {}),
      ...(options?.action
        ? { button: { title: options.action.label, onClick: options.action.onClick } }
        : {}),
    });
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
  clear: sileo.clear,
};

export { Toaster, toast };
