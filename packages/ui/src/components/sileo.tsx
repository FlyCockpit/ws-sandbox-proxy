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

// No `theme`: sileo's themes invert the page (a light pill on a dark app).
// The toast takes the app's popover tokens from globals.css instead, so it
// follows `.dark` like every other surface, with no JS theme state.
const Toaster = ({ position = "bottom-center", titles, ...props }: ToasterProps) => {
  if (titles) kindTitles = titles;

  return <SileoToaster position={position} {...props} />;
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
