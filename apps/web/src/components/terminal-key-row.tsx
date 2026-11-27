import { cn } from "@wssp/ui/lib/utils";
import {
  type CSSProperties,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
  type PointerEvent as ReactPointerEvent,
  useRef,
  useState,
} from "react";
import { useTranslation } from "react-i18next";

import { useTerminalLatches } from "@/hooks/use-terminal-utilities";
import {
  type ArrowKey,
  encodeKey,
  GRID_KEYS,
  gridLayout,
  HoldGesture,
  type LatchState,
  type ModifierName,
  SwipeTracker,
} from "@/lib/terminal-keys";

/** What the row needs from the terminal session. */
export type KeyRowTerminal = {
  sendKeys: (data: string) => boolean;
  focus: () => void;
  hasFocus: () => boolean;
  applicationCursorKeys: () => boolean;
  setKeyFilter: (filter: ((data: string) => string) | null) => void;
};

const ARROW_GLYPH: Record<ArrowKey, string> = { Up: "↑", Down: "↓", Left: "←", Right: "→" };
/** Shell meanings shown under grid letters (readline / job control). */
const CTRL_HINTS: Record<string, string> = {
  a: "home",
  c: "stop",
  d: "eof",
  e: "end",
  k: "kill",
  l: "clear",
  r: "search",
  u: "killLine",
  w: "word",
  z: "suspend",
};
const ALT_HINTS: Record<string, string> = {
  b: "wordBack",
  f: "wordForward",
  d: "deleteWord",
  ".": "lastArg",
};

const keyClass =
  "flex min-h-11 min-w-11 flex-col items-center justify-center border bg-muted px-2 text-sm font-medium text-foreground select-none touch-none active:bg-accent data-[latch=once]:bg-primary/20 data-[latch=once]:border-primary data-[latch=lock]:bg-primary data-[latch=lock]:text-primary-foreground";

/**
 * The on-screen key row (design D): Esc, Tab, Ctrl, Alt and a swipe pad.
 * Keys never take focus from the terminal (pointerdown is cancelled), so the
 * phone keyboard stays open. Tap Ctrl/Alt to latch it for the next key
 * (double-tap locks); hold it to open a letter grid, slide to a key and lift
 * to send that combination. The pad sends one arrow per 20 px of swipe,
 * following the program's application cursor mode.
 */
export function TerminalKeyRow({
  terminal,
  className,
  style,
}: {
  terminal: KeyRowTerminal;
  className?: string;
  style?: CSSProperties;
}) {
  const { t } = useTranslation(["terminal"]);
  const {
    latches,
    tap: onTapModifier,
    take,
  } = useTerminalLatches({
    setKeyFilter: terminal.setKeyFilter,
    applicationCursorKeys: terminal.applicationCursorKeys,
  });
  const [grid, setGrid] = useState<{ name: ModifierName; hot: string | null } | null>(null);
  const [layout, setLayout] = useState({ columns: 7, cell: 44 });
  const rowRef = useRef<HTMLDivElement | null>(null);
  const showGrid = (next: { name: ModifierName; hot: string | null } | null) => {
    if (next && !grid && rowRef.current) {
      // Fit the grid between the top of the visible page and the row.
      const rect = rowRef.current.getBoundingClientRect();
      const top = window.visualViewport?.offsetTop ?? 0;
      setLayout(gridLayout(rect.top - top - 4, rect.width));
    }
    setGrid(next);
  };

  /** A row key: latched modifiers apply, then one-shot ones clear. */
  const press = (key: string) => {
    terminal.sendKeys(encodeKey(key, take(), terminal.applicationCursorKeys()));
  };

  return (
    <div ref={rowRef} className={cn("relative min-w-0", className)} style={style}>
      {grid ? (
        <div
          role="menu"
          aria-label={t(`terminal:keys.grid.${grid.name}`)}
          data-terminal-key-grid={grid.name}
          className="absolute inset-x-0 bottom-full z-20 mb-1 border bg-popover p-2 text-popover-foreground shadow-md"
        >
          <p className="mb-1 truncate text-xs leading-5 text-muted-foreground">
            {t(`terminal:keys.grid.${grid.name}`)}
          </p>
          {/* Columns and cell height from gridLayout: 44 px wide, 44 px tall when it fits. */}
          <div
            className="grid gap-1"
            style={{ gridTemplateColumns: `repeat(${layout.columns}, minmax(0, 1fr))` }}
          >
            {GRID_KEYS.map((key) => {
              const hint = (grid.name === "ctrl" ? CTRL_HINTS : ALT_HINTS)[key];
              return (
                <div
                  key={key}
                  role="menuitem"
                  data-grid-key={key}
                  data-hot={grid.hot === key ? "" : undefined}
                  style={{ minHeight: layout.cell }}
                  className="flex min-w-0 flex-col items-center justify-center border bg-muted font-mono text-sm data-hot:bg-primary data-hot:text-primary-foreground"
                >
                  <span>{key}</span>
                  {hint ? (
                    <span className="max-w-full truncate text-xs leading-none text-muted-foreground">
                      {t(`terminal:keys.hint.${hint}`)}
                    </span>
                  ) : null}
                </div>
              );
            })}
          </div>
        </div>
      ) : null}
      <div
        role="toolbar"
        aria-label={t("terminal:keys.label")}
        data-terminal-keys=""
        className="flex min-w-0 gap-0.5"
      >
        <TapKey terminal={terminal} name="Esc" onTap={() => press("Esc")} />
        <TapKey terminal={terminal} name="Tab" onTap={() => press("Tab")} />
        {(["ctrl", "alt"] as const).map((name) => (
          <HoldModifierKey
            key={name}
            name={name}
            latch={latches[name]}
            terminal={terminal}
            onTap={() => onTapModifier(name)}
            onGrid={showGrid}
            onSend={(key) => terminal.sendKeys(encodeKey(key, { [name]: true }))}
          />
        ))}
        <SwipePad terminal={terminal} onArrow={press} />
      </div>
    </div>
  );
}

/** Remember whether the terminal had focus and keep it there. */
function keepFocus(terminal: KeyRowTerminal, event: ReactPointerEvent | ReactMouseEvent) {
  event.preventDefault();
  return terminal.hasFocus();
}

function TapKey({
  terminal,
  name,
  onTap,
}: {
  terminal: KeyRowTerminal;
  name: "Esc" | "Tab";
  onTap: () => void;
}) {
  const { t } = useTranslation(["terminal"]);
  const hadFocus = useRef(false);
  return (
    <button
      type="button"
      data-terminal-key={name}
      className={cn(keyClass, "shrink-0")}
      onPointerDown={(event) => {
        hadFocus.current = keepFocus(terminal, event);
      }}
      onMouseDown={(event) => event.preventDefault()}
      onContextMenu={(event) => event.preventDefault()}
      onClick={() => {
        onTap();
        if (hadFocus.current) terminal.focus();
      }}
    >
      {t(name === "Esc" ? "terminal:keys.name.esc" : "terminal:keys.name.tab")}
    </button>
  );
}

function HoldModifierKey({
  name,
  latch,
  terminal,
  onTap,
  onGrid,
  onSend,
}: {
  name: ModifierName;
  latch: LatchState;
  terminal: KeyRowTerminal;
  onTap: () => void;
  onGrid: (grid: { name: ModifierName; hot: string | null } | null) => void;
  onSend: (key: string) => void;
}) {
  const { t } = useTranslation(["terminal"]);
  const hadFocus = useRef(false);
  // The gesture outlives renders; its callbacks read the latest props.
  const onGridRef = useRef(onGrid);
  const onTapRef = useRef(onTap);
  const onSendRef = useRef(onSend);
  onGridRef.current = onGrid;
  onTapRef.current = onTap;
  onSendRef.current = onSend;
  const [gesture] = useState(
    () =>
      new HoldGesture({
        onOpen: () => {
          onGridRef.current({ name, hot: null });
          try {
            navigator.vibrate?.(10);
          } catch {
            // Vibration is optional.
          }
        },
        onClose: () => onGridRef.current(null),
        onTap: () => {
          onTapRef.current();
          if (hadFocus.current) terminal.focus();
        },
        onSend: (key) => {
          onSendRef.current(key);
          if (hadFocus.current) terminal.focus();
        },
      }),
  );

  return (
    <button
      type="button"
      data-terminal-key={name === "ctrl" ? "Ctrl" : "Alt"}
      data-latch={latch}
      aria-pressed={latch !== "off"}
      aria-label={t(`terminal:keys.modifier.${name}`, { state: t(`terminal:keys.latch.${latch}`) })}
      // Fixed width: a latch label never widens the key and squeezes the pad.
      className={cn(keyClass, "w-12 shrink-0 px-0.5 leading-tight")}
      onPointerDown={(event) => {
        hadFocus.current = keepFocus(terminal, event);
        try {
          event.currentTarget.setPointerCapture(event.pointerId);
        } catch {
          // Synthetic pointers cannot be captured.
        }
        gesture.down();
      }}
      onPointerMove={(event) => {
        if (!gesture.open) return;
        const target = document.elementFromPoint(event.clientX, event.clientY);
        const cell = target?.closest<HTMLElement>("[data-grid-key]");
        const key = cell?.dataset.gridKey ?? null;
        if (key !== gesture.highlighted) {
          gesture.over(key);
          onGrid({ name, hot: key });
        }
      }}
      onPointerUp={() => gesture.up()}
      onPointerCancel={() => gesture.cancel()}
      onMouseDown={(event) => event.preventDefault()}
      onContextMenu={(event) => event.preventDefault()}
      onKeyDown={(event) => {
        // Keyboard users latch with Enter/Space (no hold).
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onTap();
        }
      }}
    >
      <span>{t(`terminal:keys.name.${name}`)}</span>
      <span className="max-w-full whitespace-nowrap text-xs leading-none font-normal text-muted-foreground">
        {latch === "once"
          ? t("terminal:keys.latch.onceShort")
          : t(`terminal:keys.latch.${latch === "off" ? "hold" : latch}`)}
      </span>
    </button>
  );
}

function SwipePad({
  terminal,
  onArrow,
}: {
  terminal: KeyRowTerminal;
  onArrow: (key: ArrowKey) => void;
}) {
  const { t } = useTranslation(["terminal"]);
  const tracker = useRef(new SwipeTracker());
  const hadFocus = useRef(false);
  const [last, setLast] = useState<{ key: ArrowKey; count: number } | null>(null);
  let content: ReactNode = t("terminal:keys.swipe");
  if (last) content = `${ARROW_GLYPH[last.key]} ×${last.count}`;
  const announced = last
    ? t("terminal:keys.swiped", {
        direction: t(`terminal:keys.direction.${last.key}`),
        count: last.count,
      })
    : t("terminal:keys.swipe");
  return (
    <div
      role="slider"
      aria-label={t("terminal:keys.swipeLabel")}
      aria-valuetext={announced}
      aria-valuenow={last?.count ?? 0}
      tabIndex={-1}
      data-terminal-swipe=""
      className="flex min-h-11 min-w-11 flex-1 items-center justify-center overflow-hidden border border-dashed bg-muted/50 px-1 text-xs text-muted-foreground select-none touch-none"
      onPointerDown={(event) => {
        hadFocus.current = keepFocus(terminal, event);
        try {
          event.currentTarget.setPointerCapture(event.pointerId);
        } catch {
          // Synthetic pointers cannot be captured.
        }
        tracker.current.start(event.clientX, event.clientY);
        setLast(null);
      }}
      onPointerMove={(event) => {
        const keys = tracker.current.move(event.clientX, event.clientY);
        if (keys.length === 0) return;
        for (const key of keys) onArrow(key);
        const key = keys.at(-1) as ArrowKey;
        setLast((previous) => ({
          key,
          count: (previous?.key === key ? previous.count : 0) + keys.length,
        }));
      }}
      onPointerUp={() => {
        tracker.current.end();
        if (hadFocus.current) terminal.focus();
      }}
      onPointerCancel={() => tracker.current.end()}
      onMouseDown={(event) => event.preventDefault()}
    >
      <span className="truncate">{content}</span>
    </div>
  );
}
