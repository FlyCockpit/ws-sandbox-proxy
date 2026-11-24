import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import {
  clampFontSize,
  FONT_SIZE_DEFAULT,
  FONT_SIZE_MAX,
  FONT_SIZE_MIN,
} from "@/lib/terminal-keys";

/**
 * Terminal utilities choices, remembered per device (this browser's
 * localStorage), never synced to the account: a phone and a desktop want
 * different text sizes and keys.
 */
interface TerminalPreferencesState {
  /** The on-screen key row (Esc, Tab, Ctrl, Alt, swipe pad). Hidden by default. */
  keysShown: boolean;
  /** Text size in px; null is the view's default. */
  fontSize: number | null;
  setKeysShown: (shown: boolean) => void;
  setFontSize: (size: number | null) => void;
}

function validFontSize(value: unknown): number | null {
  return typeof value === "number" &&
    Number.isInteger(value) &&
    value >= FONT_SIZE_MIN &&
    value <= FONT_SIZE_MAX
    ? value
    : null;
}

export const useTerminalPreferences = create<TerminalPreferencesState>()(
  persist(
    (set) => ({
      keysShown: false,
      fontSize: null,
      setKeysShown: (keysShown) => set({ keysShown }),
      setFontSize: (size) => {
        const next = size === null ? null : clampFontSize(size);
        set({ fontSize: next === FONT_SIZE_DEFAULT ? null : next });
      },
    }),
    {
      name: "terminal-preferences",
      version: 1,
      storage: createJSONStorage(() => localStorage),
      partialize: ({ keysShown, fontSize }) => ({ keysShown, fontSize }),
      // Stored values are untrusted (hand-edited, another build): keep only valid ones.
      merge: (persisted, current) => {
        const stored = (persisted ?? {}) as { keysShown?: unknown; fontSize?: unknown };
        return {
          ...current,
          keysShown: stored.keysShown === true,
          fontSize: validFontSize(stored.fontSize),
        };
      },
    },
  ),
);

/** The size the terminal uses now. */
export function effectiveFontSize(fontSize: number | null): number {
  return fontSize ?? FONT_SIZE_DEFAULT;
}
