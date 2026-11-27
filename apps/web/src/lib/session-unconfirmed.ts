import { createContext, createElement, type ReactNode, useContext } from "react";

/** True inside a subtree that must not show who is signed in yet. */
const SessionUnconfirmedContext = createContext(false);

/**
 * Renders its subtree as if the session were still being checked, so
 * `useAuthSession()` reports `pending` there whatever Better Auth's atom
 * holds. The app shell's pending state (`AppShellPending`) uses it: it paints
 * before the session guards (`lib/route-session.ts`) have admitted anyone, and
 * a document entering the app from a public page can still hold the previous
 * account's session in the atom (another tab switched accounts meanwhile).
 * Anything in that frame that reads the session shows its pending state
 * instead of that account. docs/design/shell-rules.md § Query cache follows
 * identity.
 */
export function SessionUnconfirmed({ children }: { children: ReactNode }) {
  return createElement(SessionUnconfirmedContext.Provider, { value: true }, children);
}

export function useSessionUnconfirmed(): boolean {
  return useContext(SessionUnconfirmedContext);
}
