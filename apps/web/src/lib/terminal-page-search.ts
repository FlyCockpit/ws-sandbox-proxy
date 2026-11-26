/** The Terminals page's filter, in the URL as `?kind=` (All stays off the URL). */
export const TERMINAL_KIND_FILTERS = ["all", "sandbox", "host"] as const;
export type TerminalKindFilter = (typeof TERMINAL_KIND_FILTERS)[number];
export type TerminalsSearch = { kind?: Exclude<TerminalKindFilter, "all"> };

/** How many running sandboxes and hosts the "Open a new terminal" picker lists. */
export const NEW_TERMINAL_TARGETS_LIMIT = 20;

export function parseTerminalsSearch(search: Record<string, unknown>): TerminalsSearch {
  return search.kind === "sandbox" || search.kind === "host" ? { kind: search.kind } : {};
}
