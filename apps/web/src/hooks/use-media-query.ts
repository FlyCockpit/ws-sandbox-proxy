import { useSyncExternalStore } from "react";

/** Matches Tailwind `md` and `useIsMobile()` (`min-width: 768px`). */
export const MOBILE_BREAKPOINT_PX = 768;
export const DESKTOP_MEDIA_QUERY = `(min-width: ${MOBILE_BREAKPOINT_PX}px)`;

export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (callback) => {
      // Absent in some test DOMs: nothing ever matches there.
      if (typeof window.matchMedia !== "function") return () => {};
      const mql = window.matchMedia(query);
      mql.addEventListener("change", callback);
      return () => mql.removeEventListener("change", callback);
    },
    () => typeof window.matchMedia === "function" && window.matchMedia(query).matches,
    () => false,
  );
}

export function useIsMobile(): boolean {
  return !useMediaQuery(DESKTOP_MEDIA_QUERY);
}

export function useIsDesktop(): boolean {
  return useMediaQuery(DESKTOP_MEDIA_QUERY);
}
