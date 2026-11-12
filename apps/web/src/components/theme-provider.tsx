import { ThemeProvider as NextThemesProvider } from "next-themes";
import * as React from "react";

/**
 * next-themes always renders its own inline pre-paint `<script>` and has no
 * option to omit it. Our CSP (`script-src 'self' 'nonce-…' 'sha256-…'`) only
 * allows the app's own THEME_INIT_SCRIPT (inlined first in <head> by
 * __root.tsx and hash-allowlisted at server boot), which already applies the
 * stored/system theme before first paint — so next-themes' copy is redundant
 * and, executable, a CSP violation. A non-JavaScript `type` makes it an inert
 * data block: the browser never executes it, so CSP never evaluates it.
 * next-themes spreads `scriptProps` onto the element, so this sticks.
 */
export const INERT_THEME_SCRIPT_TYPE = "application/x-wssp-inert";

export function ThemeProvider({
  children,
  ...props
}: Omit<React.ComponentProps<typeof NextThemesProvider>, "scriptProps" | "nonce">) {
  return (
    <NextThemesProvider {...props} scriptProps={{ type: INERT_THEME_SCRIPT_TYPE }}>
      {children}
    </NextThemesProvider>
  );
}

export { useTheme } from "next-themes";
