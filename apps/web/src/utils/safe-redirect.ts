import { appHomeHref } from "@/lib/app-home";

/**
 * Validate a `redirectTo` search param so it can only point back into the
 * current locale's own routes (never to an external origin, never back to the
 * auth pages themselves). Falls back to the locale's signed-in home
 * (lib/app-home.ts).
 */
export function safeRedirectTo(value: unknown, lang: string): string {
  if (typeof value !== "string") return appHomeHref(lang);
  if (!value.startsWith(`/${lang}/`)) return appHomeHref(lang);
  if (value.startsWith(`/${lang}/login`)) return appHomeHref(lang);
  if (value.startsWith(`/${lang}/signup`)) return appHomeHref(lang);
  return value;
}
