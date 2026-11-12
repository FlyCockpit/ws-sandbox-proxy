import en from "../locales/en-US/pool-share.json";
import es from "../locales/es-MX/pool-share.json";
import { resolveMailerLocale } from "../locales/index.js";
import { escapeHtml, safeHref } from "./html.js";

export function renderPoolShare(args: {
  locale: string;
  url: string;
  inviter: string;
  pool: string;
  invite: {
    canUse: boolean;
    canContribute: boolean;
    maxMemoryMiB: number | null;
    maxVcpu: number | null;
    maxDiskGiB: number | null;
    expiresAt: Date;
  };
}) {
  const locale = resolveMailerLocale(args.locale);
  const bundle = locale === "es-MX" ? es : en;
  const vars: Record<string, string> = {
    inviter: args.inviter,
    pool: args.pool,
    use: args.invite.canUse ? bundle.yes : bundle.no,
    contribute: args.invite.canContribute ? bundle.yes : bundle.no,
    memory: String(args.invite.maxMemoryMiB ?? bundle.unlimited),
    vcpu: String(args.invite.maxVcpu ?? bundle.unlimited),
    disk: String(args.invite.maxDiskGiB ?? bundle.unlimited),
    expiry:
      new Intl.DateTimeFormat(locale, {
        dateStyle: "long",
        timeStyle: "short",
        timeZone: "UTC",
      }).format(args.invite.expiresAt) + " UTC",
  };
  const t = (key: keyof typeof en) =>
    bundle[key].replace(/\{\{(\w+)\}\}/g, (_, name: string) => escapeHtml(vars[name] ?? ""));
  return {
    subject: bundle.subject,
    html: `<!DOCTYPE html><html lang="${locale}"><head><meta charset="utf-8" /></head><body style="margin:0;padding:40px;background:#f4f4f5;font-family:Arial,sans-serif"><table cellpadding="0" cellspacing="0" style="max-width:480px;background:#fff;padding:40px"><tr><td><h1>${t("heading")}</h1>${(["body", "permissions", "caps", "expiry", "trust", "forwarding"] as const).map((key) => `<p>${t(key)}</p>`).join("")}<a href="${safeHref(args.url)}">${t("cta")}</a></td></tr></table></body></html>`,
  };
}
