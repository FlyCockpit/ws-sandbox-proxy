import en from "../locales/en-US/pool-access.json";
import es from "../locales/es-MX/pool-access.json";
import { resolveMailerLocale } from "../locales/index.js";
import { escapeHtml } from "./html.js";

/** Loss/restore notices use the committed access transition and its pinned deadline. */
export function renderPoolAccessNotice(args: {
  locale: string;
  sandboxId: string;
  kind: "loss" | "restore";
  deadline: Date;
}) {
  const locale = resolveMailerLocale(args.locale),
    bundle = locale === "es-MX" ? es : en;
  const subject = args.kind === "loss" ? bundle.lossSubject : bundle.restoreSubject;
  const body = bundle[args.kind]
    .replace("{{sandbox}}", escapeHtml(args.sandboxId))
    .replace("{{deadline}}", escapeHtml(args.deadline.toISOString()));
  return {
    subject,
    html: `<!DOCTYPE html><html lang="${locale}"><head><meta charset="utf-8" /></head><body style="padding:40px;background:#f4f4f5;font-family:Arial,sans-serif"><table style="max-width:480px;background:#fff;padding:40px"><tr><td><h1>${subject}</h1><p>${body}</p><p>${bundle.notice}</p></td></tr></table></body></html>`,
  };
}
