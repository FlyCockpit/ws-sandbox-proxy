import en from "../locales/en-US/webhook-endpoint-disabled.json";
import es from "../locales/es-MX/webhook-endpoint-disabled.json";
import { resolveMailerLocale } from "../locales/index.js";
import { escapeHtml } from "./html.js";

/**
 * Sent at most once per sustained-failure disable. Carries the destination
 * HOST only: never the URL path, query, a secret or any payload.
 */
export function renderWebhookEndpointDisabled(args: {
  locale: string;
  host: string;
  consecutiveFailures: number;
}) {
  const locale = resolveMailerLocale(args.locale),
    bundle = locale === "es-MX" ? es : en;
  const body = bundle.body
    .replace("{{host}}", escapeHtml(args.host))
    .replace("{{failures}}", escapeHtml(String(args.consecutiveFailures)));
  return {
    subject: bundle.subject,
    html: `<!DOCTYPE html><html lang="${locale}"><head><meta charset="utf-8" /></head><body style="padding:40px;background:#f4f4f5;font-family:Arial,sans-serif"><table style="max-width:480px;background:#fff;padding:40px"><tr><td><h1>${escapeHtml(bundle.subject)}</h1><p>${body}</p><p>${escapeHtml(bundle.action)}</p></td></tr></table></body></html>`,
  };
}
