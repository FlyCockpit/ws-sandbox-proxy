import { expect, it } from "vitest";
import en from "../locales/en-US/webhook-endpoint-disabled.json";
import es from "../locales/es-MX/webhook-endpoint-disabled.json";
import { renderWebhookEndpointDisabled } from "./webhook-endpoint-disabled";

it.each(["en-US", "es-MX", "fr-FR"])("%s disable notice names only the escaped host", (locale) => {
  const mail = renderWebhookEndpointDisabled({
    locale,
    host: "<hooks.example.com>",
    consecutiveFailures: 21,
  });
  expect(mail.html).toContain("&lt;hooks.example.com&gt;");
  expect(mail.html).not.toContain("<hooks.example.com>");
  expect(mail.html).toContain("21");
  expect(mail.html).not.toContain("{{");
  expect(mail.subject).toBe(locale === "es-MX" ? es.subject : en.subject);
  expect(Object.keys(es)).toEqual(Object.keys(en));
});
