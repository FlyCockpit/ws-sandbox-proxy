#!/usr/bin/env node
// Dev-only webhook receiver for the live end-to-end check (docs/guide/webhooks.md
// § Local testing). Not shipped. No dependencies beyond the built SDK:
//   pnpm --filter @wssp/sdk build
//   WEBHOOK_SECRETS=whsec_new[,whsec_old] node scripts/webhook-receiver.mjs --port 8787
//     [--host 0.0.0.0] [--tls-cert cert.pem --tls-key key.pem] [--fail]
// Logs webhook-id, the verification result and the event type, and dedupes ids.
// `--fail` answers 503 to everything (exercises retries); toggle at runtime with
// SIGUSR1. Never logs a secret or a body.
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";

const { verifyWebhook, WebhookVerificationError } = await import(
  new URL("../packages/sdk/dist/webhooks.mjs", import.meta.url).href
);

const args = new Map();
for (let i = 2; i < process.argv.length; i++) {
  const flag = process.argv[i];
  if (flag === "--fail") args.set("fail", true);
  else args.set(flag.replace(/^--/, ""), process.argv[++i]);
}
const secrets = (process.env.WEBHOOK_SECRETS ?? "").split(",").filter(Boolean);
if (secrets.length === 0) {
  console.error("Set WEBHOOK_SECRETS to the endpoint's whsec_ secret(s).");
  process.exit(2);
}
let failing = args.get("fail") === true;
process.on("SIGUSR1", () => {
  failing = !failing;
  console.log(`[receiver] failing=${failing}`);
});

const seen = new Set();
function handle(req, res) {
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const id = req.headers["webhook-id"];
    const attempt = req.headers["wssp-delivery-attempt"];
    if (failing) {
      console.log(`[receiver] ${id} attempt=${attempt} -> 503 (failing)`);
      res.writeHead(503, { "retry-after": "5" }).end();
      return;
    }
    try {
      const event = verifyWebhook({
        body: Buffer.concat(chunks),
        headers: req.headers,
        secret: secrets,
      });
      const duplicate = seen.has(event.id);
      seen.add(event.id);
      console.log(
        `[receiver] ${event.id} type=${event.type} attempt=${attempt} verified=yes duplicate=${duplicate}`,
      );
      res.writeHead(204).end();
    } catch (error) {
      const code = error instanceof WebhookVerificationError ? error.code : "error";
      console.log(`[receiver] ${id ?? "-"} verified=no (${code})`);
      res.writeHead(400).end();
    }
  });
}

const port = Number(args.get("port") ?? 8787);
const host = args.get("host") ?? "0.0.0.0";
const server =
  args.get("tls-cert") && args.get("tls-key")
    ? https.createServer(
        { cert: readFileSync(args.get("tls-cert")), key: readFileSync(args.get("tls-key")) },
        handle,
      )
    : http.createServer(handle);
server.listen(port, host, () => console.log(`[receiver] listening on ${host}:${port}`));
