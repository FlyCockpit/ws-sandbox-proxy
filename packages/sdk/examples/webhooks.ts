import { createServer } from "node:http";
import { createWsspClient } from "@wssp/sdk";
import { verifyWebhook, WebhookVerificationError } from "@wssp/sdk/webhooks";

// 1. Register an endpoint with a key that has `webhooks:write` (an all-owned,
//    all-usable key). The signing secret is returned ONCE: store it now.
const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});
const { endpoint, secret } = await wssp.webhooks.endpoints.create({
  url: "https://hooks.example.com/wssp",
  events: ["sandbox.ready", "sandbox.create_failed", "operation.completed"],
});
console.log(`endpoint ${endpoint.id}; save the secret in your secret store`);
await wssp.webhooks.endpoints.test(endpoint.id); // a signed `webhook.test` delivery

// 2. Receive. Verify the RAW body bytes, dedupe by `webhook-id` (delivery is
//    at-least-once and unordered), answer 2xx fast, and process later.
const seen = new Set<string>(); // use a durable store with a ≥ 24 h TTL in production
createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (chunk: Buffer) => chunks.push(chunk));
  req.on("end", () => {
    try {
      const event = verifyWebhook({
        body: Buffer.concat(chunks),
        headers: req.headers,
        secret, // during a rotation pass both: [newSecret, oldSecret]
      });
      res.writeHead(204).end();
      if (seen.has(event.id)) return;
      seen.add(event.id);
      if (event.type === "sandbox.ready") console.log("ready", event.data);
    } catch (error) {
      res.writeHead(error instanceof WebhookVerificationError ? 400 : 500).end();
    }
  });
}).listen(8080);
