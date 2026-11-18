# Webhooks

A webhook endpoint is an HTTPS URL that WS Sandbox Proxy calls when your sandboxes and
operations change state. Each call is signed, so your receiver can prove it
came from your WS Sandbox Proxy server. Endpoints are owned by your account like every
other resource: you see and manage only your own.

Webhooks are off unless the operator sets `DATA_ENCRYPTION_KEY` on the server
and the worker (see [Operator setup](#operator-setup)). Without it, the
dashboard says "not configured", `/v1/capabilities` does not list
`webhooks.write`, and every webhook route answers `UNSUPPORTED_CAPABILITY`.

## Events

| Event                          | When it fires                                                                                                                                                                                                                                             |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sandbox.ready`                | Every time a sandbox enters READY: create, cold or warm reconnect, recovery, or ERROR → READY. `data.sandbox.previousState` tells them apart.                                                                                                             |
| `sandbox.stopped`              | A sandbox enters STOPPED.                                                                                                                                                                                                                                 |
| `sandbox.create_failed`        | A sandbox that was never ready leaves a pre-READY state (REQUESTED, SCHEDULED, PROVISIONING, or waiting for capacity) into ERROR, or into DELETED with an error code. A kill before READY sends only `sandbox.destroyed`.                                 |
| `sandbox.destroyed`            | A sandbox enters DELETED.                                                                                                                                                                                                                                 |
| `operation.completed`          | An operation reaches SUCCEEDED, FAILED, CANCELLED or UNKNOWN_OUTCOME. An UNKNOWN_OUTCOME that later resolves fires a second time with the final state.                                                                                                    |
| `credential.capture_failed`    | A CLI login could not be captured on your stop or kill, so the stop was refused and the sandbox kept running with the login still attached.                                                                                                               |
| `credential.capture_lost`      | A login's newest value was lost: the disk holding it was destroyed before a capture committed. The previous value is kept.                                                                                                                                |
| `credential.recovery_required` | A login's newest value could not be captured and is still on the sandbox's disk. Start the sandbox to recover it (or stop it again if it is still running), or force-release the lease. See [CLI logins](./cli-logins.md#when-a-capture-cannot-be-saved). |
| `credential.needs_login`       | A login instance needs a new sign-in or upload (its rotation was lost, or a capture was missing required files).                                                                                                                                          |
| `webhook.test`                 | Only from **Send test event**. You cannot subscribe to it.                                                                                                                                                                                                |

`operation.completed` is filtered by operation kind. New endpoints get the
lifecycle kinds plus commands: `CREATE_SANDBOX`, `STOP_SANDBOX`,
`KILL_SANDBOX`, `RECONNECT_SANDBOX`, `RENEW_SANDBOX_LEASE` and `RUN_COMMAND`.
Pass `"all"` for every kind; file and process reads are high-volume.

Events are emitted for transitions that commit after the endpoint exists. They
are written in the same database transaction as the state change, so a change
that rolls back never sends an event.

## Payload

Every body is one JSON object (schema version 1):

```json
{
  "id": "evt_6f1c2a9e0b7d4c3a8e5f1b2c3d4e5f60",
  "type": "sandbox.ready",
  "schemaVersion": 1,
  "occurredAt": "2026-11-02T18:04:11.512Z",
  "data": {
    "sandbox": {
      "id": "sbx…",
      "name": "quiet-otter",
      "state": "READY",
      "previousState": "PROVISIONING",
      "generation": 1,
      "hostId": "host…",
      "templateId": "tpl…",
      "templateRevisionId": "rev…",
      "originPoolId": null,
      "metadata": { "team": "ci" }
    }
  }
}
```

- `sandbox.create_failed` adds `data.error.code`, a public operation error code
  (for example `host_capacity`).
- `operation.completed` carries `data.operation`: `id`, `sandboxId`, `kind`,
  `state`, `outcome`, `errorCode`, `failure` and `completedAt`. It never
  carries command output, results, error detail, request payloads or
  idempotency keys.
- `credential.*` events carry `data.credential` (`id`, `accountId`,
  `instanceId`), `data.leaseId`, `data.sandboxId` and `data.reason`, a fixed
  code such as `capture_lost`, `census_settlement` or `files_missing`. They
  are the fields `GET /v1/credentials/{id}/events` returns, never a login
  value, a file path or a host.
- A payload never discloses more than `GET /v1/sandboxes/{id}` or
  `GET /v1/operations/{id}` would for the same owner. `hostId` is `null` when
  the sandbox runs on another owner's shared host.
- The state fields describe the transition that fired the event, not the
  sandbox's current state. Fetch current state through the API when it matters.
- `name` is the sandbox's name when the payload is rendered, at delivery: a
  rename between the event and a delivery or retry shows the new name. A
  rename itself fires no event.

The full schemas are the `webhooks` section of the OpenAPI document
(`GET /v1/openapi.json`, committed as `packages/sandbox-contracts/openapi.json`).
Adding fields does not change `schemaVersion`; a breaking change would ship as
version 2.

## Verifying a delivery

Deliveries use the [Standard Webhooks](https://www.standardwebhooks.com/)
scheme. Each request carries:

- `webhook-id`: the event id. It stays the same across retries and redeliveries,
  so it is your dedupe key.
- `webhook-timestamp`: Unix seconds when this attempt was signed.
- `webhook-signature`: `v1,<base64 HMAC-SHA256>` over
  `<webhook-id>.<webhook-timestamp>.<raw body>`, keyed by the base64-decoded
  part of your `whsec_` secret. During a rotation overlap there are two values,
  separated by a space.
- `content-type: application/json`, `user-agent: wssp-webhooks/1`,
  `wssp-event-type`, `wssp-delivery-id` and `wssp-delivery-attempt`.

No cookie and no WS Sandbox Proxy credential is ever sent.

With the SDK:

```ts
import { verifyWebhook } from "@wssp/sdk/webhooks";

const event = verifyWebhook({ body: rawBodyBytes, headers: req.headers, secret });
```

Without the SDK (Node):

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

function verify(raw: Buffer, headers: Record<string, string>, secret: string) {
  const id = headers["webhook-id"];
  const ts = headers["webhook-timestamp"];
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) throw new Error("stale");
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const expected = createHmac("sha256", key).update(`${id}.${ts}.`).update(raw).digest();
  const ok = headers["webhook-signature"]
    .split(" ")
    .map((value) => Buffer.from(value.replace(/^v1,/, ""), "base64"))
    .some((sig) => sig.length === expected.length && timingSafeEqual(sig, expected));
  if (!ok) throw new Error("bad signature");
  return JSON.parse(raw.toString("utf8"));
}
```

Rules for receivers:

- Verify the **raw body bytes** exactly as received, never re-serialized JSON.
- Reject timestamps more than 300 seconds from your clock, in either direction.
- Remember each `webhook-id` for at least 24 hours plus that tolerance, and drop
  repeats. Delivery is **at least once**: a worker crash, a lease recovery or a
  restored database can send the same event again.
- Answer `2xx` quickly and do the work afterwards. Anything else (including a
  redirect or a timeout) is retried.
- Delivery order is **not** guaranteed, not even per endpoint. Order by
  `(sandbox.id, generation, occurredAt)` and read current state from the API.

## Retries, failures and disabling

- An attempt succeeds only on a `2xx` response within 10 seconds. Redirects are
  never followed.
- The first attempt is sent immediately. A failed attempt is retried after
  about 30 s, then 2 m, 5 m, 15 m, 30 m, 1 h, 2 h, 4 h, 6 h and 8 h (each ±20%):
  11 attempts in total within 24 hours. A `429` or `503` with `Retry-After` is honored, capped at one hour and
  never sooner than the schedule. After 24 hours the delivery fails.
- Each endpoint gets at most 2 attempts at a time. Its other due deliveries
  wait their turn and the next one starts as soon as an attempt finishes.
  Manual sends (a test event or a redelivery) go first, ahead of any
  automatic backlog; within each group the oldest due goes first. Manual
  sends still count toward the 2. A slow or failing endpoint only delays its own
  deliveries, never other endpoints'. A scheduled retry starts within a few
  seconds of its time, or later if the endpoint is busy with older
  deliveries. Undelivered deliveries still fail 24 hours after they were
  created.
- An endpoint that has failed every attempt for at least **72 hours and 20
  consecutive attempts** is disabled. Its pending deliveries are cancelled and
  the owner gets one email naming the destination host. Fix the receiver, then
  enable the endpoint; enabling resets the failure counters. Events that occur
  while an endpoint is disabled are not sent.
- **Send test event** queues a signed `webhook.test` delivery. **Redeliver**
  sends an earlier delivery's event again as a new delivery with the same
  `webhook-id` and identical body.

## Destinations

Webhooks run on the server's network, so the destination rules exist to stop
an endpoint from reaching things only the server can reach:

- `https://` only. No credentials in the URL, no `#fragment`, at most 2048
  characters, port 443 or 1024-65535.
- Every address the hostname resolves to is checked on every attempt. If any
  address is private, loopback, link-local, multicast, carrier-grade NAT,
  documentation, IPv4-mapped IPv6, NAT64, 6to4, Teredo, unique-local or
  otherwise not public unicast, the attempt is refused (`destination_blocked`).
  The connection then goes to the validated address only, so a DNS answer that
  changes between the check and the connect cannot redirect it.
- Cloud metadata and platform addresses (169.254.169.254, `fd00:ec2::254`,
  100.100.100.200, 100.100.100.100, 168.63.129.16) are refused even when an
  operator allowlists a covering range. So is every IPv6 form that embeds or
  translates an IPv4 address (IPv4-mapped, IPv4-compatible, IPv4-translated,
  NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo
  `2001::/32`): an allowlist can never reach metadata through a translator.
- Hostnames are resolved and checked when an endpoint is created or its URL
  is updated (a name that does not resolve, or that resolves to an address the
  account may not use, is refused), and again on every attempt. Every answer
  is checked; an answer set larger than 64 addresses is refused. An update
  that leaves the endpoint disabled with the same URL skips resolution, so
  you can always switch off an endpoint whose name stopped resolving.
- `localhost`, `*.localhost`, `*.local` and `*.internal` names are refused at
  create time.
- An operator can allowlist private destinations (for example a tailnet host)
  for administrator accounts; see [Operator setup](#operator-setup).

## Limits

- 10 endpoints per account.
- Endpoint writes (create, update, delete, rotate, enable): 20 per minute and
  200 per day. Test events: 5 per minute and 50 per day per account, 2 per
  minute per endpoint. Redeliveries: 30 per minute and 300 per day.
- Payloads are at most 64 KiB. A receiver's reply is read up to 64 KiB; only the
  status and a 512-byte excerpt are kept, visible to you alone.
- The delivery log keeps events, deliveries and attempts for 7 days.

## Managing endpoints

Dashboard: **Settings › Webhooks**. The signing secret is shown
once, at create and at rotation. Rotation keeps the old secret signing
alongside the new one for an overlap you choose (none, 1 hour, 24 hours or 7
days), so your receiver can switch without dropping events.

API (`/v1`, scope `webhooks:write`): `GET /v1/webhooks/endpoints`,
`POST /v1/webhooks/endpoints`, `GET /v1/webhooks/endpoints/{id}`,
`PUT /v1/webhooks/endpoints/{id}`, `DELETE /v1/webhooks/endpoints/{id}`,
`POST /v1/webhooks/endpoints/{id}/rotate-secret`,
`POST /v1/webhooks/endpoints/{id}/test`,
`GET /v1/webhooks/endpoints/{id}/deliveries`,
`GET /v1/webhook-deliveries/{id}` and
`POST /v1/webhook-deliveries/{id}/redeliver`. These routes take no
`Idempotency-Key`; create is not idempotent (it is capped and returns a
show-once secret), so check the list before retrying an uncertain create.
`webhooks:write` can be minted only on a key over **all owned** resources and
**all usable** pools (`sdk_key.webhooks_requires_all_owned`), because an
endpoint receives events for every sandbox on the account. An endpoint
outlives the key that created it.

The SDK wraps all of this as `client.webhooks.endpoints` and
`client.webhooks.deliveries`; see the [SDK README](../../packages/sdk/README.md#webhooks).

## Operator setup

| Variable                          | Meaning                                                                                                                                                                                                                                                |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `DATA_ENCRYPTION_KEY`             | 64 lowercase hex characters (32 bytes): `openssl rand -hex 32`. The deployment's root key for data at rest; endpoint secrets are encrypted under a sub-key derived from it. Set the **same value** on the server and the worker. Unset = webhooks off. |
| `DATA_ENCRYPTION_KEY_PREVIOUS`    | The second root during a key rotation. The worker re-encrypts endpoint secrets under the key the database epoch names. Follow the rotation runbook, then remove it.                                                                                    |
| `WEBHOOK_ALLOWED_PRIVATE_CIDRS`   | Comma-separated private CIDRs deliveries may reach. A range overlapping link-local, multicast, metadata, mapped or (in production) loopback ranges fails boot.                                                                                         |
| `WEBHOOK_ALLOWED_PRIVATE_HOSTS`   | Comma-separated exact hostnames that may resolve to private addresses. Used only when no CIDRs are set.                                                                                                                                                |
| `WEBHOOK_TRANSLATION_PREFIXES`    | Comma-separated network-specific NAT64 prefixes (RFC 6052) on the worker's network. Their ranges are hard-denied and cannot be allowlisted.                                                                                                            |
| `WEBHOOK_PRIVATE_ALLOWLIST_SCOPE` | `admins` (default) or `all`: which accounts may use the private allowlist. Admin means admin role, verified email, not banned or deleting, and 2FA policy satisfied, re-checked on every attempt.                                                      |
| `WEBHOOK_ALLOW_PLAINTEXT_PRIVATE` | `true` permits `http://` to allowlisted private destinations only. Default `false`.                                                                                                                                                                    |
| `WEBHOOK_DELIVERY_CONCURRENCY`    | Delivery attempts per worker process, 1-64 (default 8). Each endpoint has at most 2 attempts in flight across all workers.                                                                                                                             |

Losing `DATA_ENCRYPTION_KEY` makes every endpoint secret undecryptable: the
worker records `not_configured` attempts (they do not count toward disabling),
and owners must rotate their secrets once a key is set again. See
[production hardening](../operations/production-hardening.md#webhook-egress)
for the egress risk and network-level filtering, and
[Data encryption key](../operations/production-hardening.md#data-encryption-key)
for key custody and rotation.

DNS: the worker resolves names with the system resolver configuration
(`resolv.conf`, so tailnet MagicDNS works) but does not read `/etc/hosts`.
Use IP literals or real DNS names in allowlists.

### Local testing

The local agent stack (`pnpm dev:docker <port> --prod`) passes opt-in
`AGENT_WEBHOOK_*` variables from your shell to the server and worker:
`AGENT_DATA_ENCRYPTION_KEY=$(openssl rand -hex 32)`, plus
`AGENT_WEBHOOK_ALLOWED_PRIVATE_CIDRS=<receiver-ip>/32` and, for a plain-HTTP
receiver, `AGENT_WEBHOOK_ALLOW_PLAINTEXT_PRIVATE=true`. The account that
creates the endpoint must be an administrator while the scope is `admins`.
`scripts/webhook-receiver.mjs` is a dependency-free receiver for this check:
it verifies each delivery with the built SDK, logs `webhook-id`, type and
attempt, flags duplicates, and can answer `503` to exercise retries.

To produce sandbox events without VMs, enroll a host and run
`WSSP_FAKE_ENFORCE_EGRESS=1 wssp host run --runtime fake`. A fake host otherwise
refuses every create because it cannot enforce egress; this opt-in advertises
enforcement the fake does not perform, so use it only on local stacks. Add
`WSSP_FAKE_FAIL_CREATE_FILE=<path>` to make new creates fail (and emit
`sandbox.create_failed`) while that file exists. `wssp host run` refuses to start
the Incus runtime with either variable set.
