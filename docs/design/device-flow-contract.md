# Device flow consumer contract (`hostCredentials.exchangeDeviceCode`)

Raw HTTP contract for CLI and other non-browser consumers polling device authorization through the production oRPC stack. Browser owners use cookies and the device approval UI; this document covers the **public exchange** path only.

## Transport

| Item         | Value                                                                     |
| ------------ | ------------------------------------------------------------------------- |
| Method       | `POST`                                                                    |
| Path         | `/rpc/hostCredentials/exchangeDeviceCode`                                 |
| Content-Type | `application/json`                                                        |
| Body shape   | oRPC envelope: `{ "json": { "deviceCode": string, "hostSlug": string } }` |

### Headers (split-origin / `CORS_ORIGIN` set)

| Header         | Required                             | Value                                                                               |
| -------------- | ------------------------------------ | ----------------------------------------------------------------------------------- |
| `Content-Type` | yes                                  | `application/json`                                                                  |
| `x-csrf-token` | yes when `CORS_ORIGIN` is configured | `orpc` (matches `SimpleCsrfProtectionHandlerPlugin` on the production `rpcHandler`) |

Missing `x-csrf-token` in split-origin mode returns **403** with oRPC JSON `code: "CSRF_TOKEN_MISMATCH"` (no `data.deviceFlowError`).

Same-origin deployments without `CORS_ORIGIN` do not install the CSRF plugin; the header is not required.

## Success

| HTTP | Body                                                                                                                 |
| ---- | -------------------------------------------------------------------------------------------------------------------- |
| 200  | `{ "json": { "credentialId", "userId", "hostId", "secret" } }` where `secret` is a `wssp_device_` product credential |

## Error responses

All errors use the oRPC envelope `{ "json": { "code", "message", "status?", "data?" } }`. Device-flow semantics live in `data.deviceFlowError` when present.

| HTTP | `json.code`           | `data.deviceFlowError`  | Retry?                                                                                                                         |
| ---- | --------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| 400  | `BAD_REQUEST`         | `authorization_pending` | yes — poll again after `interval` from issuance (seconds)                                                                      |
| 400  | `BAD_REQUEST`         | `slow_down`             | yes — back off; honor `interval` before next poll                                                                              |
| 400  | `BAD_REQUEST`         | `expired_token`         | no — start a new device login                                                                                                  |
| 400  | `BAD_REQUEST`         | (absent)                | no — input validation, missing scope, or slug mismatch                                                                         |
| 403  | `FORBIDDEN`           | `access_denied`         | no — owner denied the request                                                                                                  |
| 403  | `FORBIDDEN`           | (absent)                | no — owner credential policy not satisfied at mint time                                                                        |
| 404  | `NOT_FOUND`           | (absent)                | no — unknown, consumed, or fully removed code                                                                                  |
| 409  | `CONFLICT`            | (absent)                | no — slug/host conflict, enrollment race, or the owner's host limit (`SANDBOX_MAX_HOSTS_PER_OWNER`); message is human-readable |
| 429  | `TOO_MANY_REQUESTS`   | (absent)                | yes after `data.retryAfterSeconds` (procedure budget)                                                                          |
| 503  | `SERVICE_UNAVAILABLE` | `authorization_pending` | yes — transient DB conflict, deadlock, or exchange budget store unavailable; treat like pending                                |

## Retry / backoff rules

1. **`authorization_pending` (400 or 503)** — sleep at least the issued `interval` (seconds) between attempts; 503 is not terminal.
2. **`slow_down` (400)** — increase spacing; do not tight-loop. The server records `lastPolledAt` under row lock.
3. **`TOO_MANY_REQUESTS` (429)** — wait `data.retryAfterSeconds` before the next exchange attempt (per-IP procedure budget).
4. **Terminal rows** (`access_denied`, `expired_token`, 404, 409 without pending signal, 400 without `deviceFlowError`) — stop polling; user must start a new device code flow.
5. **Any response not listed in the error table** (for example a 500, a 401, a non-JSON body, or a listed status whose `data.deviceFlowError` is not one of the documented values) — treat as **terminal**: stop polling, surface the message, and have the user start a new device login. Only the documented `authorization_pending` and `slow_down` tags and 429 are retryable; clients must never retry on an unrecognized response.

## Lost response / consumed code

Exchange is **consume-on-success**: a winning mint deletes the approved `device_code` row inside the transaction. If the client receives no response after the server committed, the code is gone and further polls return **404** `NOT_FOUND` (`Device code not found.`). The client must not treat that as pending; check for a credential issued out-of-band or restart login.

If two exchanges race, exactly one mints; the loser gets **409** `CONFLICT` or **404** when the row was consumed.

## Issuance (reference)

Device codes are created at `POST /api/auth/device/code` (Better Auth, snake_case: `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`). The `interval` field is **seconds** between polls (Better Auth also stores `pollingInterval` in milliseconds on the row). Owner approval uses `POST /api/auth/device` (claim), `/approve`, `/deny` with session cookies — not covered by this exchange contract.

## Active relay revocation

A device credential is long-lived and revocation-only. The relay rechecks it and
the owner's ban/deletion policy at every active boundary. An inactive credential
closes an existing websocket with code `4003`, reason `credential_inactive`, when
revalidation definitively fails; dependency failures use `1011`/`internal_error`
(retryable — `wssp host run` exits **5**). Terminal credential failure (`4003`,
upgrade 401/403) exits **4**. Messages never include the secret.
The owner revokes one from the dashboard's Host credentials page
(`sandboxHosts.revokeDeviceCredential`). Unban restores access with the same still-valid credential. Device replacement
invalidates prior device connections for that host before committing revocation.
See [active authority and deletion](adr-003-host-enrollment.md#active-authority-and-deletion)
for retained cleanup records and the offline-expiry prerequisite.
