# CLI logins

CLI logins let your sandboxes use command-line tools that you are signed in
to (an AI coding CLI, a cloud CLI, a package registry) without signing in
inside every sandbox. You sign a tool in once per token set, WS Sandbox Proxy keeps the
result encrypted in a write-only vault, and the host installs it in the
sandboxes you attach it to. When a sandbox stops, the host copies the files
back, so a token the tool refreshed inside the sandbox is not lost.

You describe each tool yourself in a JSON **login definition**; WS Sandbox Proxy ships
none ([reference](#definition-reference), [examples](#example-definitions-user-owned)).

**Your accounts are your responsibility.** WS Sandbox Proxy cannot verify which provider
account a value belongs to. Read each provider's terms of service before you
store a login or share one between sandboxes; some subscriptions do not allow
automated or shared use of a personal sign-in.

## Concepts

| Term           | What it is                                                                                                                                                                        |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Definition** | A JSON document describing one CLI: how it signs in and which files and env variables hold the result. Stored as numbered, immutable versions; each version has a SHA-256 digest. |
| **Login**      | Your use of one definition version, with settings: delivery, copy-back, checkpoints, foreign hosts. The sharing mode comes from the definition.                                   |
| **Account**    | A provider account you declare under a login (for example "work" and "personal"). Optional name. **Pause lives here**, because provider limits are per account.                   |
| **Instance**   | One independent token set of an account, with its own encrypted value. Signing in to the same account again adds another instance. Optional name.                                 |
| **Lease**      | One instance used by one sandbox (or one login session).                                                                                                                          |

So a login has accounts, and each account has instances:

```text
login "codex"  (definition codex-cli v3, exclusive, copy-back on)
 ├─ account "work"       paused: no
 │   ├─ instance #1      READY      held by sandbox A
 │   └─ instance #2      READY      free
 └─ account "personal"   paused: yes
     └─ instance #1      NEEDS_LOGIN
```

The dashboard and SDK say login, account and instance. The API paths and
code use `credential` (`/v1/credentials`, `CredentialInstance`).

**Instance states** are automatic; there is no manual pause on an instance.

| State         | Meaning                                                                                                                                                                                |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EMPTY`       | Created, no value yet. Log in or upload.                                                                                                                                               |
| `READY`       | Holds a value; sandboxes can use it.                                                                                                                                                   |
| `NEEDS_LOGIN` | The stored value is probably stale (`needsLoginReason`: `capture_lost` when a refreshed token was lost, `files_missing` when a capture lacked required files). Log in again or upload. |

An instance also reports `activeLeases`, its capacity (`maxConcurrent`) and
`loginInProgress`.

**Sharing modes.** A definition's `credentials.sharing` decides the login's
mode:

- **Exclusive** (default): one sandbox at a time per instance. Copy-back is
  on by default, so the newest token always returns to the vault.
- **Shareable**: up to `maxConcurrent` sandboxes at once per instance
  (unlimited when unset). There is no copy-back: with several holders there is
  no single newest value. A tool that rotates its tokens (`rotates: yes` or
  `unknown`) can invalidate the other holders' copies; use exclusive for it.
  Lowering `maxConcurrent` below current use is allowed and applies to new
  sandboxes only.

## Turning logins on

Logins are on by default on a server that has `DATA_ENCRYPTION_KEY`, and off
(never a boot failure) without it. `CREDENTIALS_ENABLED=false` turns them off
explicitly; with the key present that is **drain mode**: new use is refused
with `credential.unavailable`, while reads, deletes, force-release, captures
and key rotation keep working so existing values settle. See
[credential vault § Feature gate](../design/credential-vault.md#feature-gate),
[environment variables](../operations/environment-variables.md#data-encryption-key)
and the [key rotation runbook](../operations/production-hardening.md#data-encryption-key).

When logins are available, `GET /v1/capabilities` lists the features
`credentials.read`, `credentials.write` and `credentials.use`.

## Getting started

1. **Add a definition** (dashboard **Settings › CLI logins**, or
   `POST /v1/credential-definitions`). Start from an
   [example](#example-definitions-user-owned) and check it against the CLI's
   current documentation.
2. **Create a login** from that definition version. Delivery, copy-back and
   the foreign-hosts opt-in are chosen here, in the dashboard.
3. **Add an account**, then get a value into an instance: a
   [login sandbox](#login-sandbox) for tools that sign in interactively, or an
   [upload](#upload) for files and API keys you already have.
4. **Use it**: name the login when you create a sandbox, or attach it to a
   running one.

## Login settings

| Setting            | Values                                         | Notes                                                                                                                           |
| ------------------ | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Delivery           | `GUEST` (default) or `PROXY`                   | Fixed at create. `GUEST` installs files and env in the guest. `PROXY` keeps API keys on the host ([proxy mode](#proxy-mode)).   |
| Copy-back          | on (default) / off                             | Exclusive `GUEST` logins only. Off: the guest's changes are discarded at every stop.                                            |
| Checkpoints        | `checkpointIntervalMin` 5–240 minutes, or none | Default 30 for exclusive copy-back logins with files; needs copy-back. See [checkpoints](#checkpoints).                         |
| Foreign hosts      | off (default) / on                             | Whether a sandbox with this login may run on a pool host another account owns. See [hosts and placement](#hosts-and-placement). |
| Definition version | a version of the same definition               | **Re-pin** moves the login to another version (dashboard only).                                                                 |

- Delivery, copy-back, foreign hosts and re-pin need a live owner session in
  the dashboard; an SDK key can change only the name and the checkpoint
  interval.
- **Re-pin** is refused with `credential.repin_blocked` while any instance is
  in use, has a value on a disk waiting for recovery, or has a capture in
  flight. Otherwise every stored value is checked against the new version and
  re-encrypted. For a proxied login whose proxy settings change, re-pin erases
  the values instead (confirm by typing the login's name;
  `credential.repin_confirm_erase`) and the instances become `EMPTY`.
- **Archive** a definition version to stop new logins pinning it; logins
  already pinned to it keep working.
- Deleting a login, account or instance is refused with `credential.busy`
  while a sandbox or login session still holds it, a disk still holds its
  value, or a capture is in flight.

## Accounts and pause

Pause an account (dashboard switch, or `PUT …/accounts/{accountId}` with
`{"paused": true}`) when its provider limit is used up. New sandboxes skip its
instances. **Sandboxes already using it keep it**; free the login on each of
them to stop using the account now. Signing in again and uploading still work
on a paused account. Naming a paused account or one of its instances
explicitly is refused with `credential.account_paused`.

## Using a login in a sandbox

A sandbox can hold up to 8 logins. Each is installed before the sandbox
becomes READY: no command runs before every attached login is in place, and
an install failure fails the create (`credential_install_failed`).

### Choosing an instance

Name a login alone, or with an account or an instance:

| You name         | WS Sandbox Proxy picks                                                             | Refusals                                                                                                                                                     |
| ---------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| login only       | the first READY, unpaused instance with room, by account order then instance order | `credential.account_paused` if every account with a ready instance is paused; `credential.in_use` if all are busy; `credential.needs_login` if none is READY |
| login + account  | the first READY instance of that account with room                                 | `credential.account_paused`, `credential.in_use`, `credential.needs_login`                                                                                   |
| login + instance | that instance                                                                      | `credential.account_paused`, `credential.needs_login`, `credential.in_use` (full, or a login session holds it)                                               |

Selection never picks a paused account unless you name it, and never an
instance that is `EMPTY` or `NEEDS_LOGIN`.

### At create

```sh
curl -sS https://wssp.example.com/v1/sandboxes \
  -H "Authorization: Bearer $WSSP_SDK_KEY" \
  -H "Idempotency-Key: create-tool-1" \
  -H "Content-Type: application/json" \
  -d '{"template": "template/<template-id>", "poolId": "<pool-id>",
       "credentials": [{"credentialId": "<login-id>", "accountId": "<account-id>"}]}'
```

**Choosing an account or instance at create applies to that create only; to
force one at resume, pass it on the resume call.** It is a placement hint,
not a stored pin.

If the host's relay connection drops while a create waits for its login, the
host asks again on its new connection, within the same 60-second wait. The
server sends the login again only to that host on its current connection, for
that create, while the login is still being installed. A repeated request
from another host or session, or after the install, a cancel or an expiry, is
refused. Both outcomes are login events (`bundle_redelivered`,
`bundle_redelivery_refused`).

### Resume and pins

A cold start (`POST /v1/sandboxes/{id}/reconnect` with mode `cold`, or SDK
`connect`) takes a lease again for every attached login:

1. If the sandbox's disk still holds a value that was never captured, that
   same instance is reused and recovered first, even if its account is now
   paused (see [recovery](#when-a-capture-cannot-be-saved)).
2. Otherwise the instance the sandbox used last, if its account is not paused
   and it has room; then another instance of the same account.
3. Otherwise any instance, by the rules above.
4. A login named in the reconnect body's `credentials` is a **pin**: that
   account or instance only, no fallback (`credential.in_use`,
   `credential.account_paused`).

The foreign-host opt-in and the host's capabilities are checked again at
every start (`credential.host_forbidden`), and so is the attached set: no two
logins of one sandbox may share an env name (or one with its private env) or
overlap in files (`credential.env_conflict`, `credential.path_conflict`). A
re-pin that would introduce such an overlap on a sandbox the login is attached
to is refused the same way. A sandbox that holds logins cannot
cold-start while its host is offline or has not yet reported its pending
captures: `credential.pending_drain` (409, retry shortly). Sandboxes without
logins keep the usual offline-accepted reconnect.

### Attach and free

`POST /v1/sandboxes/{id}/credentials` attaches a login; `DELETE
/v1/sandboxes/{id}/credentials/{credentialId}` frees it. Both are
operations (202 with a receipt) and take an `Idempotency-Key`.

- **Attach on a READY sandbox** installs the login live. New commands and new
  terminals see its env; running processes do not. Refusals include
  `credential.env_conflict` (an env name collides with the sandbox's private
  env or another login), `credential.path_conflict` (files overlap another
  attached login) and `credential.already_attached`.
- **Attach on a STOPPED sandbox** only records it; the lease is taken at the
  next start. A named account or instance becomes the sandbox's last-used
  choice, so the start prefers it and falls back as usual.
- **Free on a READY sandbox** removes the env from new commands at once and
  **closes every terminal opened with it**. The files are then copied back
  (unless `credentialCapture: "skip"`) and scrubbed. Free does not stop the
  sandbox's processes first, so a file a tool is writing at that moment may be
  captured half-written; stop the tool before freeing.
- **Free on a STOPPED sandbox** ends the attachment. If the disk still holds a
  value that must be recovered, it is refused `credential.recovery_required`
  ("start it to recover, or force-release"); if a capture is still on its way,
  `credential.pending_drain`.
- Attach and free are refused while a stop, kill, reconnect, template capture
  or another attach or free of the sandbox is in progress; a stop that
  arrives during an attach or free supersedes it.

### Hosts and placement

- A sandbox with logins prefers your own hosts. It runs on a pool host owned
  by another account only if **every** attached login has the foreign-hosts
  opt-in; otherwise placement skips those hosts, and when no allowed host
  remains (or you named a foreign host) the create is refused with
  `credential.host_forbidden`. A host whose daemon does not support logins is
  not used for them. A foreign host's operator can read the login's value
  while it is installed there.
- Turning the opt-in off does not move running sandboxes. Their next start is
  refused on a foreign host. A value left on such a disk can then only be
  cleared by [force-release](#force-release).
- Stop sandboxes that hold logins before you drain or remove a host, so their
  files are copied back first.

## Getting a value in

### Login sandbox

For tools that sign in interactively (device code, paste a code, a TUI), the
dashboard starts a **login sandbox**: **Add account**, **Add another
instance**, or **Re-login** on an instance.

1. WS Sandbox Proxy creates a dedicated sandbox from the template you choose, on your own
   hosts first, with egress to the definition's `login.egress.domains` plus
   any you add. If none of your hosts fits, it asks for consent to use a
   foreign pool host for this session only (`credential.login_needs_consent`).
   The session holds the instance, so nothing else can use or overwrite it
   meanwhile. No value is installed: a re-login starts clean.
2. Run `login.command` in the login page's terminal (copy it, or let the page
   type it). `browser-callback` sign-ins are not supported.
3. **Save** runs the optional `verifyCommand`, then captures the declared
   files. On success the instance becomes READY and the sandbox is destroyed.
   If required files are missing, the session fails, the instance keeps its
   previous value, and the sandbox stays so you can try again.
4. **Cancel**, or the session's expiry (30 minutes by default, at most 2
   hours), destroys the sandbox and keeps the previous value.

A login sandbox is hidden from sandbox lists and `/v1`, sends no webhooks,
and refuses commands, files, sharing, private env, other logins and template
capture (`sandbox.managed`); only its own login page reaches it. You can have
2 login sessions open at a time.

Login sandboxes capture files only. A login whose definition requires env
values that the instance does not hold yet, and every proxied login, is set
up by upload instead (`credential.login_requires_upload`).

### Upload

`PUT /v1/credentials/{id}/instances/{instanceId}/value` (scope
`credentials:write`), or **Upload** in the dashboard. Files are base64; the
server checks them, and every env and proxied header value, against the
definition, then encrypts them. The response is metadata only
(`storageSeq`, `sizeBytes`, `state`); no route ever returns a value.

```sh
curl -sS -X PUT \
  https://wssp.example.com/v1/credentials/<login-id>/instances/<instance-id>/value \
  -H "Authorization: Bearer $WSSP_SDK_KEY" \
  -H "Content-Type: application/json" \
  -d '{"files": [{"path": ".config/tool", "kind": "dir"},
                 {"path": ".config/tool/token.json", "contentBase64": "eyJ0b2tlbiI6Ii4uLiJ9"}],
       "env": {"TOOL_API_KEY": "..."}}'
```

Every entry must be a path the definition declares (or one under a declared
directory): a parent directory of a declared file is not itself declared, so
for a definition that declares only `.config/tool/token.json`, upload just
that file. A refused upload is `credential.value_invalid` with `entry` (what
failed) and, for a file, `path`. `env.TOOL_API_KEY` names an env var that is
missing, malformed or not declared; `files.missing_required` is a required
file that is absent; `bundle.<reason>` (such as `bundle.undeclared_path`) is a
file the definition does not allow. Neither field ever contains a value. The
SDK exposes them as `error.valueInvalid`.

An exclusive instance that a sandbox or login session holds refuses uploads
(`credential.busy`). A shareable instance accepts them while in use: running
sandboxes keep the value they installed, and new installs get the new one.

## Stop, kill and lease expiry

When a sandbox holding a login stops, is killed or reaches its lease
deadline, its host saves the login's files back to the vault before the VM
goes away. You do not need to do anything.

- **Capture by default.** Every stop and kill captures, unless the request
  asks to skip it (`credentialCapture: "skip"`), which discards changes made
  in the sandbox. Before touching any guest process the host checks that it
  can seal and store the capture; then it stops processes running as the
  sandbox user, packs the declared files, seals them to the control plane
  and uploads them. Only exclusive copy-back logins that declare files are
  captured; shareable, proxied and env-only logins are only removed.
- **Stop then removes the files** from the disk once the control plane has
  stored them (or the sealed copy is safely on the host while it is offline).
  A kill destroys the disk instead. The next start installs the newest value
  again.
- **A failed capture fails a stop or kill you requested** with
  `credential_capture_failed`. The sandbox keeps running with its login, and
  the next stop captures the files again. It returns to READY when it was
  READY (or RECOVERED) before the stop, which sends the usual state-change
  webhook; a kill of a sandbox in ERROR or UNREACHABLE stays ERROR. Stops WS Sandbox Proxy
  makes itself (lease expiry, access changes) never fail: the files stay on
  the stopped disk and are recovered the next time the sandbox starts.
- **Lease expiry** gives the login up to 20 seconds to be captured, then the
  usual 16-second graceful shutdown, so a sandbox with a login can run about
  36 seconds past its deadline. A host that restarts after a missed deadline
  waits at most 52 seconds for overdue expiries before it reports them.
- **Killing a stopped sandbox** whose disk still holds an uncaptured value is
  refused with `credential.recovery_required` unless you pass
  `credentialCapture: "skip"`: start it to recover the value, or skip to
  discard it.
- **Template capture** of a sandbox removes every login file from the image
  it captures, and is refused with `credential.capture_in_progress` while a
  login is being installed, captured or recovered on that sandbox. It scrubs
  every path any login ever installed in that sandbox, including logins whose
  files a stop already removed and logins you have since deleted.
- **Scrubs are durable.** A scrub removes the files, flushes the removal to
  the disk, and only then checks that the files are gone and reports success.
- **After a node daemon restart**, commands and terminals that need a login's
  env wait up to 10 seconds for the host to fetch it again, then fail with
  the retryable `credential_env_pending`.

## Checkpoints

Every `checkpointIntervalMin` minutes the host packs an exclusive copy-back
login's files without pausing anything and, when they changed, uploads a
sealed **checkpoint**. Checkpoints never remove files and never replace the
current value on their own. They exist for one case: a sandbox whose disk is
lost before its final capture. Force-release can then promote the newest
checkpoint ([below](#force-release)). The vault keeps the current value, the
two previous values and the newest checkpoint of each instance.

## When a capture cannot be saved

A lease that could not be captured becomes **RECOVERY_REQUIRED**: the newest
value is still on the sandbox's disk, and the instance stays reserved for
that sandbox. It counts as in use. This happens when a capture fails or is
rejected on a stop WS Sandbox Proxy made itself, when the host reports a stopped sandbox
with no capture (for example after a crash), when a stop ends in an error
without proof that the VM stopped, or when the capture of a free is rejected
(the sandbox keeps running and its next stop captures again). A
`credential.recovery_required` event and webhook follow.

- **Start the sandbox to recover.** The start reuses the same instance (even
  if its account is now paused), captures the files from the disk, removes
  them, and only then installs the current value. If that recovery capture
  fails, the start fails and the value stays on the stopped disk for the next
  attempt.
- **A disk that will never start again** (host gone, foreign host no longer
  allowed) is cleared only by force-release.

### Rejected captures

The control plane checks every sealed capture against the lease and binding
it claims to come from. A capture that fails those checks is **rejected**:
the host keeps the sealed file in a quarantine directory and does not remove
the guest's files. A rejected capture never blocks a start; the next teardown
or start captures again. An instance's rejected captures are listed for its
owner (metadata only). **Discard rejected captures** (owner session, type to
confirm) tells the hosts to delete them; force-release and host
deletion discard them too.

### Force-release

`POST /v1/credentials/{id}/instances/{instanceId}/leases/{leaseId}/force-release`
(or the dashboard) ends one lease at once. `GET …/instances/{instanceId}/leases`
(SDK `credentials.leases.list`) lists the live leases with their ids and the
checkpoint that promotion would keep. Force-release: the host drops its env,
every later capture of it is discarded, and its files on the disk will be scrubbed rather
than recovered. Anything the guest changed since the last capture is lost.
With `{"promoteCheckpoint": true}` the lease's newest checkpoint becomes the
current value when it is newer than the current one; the response says what
was promoted.

### Capture lost

A system kill (access loss, a failed readiness check, destroy on expiry) or a
deleted sandbox can destroy the disk before its capture commits. The vault
keeps the previous value; when the definition's `rotates` is not `no`, the
instance becomes `NEEDS_LOGIN` (`capture_lost`) because the provider has
probably invalidated it. A capture that is missing required files also makes
the instance `NEEDS_LOGIN` (`files_missing`).

## Events and webhooks

`GET /v1/credentials/{id}/events` (or the login's page) lists the login's
events, newest first: settings, account and instance changes, pauses,
uploads, sign-ins, captures that were rejected, failed or lost, recoveries,
force-releases, discards and logins sent again after a host reconnect. Events
carry identifiers, a type, an optional reason, storage sequence and size; never
a value or a path.

Four of them are also [webhook events](./webhooks.md):

| Webhook                        | When                                                                    |
| ------------------------------ | ----------------------------------------------------------------------- |
| `credential.capture_failed`    | A capture failed on a stop or kill you requested; the stop was refused. |
| `credential.capture_lost`      | A disk was destroyed before its capture committed.                      |
| `credential.recovery_required` | A lease moved to RECOVERY_REQUIRED.                                     |
| `credential.needs_login`       | An instance became `NEEDS_LOGIN`.                                       |

## API and SDK

All routes take `Authorization: Bearer wssp_sdk_…`. Lists are cursor-paged.

| Route                                                                                                   | Scope                                                         |                                                                                                               |
| ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `GET, POST /v1/credential-definitions`; `GET, DELETE /v1/credential-definitions/{id}`                   | read / write                                                  | Versions; `POST` with `{"text": …}` or `{"document": …}`; `DELETE` archives                                   |
| `GET, POST /v1/credentials`; `GET, PUT, DELETE /v1/credentials/{id}`                                    | read / write                                                  | Logins; `PUT` changes `name` and `checkpointIntervalMin` only                                                 |
| `GET /v1/credentials/{id}/events`                                                                       | read                                                          | Events                                                                                                        |
| `GET, POST /v1/credentials/{id}/accounts`; `PUT, DELETE …/accounts/{accountId}`                         | read / write                                                  | Accounts; `PUT` sets `name` and `paused`                                                                      |
| `GET, POST …/accounts/{accountId}/instances`; `PUT, DELETE /v1/credentials/{id}/instances/{instanceId}` | read / write                                                  | Instances; `name`, `maxConcurrent`                                                                            |
| `PUT …/instances/{instanceId}/value`                                                                    | write                                                         | Upload                                                                                                        |
| `GET …/instances/{instanceId}/leases`                                                                   | read                                                          | Live leases (holders): id, kind, state, sandbox, promotable checkpoint                                        |
| `POST …/instances/{instanceId}/leases/{leaseId}/force-release`                                          | write                                                         | Force-release                                                                                                 |
| `POST /v1/sandboxes/{id}/credentials`; `DELETE /v1/sandboxes/{id}/credentials/{credentialId}`           | `sandboxes:manage` + `credentials:use`                        | Attach, free                                                                                                  |
| `credentials` on `POST /v1/sandboxes` and `…/reconnect`                                                 | `credentials:use`                                             | Create-time choice, resume pins; a start of a sandbox with attached logins needs it too (`FORBIDDEN` without) |
| `credentialCapture: "skip"` on stop, destroy and free                                                   | `sandboxes:manage` (stop/free), `sandboxes:destroy` (destroy) | Skip copy-back                                                                                                |

The login sandbox flow, delivery, copy-back, the foreign-hosts opt-in,
re-pin and discarding rejected captures are dashboard-only.

The [`@wssp/sdk`](../../packages/sdk/README.md#cli-logins) client has the same
surface: `wssp.credentials.definitions`, `wssp.credentials` (logins and
`events`), `.accounts`, `.instances` (with `writeValue`), `.leases.forceRelease`,
and `sandbox.credentials.attach` / `free`:

```ts
const sandbox = await wssp.sandboxes.create({
  template: "template/<template-id>",
  poolId: "<pool-id>",
  credentials: [{ credentialId: login.id }],
});
await sandbox.commands.run({ argv: ["tool", "whoami"] });
await sandbox.stop(); // copies the login's files back
await sandbox.connect({ credentials: [{ credentialId: login.id, instanceId: "<instance-id>" }] });
await sandbox.destroy({ credentialCapture: "skip" }); // discard this run's changes
```

## Scopes

| Scope               | Allows                                                                                                                                              |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `credentials:read`  | List definitions, logins, accounts, instances and events. Never a value.                                                                            |
| `credentials:write` | Create and edit definitions, logins (name, checkpoints), accounts (name, pause) and instances; upload values; force-release. Values are write-only. |
| `credentials:use`   | Name logins at create, pin them on a start, attach and free them. Needs `sandboxes:manage`.                                                         |

**What `credentials:use` discloses.** It puts a login's value into a guest.
A key that also has `commands:execute` or `files:read` on that sandbox can
read the value back (`cat` the token file). The SDK-key form says so at mint.
Limit such a key with the per-login allowlist: an allowlist key sees and uses
only the logins named at mint (read live, so removing a grant takes effect at
once), and an allowlist key with `credentials:use` must name at least one
login. Proxied logins never place their value in the guest.

## Limits

| Limit                           | Value                                                                                               |
| ------------------------------- | --------------------------------------------------------------------------------------------------- |
| Logins per account              | 1000                                                                                                |
| Provider accounts per account   | 1000                                                                                                |
| Instances per account           | `CREDENTIAL_MAX_INSTANCES_PER_OWNER` (operator setting, default 1000)                               |
| Definition versions per account | 2000                                                                                                |
| Logins per sandbox              | 8                                                                                                   |
| Open login sessions             | 2                                                                                                   |
| Login session lifetime          | 30 minutes by default, at most 2 hours                                                              |
| Value size                      | the definition's `maxBytes` of file content (at most 4 MiB), plus up to 16 env values of 4096 bytes |
| Checkpoint interval             | 5–240 minutes                                                                                       |
| `maxConcurrent`                 | 1–100000, or unlimited                                                                              |

## Proxy mode

A login with `PROXY` delivery is for API keys that only need to reach one
HTTPS API. WS Sandbox Proxy never places the key in the guest: not in its memory, disk or
env. The host adds it as a header on the guest's requests to the definition's
upstream.

- The definition proxies every env entry and declares no files
  ([proxied entries](#proxied-entries)). Proxied logins have no copy-back and
  are initialized by upload, never by a login sandbox.
- **Upstream echo.** Proxying protects the key only if the upstream never
  reflects request headers back in a response (debug or echo endpoints).
  Choosing such an upstream is the definition author's responsibility.
- **Incus hosts** offer proxy delivery: a sandbox created with a proxied
  login gets one recorded ACL allow, guest to its bridge gateway on the proxy
  port ([network](network.md)).

### Proxy mode on the host

A sandbox becomes proxy-enabled when it is created with at least one
proxy-delivery login, and stays so for its whole life. Only a proxy-enabled
sandbox can take another proxy login by live attach; on any other sandbox the
attach is refused with `credential.proxy_not_enabled` before anything is
written. The host must also advertise proxy delivery, or placement refuses
the login (`credential.host_forbidden`).

The node daemon keeps the values in its own memory and runs one HTTP/1.1
listener per proxy-enabled sandbox on that sandbox's bridge gateway, at
`credential_proxy_port` (host config, default 48080). It accepts connections
only from the sandbox's own bridge subnet. Each proxied entry gets its own
**handle** (128 random bits). The guest sees only
`baseUrlEnv = http://<gateway>:<port>/c/<handle>` and, if declared,
`placeholderEnv = wssp-credential-proxy`. A request to
`<base URL>/<path>` is sent to `upstream basepath + /<path>` over TLS to the
definition's host, with the header set to `format` filled with the value.

The proxy is deliberately strict:

- Only `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` and `OPTIONS` are
  forwarded. Any other method (`TRACE`, `TRACK`, `CONNECT`, WebDAV, extension
  methods) gets `405` before the request is looked at further, and nothing is
  sent upstream.
- Requests must be HTTP/1.1 in origin form, with exactly one `Host`, CRLF line
  endings, no folded headers or control bytes, no `Upgrade`, at most one
  `Content-Length`, and `Transfer-Encoding` only as exactly `chunked` (never
  together with `Content-Length`). `Expect: 100-continue` is answered by the
  proxy. Paths with `#`, `\`, `//`, dot segments or encoded slashes,
  backslashes or NUL are refused, so a request never leaves the declared
  basepath. Heads are limited to 32 KiB and 64 header fields, bodies to
  32 MiB, a request to 30 minutes, and idle time to 120 seconds. Each sandbox
  gets 16 connections and 600 requests per minute; the daemon 256 connections.
- Bodies are decoded and re-framed; request trailers are dropped. Hop-by-hop
  headers, `Proxy-*`, `Forwarded`, `X-Forwarded-*`, `Via` and every guest copy
  of the configured header are removed before the header is added.
- The first request on a connection binds it, and its single upstream
  connection, to that handle. A later request on the same connection that
  names a different handle gets `400` and the connection closes, so one
  entry's value is never sent on another entry's upstream connection.
- The upstream name is resolved on the host, IPv4 only, on a bounded resolver
  pool (a saturated pool refuses at once). Proxy sockets obey the host's
  **egress ceiling**, the same one the egress guard enforces for guest
  packets: protected ranges, every non-default route prefix, the operator and
  deployment CIDR blocklists, the host's own addresses, broadcast and
  multicast. If any address in the answer is outside it, the request fails
  (`502`); each address is checked again against the current ceiling right
  before the connect. The daemon reads the ceiling from the guard
  (`wssp host guard`); while the guard is unreachable or not healthy no upstream
  connection is made (`503`). TLS uses the definition's hostname for SNI and
  certificate checks (public roots plus the daemon's `ca_file`). There is no
  plaintext fallback and no use of proxy environment variables.
- Redirects are passed to the guest, never followed. Responses are parsed with
  the same rules; a `101` or `Upgrade` response is a `502`. Response headers
  named like the configured header, or containing the value, are removed.
- Every refusal closes the connection. Logs carry status classes and counts
  only, never a value, handle, path, header or host.

Every read of a request, chunk-size and trailer lines included, is bound by
the 30-minute request limit: a guest trickling framing bytes cannot keep a
connection past it. The same limit holds beneath TLS: every raw read and
write on an upstream socket, the handshake included, checks the deadline and
revocation first, so an upstream trickling partial TLS records cannot hold a
request past it either. The handshake itself has 10 seconds. A watchdog also
shuts every upstream socket down at its request's deadline.

The egress ceiling governs an upstream connection for its whole life, not
only at connect. The daemon re-checks every open upstream connection against
the current ceiling about once a second, before each keep-alive reuse, and
while a long response streams. A connection whose destination the ceiling
now refuses, such as a newly denied CIDR, is closed. If the guard becomes
unreachable or unhealthy, every proxy upstream connection is closed. The
next request on that guest connection gets `502` (`503` while the ceiling is
unavailable), or the stream in progress ends.

Residual: this is enforced in the daemon, not in the kernel. Proxy sockets
are host sockets, so the guard's packet chains on the sandbox bridges never
see them. A change to the ceiling takes effect on open connections within
about two seconds: the once-a-second check plus the daemon's one-second cache
of the guard's answer. Until then an established connection can still carry
bytes. A dedicated cgroup for proxy egress, matched by the guard's table,
would close that gap in the kernel. It is not used today.

Freeing the login, revoking its lease, stopping, killing or expiring the
sandbox removes its handles at once (`403` afterwards), wipes the values and
closes the guest connections bound to them together with their upstream
connections. A request in flight never writes the header upstream after the
revocation: the header is built and written only after revocation is
re-checked. An install or restore that was waiting for its bundle when the
lease was revoked is refused. The listener itself stays up while the sandbox
runs, even after its last proxy login is freed (freed handles answer `403`),
so a proxy login attached later is served on the same address. It closes when
the sandbox stops, is killed or expires (after a daemon restart, a sandbox with
no proxy login left listens again when one is attached). After a daemon
restart the handles return as
`503` until the host re-requests the values; the guest's base URLs stay the
same.

Proxy delivery needs a runtime that gives each sandbox a bridge gateway the
guest can reach on the proxy port. Incus hosts advertise it: a proxy-enabled
sandbox gets an ACL allow from the guest to its bridge gateway on
`credential_proxy_port` ([network](network.md)). A host firewall must also let
that port in on the sandbox bridges
([hosts](hosts.md#host-firewall-ufwfirewalld)).

## Security model

**What WS Sandbox Proxy guarantees.**

- **Write-only values.** No route, log, operation result, webhook or event
  carries a value. An upload answers with metadata.
- **Encrypted at rest.** Each stored value is AES-256-GCM under its own data
  key, wrapped under a key derived from `DATA_ENCRYPTION_KEY`, and bound to
  its owner, login, instance, version and definition digest: a row copied
  anywhere else fails to decrypt. Without `DATA_ENCRYPTION_KEY` nothing
  decrypts. Details: [credential vault](../design/credential-vault.md).
- **Values travel only to the host that runs the sandbox,** over its
  outbound WSS connection, and only while that host holds the sandbox's lease.
  Hosts seal captures to a control-plane key before they leave the host, so a
  capture in transit or waiting on an offline host is ciphertext.
- **A sandbox that ever had a login stays on your own hosts.** Its stopped
  disk may be offloaded to the image store, but only after every lease has
  settled, and it restores only onto hosts you own, even after the login is
  deleted ([disk offload](./sandboxes.md#disk-offload)). A restore claims
  the attached logins on its new host exactly as a cold reconnect does.
- **The node daemon never deliberately writes a value to disk** outside the
  guest: not to its journal, outbox, staging area or logs, except a
  whole-disk offload, which is encrypted on the host with a per-upload key
  before it leaves the host; its short-lived plaintext copies stay on that
  host and are deleted once the upload is confirmed
  ([whole-disk offload](../design/credential-vault.md#whole-disk-offload)).
  It keeps values in memory that is wiped on drop and marks itself
  non-dumpable.
- **Guests receive no control-plane credentials.** Installation and capture
  walk the guest home without following links, so a guest cannot redirect
  them to other files.

**Threat model summary.**

| Adversary                                            | Mitigation                                                                                                                                                                       | What remains                                                                                                                                                                                                                                                                                    |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Someone with a database dump                         | Encryption under an env-only root; no stored check value to test guesses offline                                                                                                 | Metadata (names, sizes, timestamps)                                                                                                                                                                                                                                                             |
| Someone who can write the database but lacks the key | Context-bound encryption; settings re-read inside each claim                                                                                                                     | Rolling back to an older complete row set; flipping the foreign-hosts setting                                                                                                                                                                                                                   |
| Root on your own host                                | Plaintext only while installing, capturing or proxying; sealed captures                                                                                                          | Values in use on that host                                                                                                                                                                                                                                                                      |
| A foreign host's operator                            | Opt-in per login with a warning; scrub on stop                                                                                                                                   | An opted-in login while it is installed there                                                                                                                                                                                                                                                   |
| The guest workload                                   | Proxy mode, free, link-safe file handling, server-enforced copy-back setting                                                                                                     | Values copied out before a free; a reflecting proxy upstream. With [`guestRoot`](sandboxes.md#root-in-the-guest) the workload is guest root: quiesce kills only guest-user writers and `verifiedAbsent` is guest-attested (no new exposure: the values were already readable by the guest user) |
| A leaked SDK key                                     | Write-only values; `credentials:use` disclosed at mint; per-login allowlist                                                                                                      | Guest-delivered values the key may use and read back                                                                                                                                                                                                                                            |
| Administrators                                       | Admin views show metadata only                                                                                                                                                   | —                                                                                                                                                                                                                                                                                               |
| Someone with the offloaded disk object               | Encrypted on the host under a per-upload key wrapped by the control plane; a disk that ever held a login resumes on your own hosts only; offload waits for every lease to settle | Control-plane compromise decrypts it, login files and freed blocks included; the source host keeps plaintext copies until the upload is confirmed                                                                                                                                               |

**Out of scope.**

- **Control-plane compromise:** the server or worker process, its
  environment, Valkey.
- **Coherent database rollback.** Someone who can write the database can
  restore an older, complete set of rows. Encryption stops moving values
  between contexts, not restoring old ones; there is no external freshness
  check. Treat database write access as control-plane compromise.
- **Guest-disk remanence.** Scrubbing unlinks the files inside the guest and
  checks they are gone. The data may survive in the guest filesystem's
  journal and free blocks, storage-pool copy-on-write extents, snapshots,
  backups and copies the guest made. Host swap and crash dumps may contain
  daemon memory. Use encrypted storage pools and encrypted or no swap, and
  run the daemon with `LimitCORE=0`
  ([production hardening](../operations/production-hardening.md#cli-logins)).
- **Revocation at the provider.** Freeing or force-releasing a login stops
  WS Sandbox Proxy from using it; it does not sign the token out at the provider. After
  a suspected leak, sign out or rotate the token with the provider and log in
  again.

## Definition reference

The definition format (schema version 1) is implemented twice, by
`@wssp/login-definition` (TypeScript, server and dashboard) and the
`login-definition` crate (Rust, node daemon). Both validate against the same
conformance vectors in `packages/login-definition/vectors/`, and the
generated JSON Schema lives at
`packages/login-definition/schema/login-definition.v1.schema.json` for editor
completion. The JSON Schema describes the shape only; the rules below that
span several fields (path overlap, proxy-only definitions, byte limits) are
enforced by the validators.

### Shape

```text
schemaVersion   1 (required)
id              ^[a-z0-9][a-z0-9-]{0,62}$
displayName     1-80 characters, no control characters
description?    up to 500 characters
install?        { checkCommand?, command?, needsRoot?, notes? }   advisory only
login           { command, method, doneWhenCommandExits = true, verifyCommand?,
                  egress?: { domains[] } }
credentials     { files?: { required[], optional[], exclude[] },
                  env?: [ { name, description?, required, proxy? } ],
                  sharing = "exclusive", rotates = "unknown", maxBytes = 1048576 }
x-*             any value, at any object level
```

- **`login.method`** is `device-code`, `paste`, `interactive` or
  `browser-callback`. `browser-callback` is accepted but flagged unsupported.
- **`install`** is never executed. It documents what your template must
  already contain.
- **Commands** (`login.command`, `login.verifyCommand`, `install.*Command`)
  are non-empty, at most 4096 bytes, and contain no NUL.
- **`login.egress.domains`**: at most 32 exact, lowercase DNS names with at
  least two labels (punycode for international names). No wildcards, ports or
  IP literals.
- **`credentials.sharing`** is `exclusive` or `shareable`;
  **`credentials.rotates`** is `yes`, `no` or `unknown`.
- **`credentials.maxBytes`** bounds the total decoded file content of one
  value: 1 to 4194304 bytes.
- A definition declares at least one file path or env entry.

### Extensions and versions

Keys that start with `x-` followed by at least one character are allowed at
every object level and may hold any JSON value; WS Sandbox Proxy ignores them. Every other
unknown key is refused, so a typo fails loudly instead of being dropped.
`null` is never accepted outside an extension: omit optional fields.

A document whose `schemaVersion` is an integer above 1 is refused with
`definition.schema_version_unsupported`, so a newer definition is never
half-understood. Every other problem is `definition.invalid` with the failing
path.

### Paths

`credentials.files` paths are relative to the sandbox user's home directory.

- No leading `/`, no empty, `.` or `..` segment, no trailing slash.
- No backslash, colon, NUL or control byte; at most 255 bytes.
- Nothing whose first segment starts with `.wssp` (reserved for WS Sandbox Proxy).
- At most 64 paths across `required`, `optional` and `exclude`.
- `required` and `optional` paths must not overlap (neither may equal or
  contain another).
- Every `exclude` path lies strictly below a `required` or `optional` path,
  and excludes do not overlap each other.

A path may name a file or a directory; a directory includes everything below
it except excluded paths.

### Environment entries

At most 16 entries. `name` is a POSIX name (letters, digits, underscore; not
starting with a digit), at most 128 bytes, unique, and never `HOME`, `SHELL`,
`TERM`, the executable search path variable or anything starting with LD_. `required`
is mandatory. Values are at most 4096 bytes and contain no NUL.

#### Proxied entries

An entry with `proxy` is never placed in the guest: the host adds it as an
HTTP header on requests to one upstream. A definition that proxies any entry
must proxy every entry and must not declare files.

| Field            | Rule                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `upstream`       | `https://host[:port][/basepath]` in normalized form: lowercase scheme and host, a DNS name (no IP literal), port 1-65535 without leading zeros, no userinfo, query, fragment or trailing slash. The basepath has no `//`, dot segment, encoded slash or backslash, and percent-escapes are uppercase and only for characters that need them. Host at most 253 bytes, basepath at most 240, whole upstream at most 512. |
| `header`         | An HTTP token, at most 64 bytes, not `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`, `Trailer`, `Keep-Alive`, `Expect`, `Forwarded`, `Via`, `Proxy-*` or `X-Forwarded-*` (case-insensitive).                                                                                                                                                                                             |
| `format`         | At most 256 bytes, contains `{value}` exactly once, does not start or end with a space or tab, and the rest is valid header text.                                                                                                                                                                                                                                                                                      |
| `baseUrlEnv`     | Env name the guest uses as the API base URL. Unique, and not an entry name.                                                                                                                                                                                                                                                                                                                                            |
| `placeholderEnv` | Optional env name holding a placeholder (tools that insist on a key being set). It may reuse its own entry's name, nothing else.                                                                                                                                                                                                                                                                                       |

Every stored value of a proxied entry must produce a valid header value:
`format` with `{value}` substituted is 1 to 8192 bytes of visible ASCII,
bytes 0x80-0xFF, spaces or tabs, with no leading or trailing whitespace. A CR,
LF or NUL in a value is refused when the value is written, and again on the
host before the header is serialized. The refusal names the entry, never the
value.

Proxying protects the value only if the upstream does not echo request
headers back in its responses (debug or echo endpoints). Choosing such an
upstream is the definition author's responsibility.

### Digest

A definition is identified by the SHA-256 of its **canonical JSON**: object
keys sorted by Unicode code point, no whitespace, strings escaped as
JavaScript's `JSON.stringify` escapes them, UTF-8. Numbers must be integers in
the range ±(2^53 - 1); `1.0` counts as `1`, and any fractional number is
refused, including inside extensions. Nesting is limited to 32 levels and the
canonical text to 262144 bytes. The definition text you submit, whitespace
included, is limited to 1048576 bytes.

The digest covers the document exactly as you wrote it, `x-*` keys included
and defaults not filled in, so editing a note changes the digest. WS Sandbox Proxy
recomputes it whenever it loads a stored definition and refuses to use one that
no longer matches (`credential.definition_corrupt`).

### Example definitions (user-owned)

These two definitions are **examples you own, not built-ins**. File locations,
commands and sign-in flows belong to each CLI's vendor and change without
notice; check them against the vendor's current documentation before use.
**Read each provider's terms of service first.** Some subscriptions do not
allow automated or shared use of a personal sign-in, and you are responsible
for how your accounts are used. WS Sandbox Proxy cannot verify which provider account a
login belongs to.

Codex CLI, signing in with a ChatGPT account through the device-code flow:

```json
{
  "schemaVersion": 1,
  "id": "codex-cli",
  "displayName": "Codex CLI (ChatGPT sign-in)",
  "description": "User-owned example. Signs the Codex CLI in with a ChatGPT account through the device-code flow and keeps the resulting auth file.",
  "install": {
    "checkCommand": "codex --version",
    "command": "npm install -g @openai/codex",
    "needsRoot": false,
    "notes": "Advisory only: wssp never runs install commands. Bake the CLI into your template."
  },
  "login": {
    "command": "codex login --device-auth",
    "method": "device-code",
    "doneWhenCommandExits": true,
    "verifyCommand": "codex login status",
    "egress": { "domains": ["auth.openai.com", "chatgpt.com"] }
  },
  "credentials": {
    "files": {
      "required": [".codex/auth.json"],
      "optional": [],
      "exclude": []
    },
    "sharing": "exclusive",
    "rotates": "yes",
    "maxBytes": 65536
  },
  "x-source": "Check the CLI vendor's documentation and terms before use."
}
```

Claude Code, signing in interactively and keeping the credentials file it
writes on Linux:

```json
{
  "schemaVersion": 1,
  "id": "claude-code",
  "displayName": "Claude Code (subscription sign-in)",
  "description": "User-owned example. Runs the interactive Claude Code sign-in and keeps the credentials file it writes on Linux.",
  "install": {
    "checkCommand": "claude --version",
    "notes": "Advisory only: wssp never runs install commands."
  },
  "login": {
    "command": "claude /login",
    "method": "interactive",
    "doneWhenCommandExits": false,
    "verifyCommand": "test -s \"$HOME/.claude/.credentials.json\""
  },
  "credentials": {
    "files": {
      "required": [".claude/.credentials.json"],
      "optional": [".claude.json"]
    },
    "rotates": "yes"
  },
  "x-source": "Check the CLI vendor's documentation and terms before use."
}
```

Both files are also valid conformance vectors
(`packages/login-definition/vectors/valid/`), so they are checked by the
TypeScript and Rust test suites on every change.

For keys with **own sandboxes only**, attach/free and sandbox-related login operations require that the same key originally created the sandbox. New sandbox creation needs `sandboxes:create`; reconnect needs `sandboxes:manage`, in addition to `credentials:use`. Host command access is not limited by own sandboxes only.
