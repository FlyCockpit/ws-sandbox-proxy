# WS Sandbox Proxy guide

WS Sandbox Proxy (`wssp`) is a self-hosted sandbox control plane. You run the
server (API, dashboard, Postgres, Valkey) and enroll your own Linux machines as
**hosts**. Each host runs the `wssp connect` daemon, which dials out to the
server over WSS and drives **Incus KVM virtual machines**. A **sandbox** is one
such VM, booted from a **template** you registered on that host. Your programs
reach sandboxes through the `/v1` HTTP API (or the `@wssp/sdk` TypeScript
client), and you reach them in the browser through the dashboard, including a
terminal.

Everything is owned by one user account. There are no organizations, teams or
shared resources: another owner's host, template, sandbox or operation reads
as not found. Administrators see cross-owner **metadata** only; an admin role
never grants command, file or terminal access to someone else's sandbox.

## Pages

| Page                                                               | What it covers                                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Authentication planes](./auth-planes.md)                          | Browser sessions, SDK keys, host credentials, and why none of them works on another plane                                                                                                                                                                           |
| [Host pools](./pools.md)                                           | Pool/member management, placement, grants and capacity fallback                                                                                                                                                                                                     |
| [Hosts](./hosts.md)                                                | Host prerequisites, enrollment, the systemd service, signals, upgrades, drain, credential rotation                                                                                                                                                                  |
| [Templates and images](../operations/templates.md)                 | Preparing and registering an Incus VM image (guest agent, user and HOME, tools)                                                                                                                                                                                     |
| [Template builds](./template-builds.md)                            | Building a template revision from a recipe or Dockerfile subset in a build VM: steps, limits, egress, context, start/ready commands, rebuild on miss                                                                                                                |
| [Sandboxes and operations](./sandboxes.md)                         | Lifecycle, leases and expiry, operations, idempotency and unknown outcomes, commands, bounded files/tracked-process panels and controls, file transfers                                                                                                             |
| [agent-browser recipe](./recipes/agent-browser.md)                 | A tested Ubuntu 26.04 browser template, Chrome sandbox modes, egress and capacity                                                                                                                                                                                   |
| [Network egress](./network.md)                                     | Open-by-default egress, allowlist mode, what is always blocked, foreign-host consent, refusal reasons, what a domain grant really means                                                                                                                             |
| [Sandbox terminal](./terminal.md)                                  | The browser shell: attach model, security properties, limits                                                                                                                                                                                                        |
| [Webhooks](./webhooks.md)                                          | Signed event deliveries: events, payloads, verification, retries, destination rules, operator setup                                                                                                                                                                 |
| [CLI logins](./cli-logins.md)                                      | Signed-in CLIs in sandboxes: logins, accounts and instances, pause, sharing, selection and resume pins, attach/free, login sandbox and upload, copy-back and recovery, webhooks, scopes, limits, security model, and the definition format with user-owned examples |
| [TypeScript SDK](../../packages/sdk/README.md)                     | `@wssp/sdk` with compiled examples                                                                                                                                                                                                                                  |
| [CLI reference](../../apps/cli/docs/cli-reference.md)              | Every `wssp` command and flag (generated)                                                                                                                                                                                                                           |
| [Deployment](../operations/deployment.md) and [infra](../infra.md) | Running the server: images, environment, schema, proxies                                                                                                                                                                                                            |

The wire-level contracts behind these pages live in [docs/design](../design/README.md).

## What is not supported

These are deliberate, current limits, not hidden features:

- **Builds are VM builds, not OCI.** A [template build](./template-builds.md)
  runs a recipe (or a Dockerfile subset) inside a KVM build VM started from
  one of your templates. WS Sandbox Proxy does not pull OCI/Docker images, and a build
  has no layer cache and no multi-stage, `ADD`, `CMD` or `ENTRYPOINT`. The
  first base template is still an Incus `virtual-machine` image you prepare
  on a host yourself ([templates](../operations/templates.md)).
- **No snapshots, restore or fork.** Those entry points answer
  `UNSUPPORTED_CAPABILITY` until they are separately specified. Stop keeps the
  disk; that is the only persistence.
- **Immutable VM size.** Native API/SDK create selects CPU and guest RAM; stop
  and cold reconnect retain that size. Resize, disk sizing and CPU-sum quotas
  are unsupported. The dashboard offers optional size overrides at create.
- **No memory pause.** Stop shuts the VM down; a cold reconnect boots it again.
- **No guest port URLs, volumes, file watches or host-directory mounts.**
  Guest paths are the VM's own filesystem.
- **Linux-only CLI and hosts.** Run the outbound `wssp connect` daemon on a
  spare Linux machine with Incus and KVM. macOS and Windows are not supported
  CLI platforms.
- **One server replica.** Host relay sessions, in-process credential
  revocation and the transfer spool assume a single control-plane server process (a dedicated worker container is
  optional).
- **E2B is a reference, not a compatibility target.** The native `/v1` API is
  the product API; see [E2B parity notes](../design/e2b-parity.md).

Template discovery separates logical identities, exact revisions and per-host
availability. Create uses a template selector plus exactly one pool or explicit host.
The dashboard keeps template selection independent of placement. Follow the
[SDK resource-grant walkthrough](./auth-planes.md#minting-sdk-resource-grants)
and the [pool dashboard walkthrough](./pools.md#dashboard-walkthrough) after
enrolling hosts.
