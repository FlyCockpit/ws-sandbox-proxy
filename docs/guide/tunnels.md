# Preview tunnels

A preview tunnel shares a web app running inside a sandbox through a
[tunnel](https://github.com/FlyCockpit/tunnel) server: the visitor opens a
short-lived link and lands on `https://<port>-<id>.<zone>/`. The node runs the
tunnel client **outside the VM**; the guest gets nothing installed, running or
stored, and cannot change which ports are exposed.

**Tunnels are optional.** A deployment without a configured tunnel server works
exactly as before: `GET /v1/capabilities` reports `ports.tunnel: false` and no
`sandboxes.tunnel` feature, and every tunnel call (including a create with
`network.tunnelPorts`) answers `UNSUPPORTED_CAPABILITY` with
`reason: "tunnel_off"`. You do not need to run a tunnel server to run wssp.

## How it works

1. **Declare ports at create.** `POST /v1/sandboxes` with
   `network: { tunnelPorts: [3000, 5173] }` (at most 8; `[]` makes a tunnel
   sandbox with no ports yet). The host pins the sandbox's address
   (`x.y.z.2` in its own /24) and compiles the ports into its recorded
   network plan as one rule: TCP from the bridge gateway to that address on
   exactly those ports. The drift checker watches that rule like every other
   one. Nothing else on the host or the network can reach the guest's ports.
   Only a sandbox created with `tunnelPorts` (even `[]`) is a tunnel sandbox;
   the others can never get ports later.
2. **Expose.** `PUT /v1/sandboxes/{id}/tunnel` `{ports?}` (a subset of the
   declared ports; default all) with an API key that has the
   `sandboxes:tunnel` scope. The server creates a link-mode tunnel on the
   tunnel server with its own service credential, then sends the node a
   per-tunnel token over the relay. The token is never stored by the server
   and never reaches the guest or any caller.
3. **The node runs the client.** The daemon checks the pinned client's
   SHA-256, then starts it as a separate process with the token in its
   environment only (never argv), its state directory on tmpfs
   (`$XDG_RUNTIME_DIR/wssp/tunnels/<node>/<sandbox>/`), and the target address
   taken from the recorded plan. The client dials the tunnel server outbound and
   forwards visitor streams only to the exposed ports.
4. **Link.** `POST /v1/sandboxes/{id}/tunnel/links` `{port, ttlSeconds?,
   singleUse?, sessionTtlSeconds?}` returns a one-time URL (default: valid
   60 s, single use, a 1 h browser session) and the link's stable `id`.
   Treat the URL as a secret. The tunnel server's gate turns it into a cookie
   for that tunnel; a second use of a single-use link is refused (401).
   `DELETE /v1/sandboxes/{id}/tunnel/links/{linkId}` revokes one link. See
   [Revoking one link](#revoking-one-link).
5. **Read and close.** `GET` shows `state` (`pending`, `connecting`,
   `connected`, `suspended`, `error` with `lastError`, or `closed`) and the
   preview origins; `DELETE` deletes the tunnel, and every link to it stops
   working. A closed tunnel reports its `cleanup`: `pending` until access
   through it is confirmed cut, then `done`. See
   [Closing and cleanup](#closing-and-cleanup).

6. **Change ports at runtime.** `POST /v1/sandboxes/{id}/tunnel/ports`
   `{add?, remove?}` (scope `sandboxes:tunnel`; also the MCP tool
   `sandbox_tunnel_ports`) for a dev server started on a new port. It answers
   the declared set, its `revision` and `state`: `pending` until the
   sandbox's host recorded the change, then `applied`. See
   [Changing ports at runtime](#changing-ports-at-runtime).

The SDK wraps these as `sandbox.tunnel.expose()`, `.get()`, `.close()`,
`.link({ port })`, `.revokeLink(id)` and `.updatePorts({ add, remove })`.

## Revoking one link

To remove one person's access without disturbing everyone else, revoke the
link you gave them: `DELETE /v1/sandboxes/{id}/tunnel/links/{linkId}` (scope
`sandboxes:tunnel`, the same per-account budget as link mints), with the
`id` that `POST …/tunnel/links` returned.

- The tunnel server refuses the link and ends every browser session it
  granted within moments: requests in progress, streaming responses (SSE,
  downloads), uploads and WebSockets are cut, and new requests get `401`.
  The tunnel's other links and their sessions keep working (closing or
  replacing the tunnel would end them all).
- Only a link minted for this sandbox can be revoked through it. wssp keeps
  its own record of every link it minted (`sandbox_tunnel_link`: sandbox,
  owner, the configuration that minted it, and how long the link and any
  session it granted can live; never the URL). Another sandbox's link
  answers `sandbox.tunnel_link_not_found` (404).
- One transaction re-checks the caller's authority and admits the request:
  a key revoked meanwhile revokes nothing. The first admitted request per
  link is audited (`link.revoked`: actor, key, port, link id).
- Idempotent: a link that is already revoked, expired or gone with its
  tunnel answers `200` too, for as long as wssp keeps its record: until a
  day after the link and every session it granted expired. After that
  the link answers `sandbox.tunnel_link_not_found` (404), and nothing it
  granted can still work. wssp asks the tunnel server with the current
  credential. A link that server no longer has counts as gone if one of
  these holds:
  - it was minted under the current configuration;
  - its configuration was turned off normally (every tunnel deleted, links
    with them);
  - it has outlived any session it could have granted.
- `sandbox.tunnel_unavailable` (503) means wssp could not confirm the
  revocation. Either the tunnel server did not answer (the revocation may
  or may not have landed; retrying is safe), or the link was minted under a
  configuration removed with **remove the setting now** and may still live
  on a tunnel server wssp no longer reaches. In that case it ends when its
  own lifetime does (at most the link's lifetime plus its session's, 25 h
  with the maximums).
- Revocation works while tunnels are turned off too (it answers what it can
  confirm).

## Changing ports at runtime

- **Who:** the owner or an API key with `sandboxes:tunnel` (the same
  per-account budget as expose, close and link mints), on a tunnel sandbox in
  any state but deleted; at most 8 declared ports. Every change is one
  transaction that re-checks the caller's authority, bumps the sandbox's
  `tunnelPortsRevision` (never reset), and records a `ports.changed` audit
  event (actor, key, new set and revision).
- **The host:** the server sends `tunnel.ports {revision, ports}` to the
  sandbox's host until that host acknowledges the revision (a stopped
  sandbox's host too; an offloaded sandbox gets the ports with its restore).
  The node changes the recorded plan and the ACL together under the
  sandbox's lifecycle lock and the plan's existing fences: it first records
  the change as pending (from then on the drift checker accepts exactly the
  old or the new rule, nothing else), stops a tunnel client that forwards a
  port the change removes (its open connections close with it), writes the
  ACL's tunnel rule, then commits the plan. A change interrupted half way
  (crash, uncertain write) is rolled back before the next one. A revision at
  or below the recorded one is ignored, so a late or replayed frame never
  reopens a port. Only the server's frame changes ports: the guest has no
  channel to the host's plan.
- **Adding** a port: expose it once the change is `applied` (an expose
  before that waits: no tunnel is applied until the host has the ports).
- **Removing** a port that is not exposed only changes the plan. Removing
  an **exposed** port replaces the tunnel: tunnel-server access is per
  tunnel, not per port, so the call deletes the old tunnel first (every link
  and browser session of it stops working, `401`) and the controller
  creates a new one for the remaining ports (a new preview origin: mint new
  links). Removing the last exposed port closes the tunnel. The host hears
  of the removal only after the old tunnel is deleted (or its clean-up
  hold has ended).

## Closing and cleanup

`DELETE /v1/sandboxes/{id}/tunnel` answers the closed tunnel at once:
`state: "closed"` and `cleanup: "pending"`. `GET` keeps answering it (until
the sandbox is deleted), and so does a repeated `DELETE`. `cleanup` turns
`done` only when both of these are confirmed:

- **The tunnel server deleted the tunnel** (and every other tunnel labelled
  for the sandbox). That deletion cuts every client and link, including
  in-flight responses and WebSockets. If the tunnel server cannot be
  reached, the controller retries every pass until it confirms.
- **Every host that may still run the tunnel's client confirmed it
  stopped.** Whenever a tunnel record stops naming a host (a close, a stop, a
  port change, the host away), the database records that host's obligation
  (`sandbox_tunnel_client_stop`, written by a trigger, so no code path can
  skip it). The server sends that host `tunnel.clear` at the recorded
  generation, again every 10 s and at once after a reconnect, until the host
  reports the client stopped. A client that is still running reports its own
  generation, which never counts as a stop. Two other facts also settle an
  obligation: the host reconnects without a tunnel client configured (the
  daemon stops every leftover client when it starts), or the host is deleted
  (it can never run a client for wssp again).

A host that is merely offline keeps the clean-up `pending` until it is back.
After the admin's **remove the setting now**, tunnels on the tunnel server
were forgotten without confirmation, so those tunnels never report `done`
(until exposed again). While tunnels are turned off, tunnel calls answer
`tunnel_off`. When a sandbox is destroyed its tunnel record goes once the
tunnel server confirmed the deletion. Its `GET` then answers 404, and the
destroy itself tears the client down with the sandbox's network.

**Integrators** (for example a workspace app that removes a member): close
(or replace) the tunnel, then keep treating access as live until `GET`
reports `cleanup: "done"`. A re-expose of the same sandbox is accepted once
the tunnel server confirmed the deletion, even while a host's stop is still
owed. That host obligation is kept and counts again at the next close.

## Lifecycle

| Event                                          | What happens                                                                                                                                                                      |
| ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stop, offload, destroy                         | The server deletes the tunnel on the tunnel server and tells the node to stop the client (`suspended`).                                                                           |
| Start / restore                                | A new tunnel is created and applied (new preview hostname; mint new links).                                                                                                       |
| Node daemon restart or relay reconnect         | Clients stop with the daemon. After the node registers again the server rotates the tunnel's token and re-applies it: same hostname, open previews reconnect after a few seconds. |
| Node gone (no heartbeat for 60 s)              | The server deletes the tunnel. A shorter relay drop keeps it.                                                                                                                     |
| Shared-pool access lapses                      | The server deletes the tunnel (`error`, `not_shared`), as commands and files are refused.                                                                                         |
| Tunnel deleted or expired on the tunnel server | The client exits; the server creates a new one while the sandbox runs.                                                                                                            |
| Network teardown on the node                   | The client is stopped and reaped before the sandbox's bridge and subnet are released, so a reused subnet can never be reached through an old tunnel.                              |

## Admin: configure the tunnel server

1. On the tunnel server, create a service credential for this deployment (its
   own tunnel quota, no user management):
   `tunnel-server service add wssp --max-tunnels 50 --token-file ./wssp.svc`.
2. In the dashboard: **Admin → Settings → Preview tunnels**. Enter the
   server's `https://` origin and the `tnsvc_…` credential, and the per-account
   tunnel limit. The server checks the credential against the tunnel server
   before storing it. It is sealed with `DATA_ENCRYPTION_KEY` (required) under
   its own key purpose, bound to the URL, and never shown again. Data-key
   rotation reseals it automatically.
3. **Turn off tunnels** turns the integration off for callers at once; the
   server then deletes every tunnel on the tunnel server with the stored
   credential, closes every tunnel, deletes any other tunnel labelled for this
   configuration that the credential still holds, and removes the setting when none is left (the
   card shows "Turning off" until then). After tunnels are configured again,
   owners expose them again.
4. A configuration keeps its server URL and credential for its whole life
   (only the per-account limit can change). To use another server or
   credential, turn tunnels off, wait until the setting is gone, then
   configure the new one. Every tunnel record carries the identity of the
   configuration it was made with, every clean-up uses that configuration,
   and a configuration is removed only once no record refers to it. This way
   no tunnel is ever left on a server wssp no longer holds a credential for.
   Only an `https://` host name or IPv4 origin is accepted. (One narrow
   exception: a tunnel-server create that lands after its two-minute hold
   ended and its sandbox's label was cleaned up, whose own clean-up then
   also fails, stays on the server until its 7-day lifetime ends.)
5. **Remove the setting now** is the last resort when the tunnel server is
   gone for good or no configured data key opens the stored credential any
   more: wssp forgets every tunnel at once; tunnels still on the tunnel
   server stop when their 7-day lifetime ends. Their closed records never
   report `cleanup: "done"` (nothing confirmed the deletion).

The same actions are the admin procedures `adminTunnel.get`, `adminTunnel.set`
and `adminTunnel.clear`.

## Node owner: run the client

A node advertises tunnels only after its owner installs a pinned client:

```sh
wssp host tunnel install --file ./tunnel-x86_64-linux-musl --sha256 <64 hex> [--max-tunnels 16] [--allow-for-others]
systemctl --user restart wssp-host
wssp host tunnel status
```

- The binary is copied to wssp's data directory (`0555`) and recorded in the
  `[tunnel]` section of the config with its hash. It is re-hashed before every
  client start; a mismatch refuses the tunnel.
- `XDG_RUNTIME_DIR` must exist, be private and be memory-backed (tmpfs or
  ramfs; the user service's `/run/user/<uid>` is). Client state lives under
  `$XDG_RUNTIME_DIR/wssp/tunnels/<node>/`, where `<node>` is derived from the
  daemon's state directory, so two daemons of one user never share it.
- At start the daemon stops every client an earlier run of the same node left
  behind (found by its state-directory argument). A client that survives that
  fails the start.
- A client runs only for a sandbox this node holds a live lease for, another
  user's only with `--allow-for-others`; when the lease lapses the client
  stops for good.
- `--allow-for-others` lets other users' sandboxes in your shared pools use
  tunnels on this node (your bandwidth and outbound connections). Off by
  default. You already have full access to every VM on your node; a tunnel
  adds no access to other tenants.
- `wssp host tunnel remove` turns it off (restart applies).

Placement honours it: a create with `tunnelPorts` only lands on a node that
runs a verified client for you; otherwise it is refused with
`reason: "tunnel_no_host"` (pool) or `"tunnel_host_unsupported"` (direct).
A restore of an offloaded sandbox needs only a node whose daemon knows the
tunnel plan (every current daemon): on a node without a client its tunnel
shows `error` (`refused`) until it runs on one that has one. Upgrade the
server before the node daemons.

## Limits and audit

- 8 declared ports per sandbox (also after runtime changes; every tunnel is
  created for 8 ports); the admin's per-account tunnel limit
  (`sandbox.tunnel_quota`); the node's `max_tunnels`; the tunnel server's
  service quota (`lastError: "quota"`).
- Expose, close and link mints share a per-account budget of 60 per minute.
- A tunnel row is the cleanup record: it outlives its sandbox (and the
  owner's account) until the tunnel server confirmed every tunnel labelled
  `wssp:<configuration key>:<sandbox id>` deleted. A closed row stays until its sandbox is
  deleted: it keeps the tunnel's generation, which nodes use to ignore
  stale instructions.
- Every tunnel-server create and every clean-up (a stop, close, destroy,
  turn-off or label sweep) first takes its row's two-minute hold, and only
  a server process whose view of the row is current can take it. While it
  is held no other process creates, rotates or cleans up that sandbox's
  tunnels, so a clean-up from an old view can never delete a tunnel the
  owner exposed again since.
- `sandbox_tunnel_link` records each minted access link until a day after
  it and every session it granted expired.
- `sandbox_tunnel_client_stop` holds one row per (sandbox, host) whose
  client stop is not confirmed yet; it goes with the tunnel record.
- `sandbox_tunnel_event` records config changes, enable/disable, port
  changes, tunnel create/delete, link mints and revocation requests (with
  tunnel-server ids only: never a token or link URL), kept 90 days.
- One MCP tool, `sandbox_tunnel_ports`, changes declared ports; exposing,
  links and link revocation stay with the API (links are person-facing
  secrets), with a key that has `sandboxes:tunnel`.

## Security notes

- A per-tunnel token can serve only that one tunnel's preview, so a node
  owner holding it gains nothing beyond what they already have (the VM).
- Any process on the node can reach the declared ports through the bridge
  gateway; other nodes, sandboxes and the LAN cannot.
- The tunnel server sees preview traffic. Use a tunnel server you trust, and
  a preview domain that is not same-site with your other apps.
