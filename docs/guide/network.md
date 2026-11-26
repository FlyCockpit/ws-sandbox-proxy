# Network egress

Sandboxes have **open internet by default**. A sandbox created without an
`egress` policy can reach the public IPv4 internet (inference APIs, package
installs, `curl`, scrapers, CLI installers) and nothing else. You can restrict a
sandbox to an **allowlist** at create time. The policy is fixed at create (there
is no update), recorded on the sandbox, shown to its owner, and re-applied on
every cold boot. Metadata can never widen it.

Each sandbox has one of two modes:

| Mode             | Reachable                                                                                 |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `open` (default) | The public IPv4 internet, minus [what is always blocked](#what-is-always-blocked)         |
| `allowlist`      | Only the listed exact `domains` and IPv4 `cidrs`; none listed blocks all outbound traffic |

## Choosing a mode

```json
{}
{ "egress": { "mode": "allowlist", "domains": ["registry.npmjs.org"], "cidrs": ["8.8.8.8/32"] } }
```

- Omitting `egress` (or sending `null` or `{}`) requests `open`.
- Without `mode`, any `domains` or `cidrs` key, even an empty array, means
  `allowlist`, so a client that lists any grants gets a restricted sandbox.
  Explicit deny-all is `{ "mode": "allowlist" }`.
- The TypeScript SDK adds `allowInternetAccess` (the E2B name). `true` requests
  `open`; any `egress.domains`/`cidrs` become **fallback grants**, used only if
  the sandbox lands on another user's host that allows only listed
  destinations. `false` requests `allowlist` with the listed grants. A
  `egress.mode` that contradicts `allowInternetAccess` is refused locally with
  kind `invalid_request`, before any network call.
- At most 128 `domains` and 128 `cidrs`. Domains are exact hostnames
  (normalized, IDNA A-labels): no wildcards, URLs, ports or IP literals. CIDRs
  are canonical IPv4 prefixes; host bits are masked. IPv6 grants are refused:
  sandboxes have IPv4 egress only.
- Grants are validated the same way in both modes. A grant that intersects an
  always-blocked range is refused, not carved out, even through a broad CIDR
  such as `0.0.0.0/0`; IPv4-mapped IPv6 prefixes are refused outright. An
  invalid policy is `sandbox.egress_policy_invalid` before anything is created.
- The effective mode is resolved once, when the host is chosen (direct,
  pool-placed, or a queued create reaching placement), and is fixed from then
  on. `GET` on a sandbox reports `egress.mode`, and `egressModeReason` says why
  an open request became an allowlist: `node_policy` (the host's owner did not
  allow open internet for other users) or `host_unsupported` (the host's daemon
  does not advertise open egress).

## What is always blocked

In open mode, and as a ceiling on every allowlist grant, a sandbox can never
reach:

- loopback, private (RFC 1918), link-local and instance-metadata addresses
  (`169.254.0.0/16`, `100.100.100.200`, the Azure wireserver), CGNAT and tailnet
  space (`100.64.0.0/10`), documentation, multicast and other reserved ranges
  (the shared table is `SPECIAL_PURPOSE_V4` in `special-ranges.ts`);
- **every address of the host itself** and its routed internal prefixes, so a
  sandbox cannot reach the host's services or LAN;
- other sandboxes and other owners' guests;
- anything on the **operator blocklist**: the host's root-owned
  `/etc/wssp/egress-blocklist` unioned with the deployment-wide
  [`SANDBOX_EGRESS_BLOCKLIST`](../operations/environment-variables.md).

The blocklist holds IPv4 CIDRs and domain names. **CIDRs are enforced by the
guard in the kernel path. Domains are best-effort:** they are removed from the
sandbox's bridge resolver, which stops lookups through it, but a guest that
resolves elsewhere (direct DNS is allowed by default, see below) or connects to
a literal address is not stopped by a domain entry. Block an address range if
you need a guarantee.

Enforcement on the host is a root-owned, drop-only nftables table installed by
`sudo wssp host guard install --daemon-user <user>`; see [hosts](./hosts.md#egress-guard).

## Open mode details

- **SMTP (tcp/25) is blocked by default**, so a sandbox cannot send mail
  directly. The host owner can allow it with
  `wssp host config set-egress-block-smtp off` (applies to sandboxes created
  afterwards).
- **Direct DNS to public resolvers is allowed by default**, so scrapers and
  tools that pin a resolver just work. A host owner can reject DNS to anything
  but the sandbox's own resolver with
  `wssp host config set-egress-block-external-dns on` (key
  `egress_block_external_dns`, sandboxes created afterwards).
- **Upstream resolvers.** The bridge resolver forwards to the host's resolvers
  by default. A host owner can name up to four IPv4 upstreams with
  `wssp host config set-egress-dns-upstreams 1.1.1.1,9.9.9.9` (key
  `egress_dns_upstreams`; `--clear` restores the host resolvers). This setting
  applies to **open mode only**; allowlist mode never forwards queries.

## Other users' hosts

A pool can include hosts owned by other users. Open internet from a host
exposes that owner's network identity (IP address) to whatever the sandbox
does, so the host owner decides. `allow_open_egress_for_others` is **off by
default**, is asked once during `wssp host enroll`, and is changed with
`wssp host config set-open-egress-for-others on|off`. Your own sandboxes on your own
hosts are always open unless you asked for an allowlist.

- Placement prefers hosts where the requested mode can be granted. If an open
  request lands on a non-consenting foreign host, the sandbox is created in
  allowlist mode with your fallback grants (none means deny-all) and
  `egressModeReason: "node_policy"`. Grantees of a pool do not see the owner's
  setting; they learn the result from `egress.mode`.
- The mode is fixed at creation. If the owner turns consent off afterwards,
  already-running sandboxes are not touched (warm reconnect and adoption keep
  working), but a **cold reconnect** or start of an open sandbox on that host
  is refused with `open_egress_not_permitted`. Create a new sandbox.
- Template builds follow the same rule: open on your own and consenting hosts,
  allowlist (fallback grants and presets) elsewhere.

## Refusal reasons

A launch, cold reconnect or start refused for egress reasons fails with
`UNSUPPORTED_CAPABILITY`. The `/v1` error keeps its constant catalog message;
a typed `reason` is attached for these two:

| `reason`                    | Meaning                                                                                                                                                       | What to do                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `egress_guard_unavailable`  | The host's egress guard is missing, unhealthy, outdated, its 15 s lease expired, or it does not cover this sandbox's bridge. Applies to both modes. Retryable | Retry; the host owner runs `wssp host guard status`             |
| `open_egress_not_permitted` | An open sandbox on another user's host whose owner does not (or no longer) allow open internet for other users                                                | Create a new sandbox (allowlist, or on a host that allows open) |

Related: a compiled allowlist whose ACL body exceeds 64 KiB is refused at
create with `request_too_large` (`egress_policy_too_large`). A DNS refresh that
would exceed the same budget keeps the last-good rules instead (it fails
narrow) and records a warning.

## Requirements

- A host must prove it can enforce policies: Incus 6.14+ with network ACLs (see
  [host requirements](./hosts.md#requirements)) **and a healthy egress guard**.
  Otherwise the create, or a cold boot, fails with `UNSUPPORTED_CAPABILITY`
  before any VM is allocated. A host without a healthy guard takes no new
  sandboxes in either mode. Read `egressEnforcement` on `GET /v1/hosts` first;
  the host card shows that it cannot enforce, and the daemon log says why.

## Allowlist mode

The rest of this page describes allowlist mode (and the machinery both modes
share).

## When the protected ranges expand

A stored policy is not grandfathered when a future release adds a protected
range. For example, a stored `203.0.0.0/8` intersects the protected
`203.0.113.0/24` and is refused even though most of the prefix is public.
The policy is immutable; recreate the sandbox with narrower, allowed CIDRs.

- **Next refresh:** parsing the static CIDRs fails the whole refresh before
  it applies or commits new grants. No domain grant is renewed; existing
  timed grants lapse through the independent expiry enforcement. If an
  enforcement refusal already blocks refresh, the pass is skipped instead.
- **Next reconnect:** the relay rejects the recorded policy before sending
  the create/reconnect dispatch and fails the operation with `protocol_error`.
  A reconnect reaching the host directly also fails when it recompiles the
  persisted grant expansion; it does not start the VM or rebuild its network.
- **Other dispatches:** the relay's policy validation is specific to create
  and reconnect. Host enforcement checks re-parse the persisted grants; a
  newly forbidden CIDR makes that evidence unreadable, so new guest work is
  refused as inconclusive enforcement. That alone does not stop or delete
  the VM. This is not an immediate rewrite of an existing ACL: static CIDR
  rules have no DNS lease and can remain until sandbox teardown.

## How it is enforced

Each sandbox gets its own Incus bridge and network ACL on its host, with
`drop` as the default in both directions. The only permitted traffic is DHCP,
DNS to the bridge's own resolver, and one allow per granted destination. The
guest has exactly one NIC with MAC, IPv4 and IPv6 filtering and port
isolation; there are no forwards, proxy devices or host mounts. The bridge is
IPv4-only. A sandbox cannot reach other sandboxes, other owners' guests or the
host's services through its bridge unless a CIDR grant names them.
All of this is host-side: root inside the guest
([`guestSudo`](sandboxes.md#root-in-the-guest)) cannot change it.
CLI-logins proxy mode (see [CLI logins](cli-logins.md#proxy-mode-on-the-host))
adds one more gateway allow, guest to the gateway on the credential proxy
port over TCP, in both modes, only for a sandbox created with a proxied
login. Like DNS it targets the gateway, so no reject covers it; every other
gateway port stays dropped. It is part of the recorded network plan, so a
later change of `credential_proxy_port` never applies to a running sandbox.

The bridge resolver answers **only** the allowlisted names, with the answers
the host published: their IPv4 (A) records, and an empty NOERROR answer
(NODATA) for every other record type of such a name (AAAA, HTTPS, TXT, ...),
so strict resolvers such as musl's fall back to the A answer. Any other name,
including an unlisted subdomain of an allowlisted one, gets no answer
(REFUSED, or NXDOMAIN for a blocked name).
DHCP advertises this bridge resolver explicitly. Published
records have TTL zero so guest caches cannot keep an old CDN address after the
host rotates its ACL grants. It never forwards other queries upstream, and direct DNS
or DNS-over-TLS to outside resolvers is blocked unless a CIDR grant covers
that resolver. No bridge resolver logs queries. The one exception to "never
forwards" is a template build VM in allowlist mode: its resolver hands names
it does not answer to the node daemon's in-memory DNS stub on the host's
loopback, which answers at once (NXDOMAIN, or NODATA for a granted name's
other record types) and records a name only for the build's
[blocked-name hints](template-builds.md#egress), and only when the query
comes from that bridge's own dnsmasq as recorded by Incus. Nothing leaves the host, and while
the daemon is down those lookups time out rather than fail at once. Enforcement is verified before every start and on readiness;
confirmed drift on a running sandbox (a broadened ACL, a detached bridge ACL,
a replaced NIC) is enforcement loss: new guest work is refused and the VM is
stopped. Evidence that cannot be read refuses new guest work but never stops
or deletes anything on its own.

## What a domain grant means

**A domain grant is a grant to IP addresses, not to a hostname.** The host
resolves each name with its system resolver when the policy is applied (at
create and at every cold boot), permits the resulting public **IPv4**
addresses, and keeps re-resolving them while the sandbox runs. Consequences:

- **Grants are leased and refreshed.** Each resolved address is granted for
  300 seconds. While the sandbox is running, the node daemon re-resolves its
  names about halfway through that lease (every ~150 seconds) and renews the
  grant from the fresh answer, so domain egress keeps working for the life of
  the sandbox. If an answer changes, the new addresses are permitted and the
  old ones are withdrawn. Each completed sandbox refresh logs
  `DNS grant refresh completed`: INFO when grants change (including lease
  renewal), DEBUG when the pass retains unchanged grants. The line includes
  the sandbox ID, domain count, added and removed domain/address pair counts,
  their sum as `changed_addresses`, and `next_refresh_unix_secs` (the next
  eligible refresh, accounting for half-life and retry backoff). It includes
  no domain names or resolved addresses. Skipped and not-yet-due sandboxes
  do not produce completion lines.
- **Refresh failure fails closed.** A lookup that fails keeps the current
  addresses only until their existing lease runs out; it never extends them.
  Failed refreshes are retried every 15 seconds, and if none succeeds the
  addresses are withdrawn when the lease expires (the destination is fenced
  first, so it is never left open). A name that later resolves again is
  re-granted within about a minute. So a stale address can stay permitted for
  at most about 5 minutes after the host's resolver stops returning it.
- **Resolution budgets.** The host shares four resolver workers and a queue
  of four lookups. Each sandbox may have only one queued or running lookup,
  including work still stalled in libc after its caller times out. One sandbox
  cannot occupy every worker or queue slot. Each lookup waits at most 5 seconds;
  create compilation has a 30-second total budget, while refresh resolution has
  10 seconds so a slow refresh yields promptly to the next scheduling pass.
  A stalled lookup holds that sandbox's single in-flight slot until the actual
  lookup returns, even after the caller times out. Names are resolved serially:
  while the slot remains occupied, the sandbox's other names fail transiently
  for that pass and their grants are not extended. Prior grants with at least
  30 seconds remaining are kept at their original expiry; grants nearer expiry
  are withdrawn. Failed refreshes never extend the old grant's expiry.
- **An unfinished refresh is not drift.** A refresh changes the ACL (it
  withdraws denied or replaced addresses first, then permits new ones) before
  it publishes answers and records the result. If it fails in between, for
  example because the resolver config cannot be reloaded, the host treats
  the sandbox as owed a refresh, not as enforcement loss. New guest work is
  refused, the VM keeps running and is never stopped or deleted for it, and
  the refresh is retried every 15 seconds until it records. Only these
  differences are tolerated: addresses withdrawn or blocked, and new
  addresses from a fresh valid answer that the host recorded before
  permitting them. An address the refresh denied must actually be blocked.
  If it is still reachable (the block could not be installed, or someone
  re-added it), that is drift. So is any other change, such as an extra or
  unusual allow, a missing DNS block, a changed bridge setting, or a change
  to the VM's network devices. Those are checked whether or not a refresh
  is unfinished.
- **Only running, healthy sandboxes are refreshed.** A stopped sandbox, one
  whose lease is expiring, or one whose enforcement the host cannot currently
  verify (see above) is not refreshed, and its grants lapse at their lease.
  The exception is an unfinished refresh: it is retried until it records,
  even while the sandbox is stopped (only the host's bridge rules change), so
  the sandbox can start again. A sandbox refused only because a refresh is
  unfinished is refreshed too; any other reason for refusing it still stops
  the refresh. A rule change whose outcome was uncertain (for example, a dropped
  connection to Incus) does not block the sandbox: its address stays blocked
  unless granted, and a refresh removes the rule if it turns up later.
  A stopped or destroyed sandbox stops being refreshed, and so does every
  sandbox while the node daemon is stopped. Grants that lapsed meanwhile are
  re-resolved when the sandbox is running under a connected daemon again.
- **Shared IPs.** While a grant is live, everything served from a granted
  address is reachable: other sites on the same CDN or virtual-hosting IP,
  regardless of the HTTP `Host` header or TLS SNI. WS Sandbox Proxy does not inspect HTTP
  or TLS. If you need hostname-level isolation, put an egress proxy you
  control behind a CIDR grant.
- **Rebinding protection.** If any IPv4 address the resolver returns for a name is
  loopback, private, link-local, CGNAT or another protected range, the whole
  name is refused: at launch the launch fails, and on a refresh the name's
  grant is withdrawn at once. Nothing from such an answer is installed. The
  protected set includes IETF protocol assignments (`192.0.0.0/24`) and
  deprecated 6to4 relay anycast (`192.88.99.0/24`), including individual
  addresses inside them. Explicit CIDR grants intersecting these ranges are
  refused too. Documentation TEST-NET-1/2/3 (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`) are protected in DNS answers and
  CIDR grants as well. This set is not every IANA special-purpose range.
- **IPv4 only.** IPv6 answers for a name are ignored; only its IPv4 addresses
  are granted. A name with no usable IPv4 answer fails the launch closed
  (`UNSUPPORTED_CAPABILITY`); on a refresh its grant is withdrawn at once. IPv6 CIDR grants are refused at launch because
  the bridge is IPv4-only.
- The guest resolves granted names through the bridge resolver, which only
  answers names the host published.

## Qualification status

The enforcement above is tested against shims and the fake runtime in CI.

**Live smoke run (2026-11-15).** An open-egress smoke test ran on two real
Incus/KVM hosts (same LAN, both also on a CGNAT-range overlay network), each
with a healthy egress guard and daemon 1.0.0. A community Ubuntu 26.04
template was built on one host and reached the other through peer image
distribution. One sandbox at a time (1 vCPU, 1024 MiB, egress `open`) then
ran on each host. It proved, on both hosts:

- the sandbox got a bridge DHCP lease and default route, resolved DNS through
  the bridge resolver, and reached the public internet (HTTPS `200`, and TCP
  443 to a public IPv4 address);
- TCP connects from the guest timed out (dropped) to the sandbox's own
  gateway, the LAN router, both hosts' LAN addresses, both hosts' overlay
  (`100.64.0.0/10`) addresses and each host's own Incus bridge address. The
  hosts' SSH and DNS listeners on those addresses and the router's web ports
  answered from the hosts themselves, so those drops were the host's
  enforcement (the egress guard and the bridge ACLs together; the run did not
  tell which layer dropped each packet), not dead addresses;
- TCP to `169.254.169.254`, `10.0.0.1` and `172.16.0.1` also timed out, but
  those addresses had no live listener to compare against, so this shows only
  that nothing answered;
- outbound SMTP (tcp/25) was rejected immediately;
- destroy left no instances, no `wsn-*` bridges and a healthy guard.

It probed TCP only, with no grants, so it did **not** cover deny-all or
allowlist (approved/denied endpoint) mode, the shared-IP limitation, DNS
rebinding and grant expiry, IPv6, UDP or other protocols, lateral
sandbox-to-sandbox or cross-owner traffic (only one sandbox ran at a time),
or guest-root escape attempts. The full
[host isolation qualification](../operations/host-isolation-qualification.md)
is still outstanding: treat the guarantees beyond the smoke's open-mode
blocks as designed and unit-proven, not as independently qualified.

Retained sandbox authority names the exact
revision and the sandbox's current host (or, while offloaded, the host it last
ran on); cold reconnect and restore keep the pinned configuration.

Port exposure remains reserved: an external provider would use an independent
origin/VPS and its own future contract. Capability URL/hostname templates must
be credential-free public strings, and a provider auth mode grants no WS Sandbox Proxy
authority. Ingress and public port helpers currently refuse before allocation.

Template choice and pool placement never widen egress. The create request's
immutable policy applies on whichever member is selected, on later cold
boots, and on a restore of an offloaded disk onto another host, byte for byte.
A restore never narrows the recorded policy to fit a host: an open-egress
sandbox restores onto another user's host only when that host allows open
egress for others, and every restore target needs a healthy egress guard
([disk offload](./sandboxes.md#disk-offload)). Reserved `network.ingress`/`network.ports` options
refuse with `UNSUPPORTED_CAPABILITY` before idempotency/receipt persistence.
`portExposure` reserves an external provider, public URL template, nullable
hostname template, protocols and authMode, all inactive. Its URL/hostname
strings must contain no credentials because capabilities are readable without
a resource scope. No WS Sandbox Proxy cookie, SDK or host credential is implied by a
provider authMode. An independent sidecar origin/VPS remains outside WS Sandbox Proxy's
CSP/CORS allowlists; sidecar traffic/grant credentials are not defined here.

## Registry and CDN pulls

Docker-in-VM qualification starts with exact domains `registry-1.docker.io`,
`auth.docker.io`, `production.cloudfront.docker.com`, `index.docker.io`. These
are starting grants, not a promise of complete/stable registry routing. Pin a
public platform digest; use uncached layers and no registry login. Add a further
exact domain only after a failed pull yields sanitized hostname/status evidence,
then create a new sandbox with that immutable policy. Never save tokens, signed
URLs, headers or raw Docker debug output; do not add automatic redirect discovery.

A grant is host-resolved destination IP access, not HTTP hostname or TLS identity
isolation. Shared CDN IPs broaden reachable services. DNS rotation during an in-flight request and IPv6-only endpoints can refuse a pull. Verify host
resolution and the guest's supported bridge DNS path; this bridge is IPv4-only.
Existing 300-second leases refresh around 150 seconds, retry failed lookups every
15 seconds, and expire/fail closed. Record observed hostnames and refresh timing
in live evidence. Do not add wildcards, arbitrary CIDRs or proxies, or weaken
enforcement. (This qualification uses allowlist mode on purpose.) Docker preparation and 32-GiB persistence assertions are
in the [template recipe](../operations/templates.md#docker-inside-a-32-gib-vm-root).

## Shared-host trust and qualification

Users of a pool with foreign hosts must trust the operators. An incus-admin
user on a host can reach every VM on it. Dashboard terminal disablement and API scope do
not isolate guests from local administrators. Contributors consent to foreign
guest traffic leaving their network/IP (open internet for other users is a
separate, default-off host setting, `allow_open_egress_for_others`), alongside host resource consumption.
Domain grants identify host-resolved IP destinations, not HTTP/TLS identity.
Live A/B guest lateral-denial checks must cover IPv4/IPv6 and both directions,
with external egress controls. Model rules/fake-wire tests do not close this
release gate. See the explicitly invoked
[operator qualification](../operations/sharing-terminal-qualification.md).
