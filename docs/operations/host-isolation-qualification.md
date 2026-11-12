# Host isolation qualification checklist

Run this manual checklist on an isolated, disposable Incus/KVM host before
production. Automated tests do not execute these scenarios or establish live
hardware isolation. Plan the test endpoints, resource limits and cleanup with
the host operator before starting.

An operator must separately approve an isolated, disposable Incus/KVM host and
test endpoints. Never use production credentials, data, shared projects, public
probe targets, or arbitrary Internet destinations. Record explicit operator
approval, run id, host kernel/Incus versions, firewall backend, IPv4/IPv6
topology, template fingerprint and policy hash before creating anything.
All resources and endpoint listeners must be run-scoped and positively owned;
cleanup must refuse foreign or ownership-ambiguous objects. Failed cleanup is
a failed qualification, not permission to broaden deletion.

## Endpoint fixture

Provision operator-controlled endpoints A (approved unique IPv4), B (denied
unique IPv4), C (approved and denied virtual hosts sharing one IP), D (DNS
rotation/rebinding endpoint), V6 (controlled IPv6), and L (a second sandbox,
host services and another tenant's controlled private endpoint). Log requests
and capture packets on guest, dedicated bridge and destination. Synchronize
clocks. Use TCP and UDP listeners and distinct ports/nonces; collect positive
reachability controls from an operator namespace outside the sandbox.

## Required scenario matrix

1. **Approved/denied endpoints.** Deny-all reaches neither A nor B except
   narrowly required bridge DHCP/DNS. An explicit grant reaches A and still
   cannot reach B, unlisted ports/protocols where the policy excludes them,
   alternate DNS or DoT. CIDR grants authorize their documented IP scope.
   Repeat after create, cold reconnect, host-daemon restart and cleanup retry.
2. **Shared-IP limitation.** Grant one domain at C, request both approved and
   denied HTTP Host/TLS SNI identities at that IP. Document that IP enforcement
   is NOT HTTP hostname or TLS identity isolation; shared-IP access is an
   expected limitation, not a successful hostname-isolation claim.
3. **DNS rebinding.** D rotates public IPv4 answers and TTLs, then returns
   loopback, RFC1918, link-local, metadata, mixed authorized/forbidden sets,
   CNAME chains and malformed/unavailable answers. Verify rejected grants
   fail closed, old destinations expire even during daemon downtime, no
   arbitrary upstream DNS is usable, restart recovers denial obligations,
   and managed expiry/refresh never falsely convicts a healthy sandbox.
   Keep a granted name in use for well over 300 s on a running sandbox and
   verify the daemon's scheduled refresh (about every 150 s) renews it, a
   rotated answer moves the grant, and a resolver outage withdraws it at the
   lease expiry.
4. **IPv6.** Attempt global IPv6, ULA, link-local, neighbor discovery,
   router-advertisement/SLAAC, DNS AAAA and IPv4-mapped addresses. With the
   current IPv4-only bridge policy, none may create an egress bypass.
5. **Lateral traffic.** Attempt A-to-L cross-sandbox, cross-owner, bridge-peer,
   host control socket, host resolver/admin service, multicast/broadcast,
   ARP/MAC spoof and alternate gateway paths. Verify no lateral admission,
   including while one bridge's ACL attachment is deliberately detached.
6. **Guest-root escape attempts.** From root INSIDE the disposable guest,
   alter routes/resolver/MAC/IP, add interfaces, spoof DHCP, raw sockets,
   nftables/iptables changes, tunnels/proxies over unauthorized destinations,
   alternate DNS/DoT/DoH and attempts to access host files/Incus sockets.
   Guest privilege must not modify host enforcement or acquire credentials.

## Drift, recovery and evidence

Deliberately broaden an owned ACL, detach bridge ACLs, weaken deny defaults and
replace the effective NIC. Record detection time, durable Prepare, immediate
ownership-fenced stop, refused next dispatch, eventual confirmed VM/network
absence, immutable-intent completion and both connected capacity releases.
Repeat with storage unavailable then healed, process restart, stale lease
renewal during observation, and an old stop worker racing stronger destruction.
Unreadable evidence must refuse work WITHOUT stop/delete; a foreign-tagged
control must remain byte-identical and untouched, with journaled refusal.
Healthy transitions and repaired current-arm controls must not be convicted.

Archive packet captures, endpoint logs, guest/bridge counters, exact commands
actually run, immutable policy/plan snapshots, lifecycle/status journals,
server/local reservation observations, timing, resource ownership inventory and
cleanup absence proof. Explicitly separate expected shared-IP limitations,
control failures and unmet scenarios. A pass requires positive allowed probes,
negative denied/lateral/root probes, restart/cleanup convergence and reviewed
packet evidence. Compiler, shim and fake test results alone NEVER qualify.
