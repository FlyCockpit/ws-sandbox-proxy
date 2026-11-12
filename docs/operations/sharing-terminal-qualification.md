# Sharing and terminal operator qualification

Run this checklist before production with the host operator's approval for
the test resources, policy changes and Incus VMs. Use disposable accounts and
an isolated host. Automated checks do not authorize changes to a live host.

Record each stage as PASS, FAIL or UNVERIFIED, with redacted assertions and the
evidence type. Unit, DOM, disposable-PG and fake-wire evidence do not establish
live VM or network isolation. Keep capacity/storage calibration and Docker
qualification in the separate [capacity runbook](../guide/hosts.md#capacity-and-storage-qualification).

## Preparation

- Record the integrated server/worker/daemon/SDK commit and build artifact IDs.
  All peers must be the same commit; matching version strings alone are
  insufficient. Expire outstanding tickets.
- Run the repository gates in [testing](../testing.md). Record their outputs,
  the production web build and `pnpm check:lazy-xterm`. A failed gate blocks rollout.
- Arrange two real disposable accounts A/B, finite leases, a dedicated test path,
  measured headroom for at most two small VMs, and a planned maintenance period.
  Record only test resource IDs and initial live/root/transfer/PTY holds.
  Do not dump cookies, OTPs, invite links, credentials, config or environment.

## Qualification stages

1. A owns the enrolled test host and pool PA. A shares PA with B. B owns PB and
   gives A contribute permission; A explicitly contributes its own host to PB.
   Exercise default BOTH, use-only/contribute-only, nullable caps and owner
   identity for duplicate slugs. Check foreign explicit-host management refusal.
2. Test verified-email direct grants, explicit bearer/email-only acceptance,
   forwarding warning, rotation/expiry and EN/es-MX mail. In a separately
   approved closed-signup window, require token plus exact target email, prove
   the mailbox, reopen the original link, then explicitly accept. Missing mail
   proof leaves that substage UNVERIFIED.
3. B registers its own exact fingerprint through PA's opaque member choice,
   with no owned host. Mint B's SELECTED key with PA plus its revision and no
   foreign host grant. Create one small VM with a finite lease. Record the
   displayed grace quote, submitted expectation and acceptedGraceSeconds DTO.
4. B uses its guest terminal, commands and only the dedicated test-path files.
   A sees opaque allocation/lifecycle/expiry metadata without creator identity,
   labels, envs, file contents or guest execution controls. B gets no foreign
   host details, heartbeat or online state from shared members. Admin and
   impersonated sessions must not acquire execution authority.
5. With B's guest running, A explicitly enables the local host terminal.
   Required mode must observe the ten-minute factor cooldown and a fresh unused
   code. Reuse must fail. Run only harmless identity/resize/detach checks;
   never enter B's guest through Incus/local administrator powers.
6. A locally lowers TOTP to optional, attaches explicitly, then raises it from
   the dashboard. Require persisted ACK; timeout/disconnect remains unconfirmed.
   Offline raises refuse without saved requests. The dashboard cannot lower or
   enable terminals. Hot local off closes pending/live host PTYs within two
   seconds without restarting the relay; B's guest continues. Restore required.
7. Within measured headroom, use no more than two small VMs. Set B's share caps
   at actual RAM/vCPU/disk usage; extra create must refuse definitively. Test
   PB's contributed-member percentages and PA's exemption from member caps,
   while both pools remain inside the one host budget.
8. Withdraw one path while another fits caps: verify continued execution and
   moved current usage. Remove the last path: guest IO/terminal refuses before
   scanning, then STOP retains disk. Restore access before destroy commits and
   cold-start the sandbox's retained disk. Disable alone must block only new placements.
   Grace expiry/shortening and restore/delete races use hermetic injected-clock
   tests; do not wait days or lower production minimums for live qualification.
9. With one A and one B guest, test guest-to-guest lateral denial in both
   directions over IPv4 and IPv6 at known test endpoints, plus permitted external
   egress controls. Do not probe host/admin endpoints. Missing hardware/headroom
   leaves the live network release gate open.
10. Revoke a disposable session/sign out everywhere/ban and verify both terminal
    targets close and cached tickets refuse. Ban must not start deletion grace.
    Active host credential revocation requires its own maintenance approval;
    otherwise mark that live substage UNVERIFIED and retain hermetic evidence.
11. Destroy only the recorded test guests. Require positive original-storage and
    network cleanup proofs and baseline live/root/transfer/PTY holds. Preserve
    unresolved IDs/obligations. Restore reviewed caps, memberships and local
    required-TOTP policy. Never use broad cleanup or storage forget.

## Evidence receipt

Record revision/artifact IDs, stage, account/resource aliases, assertion,
evidence type, result, remaining obligation and restoration status. Screenshots
must redact secrets and unrelated users. Offline STOP is enforced on reconnect
or the effective local lease where possible; a powered-off daemon cannot enforce
a deadline. Dead storage may keep host/creator account deletion blocked beyond
the pool's grace. Do not mark deployment or live isolation passed from automated
fixtures alone.
