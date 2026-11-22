# Vendored third-party crates

## russh

`third_party/russh-0.65.2` is russh 0.65.2 from crates.io plus
`third_party/russh-0.65.2.patch`, and nothing else except `NOTICE-wssp.md`
(Apache-2.0 §4(b)). The patch adds `server::Config::manual_window` and
`server::Handle::grant_window`: a channel's receive window then grows only when
`wssp ssh --stdio` grants it, so a stuck channel holds back only its own sender
(see `apps/cli/src/commands/sandbox/ssh/input.rs`).

How it is wired:

- the root `Cargo.toml` `[patch.crates-io]` points `russh` at the directory;
- `apps/cli/Cargo.toml` pins `russh = "=0.65.2"`, so the patch is always used;
- `cargo xtask vendored-russh --check` (CI, `docs-drift`) proves the directory is
  the checksum-pinned crate plus the patch, byte for byte, and that `Cargo.lock`
  takes russh from the path (no registry source, no `[[patch.unused]]`);
- `cargo xtask vendored-russh --advisories` checks RustSec advisories and yanks
  for the vendored version. cargo-deny does not: it matches advisories only to
  crates with a registry source, and a path `[patch]` has none. CI runs it in
  its own `vendored-advisories` job (independent of cargo-deny) weekly, on
  manual runs, and on a push or PR that changes `Cargo.lock`, `Cargo.toml`,
  `apps/cli/Cargo.toml`, `apps/cli/deny.toml`, `third_party/**` or
  `apps/cli/xtask/**`; a new disclosure therefore fails the weekly run, not
  unrelated PRs. Malformed advisory or index metadata fails it too, and it
  refuses a prerelease vendored version;
- Dependabot ignores russh (`.github/dependabot.yml`): an upgrade goes through
  the steps below, never through a version bump in `Cargo.toml` alone.
- `third_party/russh-key-fixtures.sha256` is the only exception
  `pnpm policy:template-secrets` makes to "no private key in git". russh's own
  sources hold upstream test keys and PEM header constants (`src/helpers.rs`,
  `src/keys/mod.rs`, `src/keys/format/mod.rs`, `src/keys/format/tests.rs`).
  Each line pins one of those files as `<sha256>  <path>` (plain path
  characters only). The scanner accepts a private-key match only at exactly a
  pinned path (`git grep -z`, so a path is never split at a `:`), and only
  while that literal file (no symlinked component) hashes to its pin and no
  line of `russh-<version>.patch` names it. Any edit to the file, the same keys
  at any other path, a missing or malformed pin file, or a patch line naming
  the file (a hunk, mode, rename or copy header) fails the scan. `--check`
  proves every pin is the published crate's own bytes of that file, unpatched,
  and holding a key header, so the exception only ever covers byte-identical
  upstream content; its patch parser refuses any header it does not apply
  (mode, rename, copy, binary, quoted paths), and the scanner grants no
  exception at all for a patch outside that form or for a pin of a copy the
  root `Cargo.toml` does not patch in. The scanner trusts the hashes only as
  far as `--check` proves them: CI runs `--check` on every change under
  `third_party/**`, but `pnpm verify` does not, so run it after editing a
  pin. There is no path or glob exemption, and nothing changes what counts as
  a key.

Change the vendored code only by editing the tree and regenerating the patch
(step 3 of "When the patch does not apply").

### Upgrading russh

When `--advisories` fails, or a russh release is wanted:

1. From `apps/cli`, run `cargo xtask vendored-russh --update <version>`. It:
   - refuses a prerelease (wssp vendors stable releases only), and refuses
     unless the current tree passes `--check` (nothing local is lost);
   - takes the new crate's checksum from the crates.io index, refuses a yanked
     release, and fetches and checks the `.crate`;
   - re-applies the patch: a hunk may move, but every context and removed line
     must still match; otherwise it stops and changes nothing;
   - computes, in memory and before writing anything, the new tree, its
     restated patch (checked to rebuild the tree strictly) and the rewrites of
     the version, checksum and upstream commit in the files listed in
     `REWRITTEN` (`apps/cli/xtask/src/vendored.rs`), and the key-fixture pins
     re-pinned to the new crate's files (a file that is gone, now patched or
     without a key is dropped and named; add a new pin by hand, and `--check`
     then proves it): both manifests (checked to
     pin and patch the new version), the xtask constants,
     `THIRD-PARTY-LICENSES.md`, this file, the CI comments and the docs that
     name the copy;
   - writes `third_party/russh-<version>` with `NOTICE-wssp.md`,
     `third_party/russh-<version>.patch` (hunk lines restated) and the
     rewrites, then re-verifies the new tree, runs `cargo update -p russh`, the
     wiring check and `cargo xtask sync-docs`;
   - only after all of those succeed deletes the old directory and patch. If any
     of them fails, it restores every rewritten file, `Cargo.lock` and the
     `AGENTS.md` mirrors from their saved bytes, removes the new directory and
     patch, and reports the failure: the repository is as before. Once they
     have succeeded the new version is in use; if deleting the old directory
     or patch then fails (a read-only subdirectory, say), the command still
     succeeds and prints a warning listing every path left behind. Nothing
     references them: remove them by hand (`chmod -R u+w` first if read-only,
     then `rm -rf`) before committing.
2. Review: `git diff`; `git grep -n 'russh.<old version>'` (CHANGELOG entries
   stay); the upstream CHANGELOG between the two releases (anything about
   windows, `adjust_window_size`, channel data, the server session loop or the
   priority queue needs a closer look at the patch); new or changed
   dependencies in `Cargo.lock` (cargo-deny's licence and source checks).
   `NOTICE-wssp.md` lists the changed files: keep it true.
3. Run the checks below.

#### When the patch does not apply

`--update` stops on the first hunk whose context changed. Rebase by hand:

1. Unpack the new crate somewhere outside the repository and copy it to
   `third_party/russh-<version>` (no `.cargo-ok`).
2. Re-make each change of the old patch there (the old patch and `NOTICE-wssp.md`
   say what each one is for); copy `NOTICE-wssp.md` over and update its version,
   checksum and commit.
3. Write `third_party/russh-<version>.patch`: in an empty scratch directory, put
   the unpacked crate as `a` and a copy of the edited tree without
   `NOTICE-wssp.md` as `b`, then `git diff --no-index --no-prefix a b > patch`
   (paths `a/…`/`b/…` relative to the crate root, in-place edits only).
4. Update by hand what `--update` rewrites: `VERSION` and `CHECKSUM` in
   `apps/cli/xtask/src/vendored.rs` (the checksum is the crates.io index `cksum`,
   which `cargo` records in `Cargo.lock` for a registry crate), the `=` pin in
   `apps/cli/Cargo.toml`, the `[patch.crates-io]` path in `Cargo.toml`,
   `THIRD-PARTY-LICENSES.md`, the other files in `REWRITTEN`, the paths and
   hashes in `russh-key-fixtures.sha256` (`sha256sum` of each unpatched pinned
   file, sorted by path; drop any file the patch now edits); delete the old
   directory and patch; `cargo update -p russh`; `cargo xtask sync-docs`.
5. Run the checks below.

### Checks after any change

From the repository root (heavy jobs as the repository rules say):

```sh
cd apps/cli && cargo xtask vendored-russh --check && cargo xtask vendored-russh --advisories && cd ../..
cargo test -p xtask
cargo test -p wssp --test russh_manual_window   # the patch still has effect
WSSP_REQUIRE_SSH_TOOLS=1 cargo test -p wssp --test ssh_stdio   # windows end to end
cargo test -p wssp --lib ssh::
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTFLAGS="-D warnings" cargo build -p wssp --all-features   # the vendored crate builds under CI's flags
cd apps/cli && cargo deny check && cd ../..
```

`tests/russh_manual_window.rs` runs a russh client and server in process: with
`manual_window` the server's announced window does not grow until
`grant_window`, and grows by exactly the grant; without it russh refills it (the
control that proves the test can see a refill). It fails if a rebase loses the
data-arm hunk in `src/server/encrypted.rs` or the grant in
`src/server/session.rs`. The other five are the upstream branch's: data uses up the
window (a grant of `u32::MAX` fits only then), and a server-initiated key
exchange with granted data in flight, large or in one-byte packets, for an
open channel or one the server has just closed, does not end the session
(fails if the rekey bound ignores grants, counts whole messages or charges
data it drops). The vendored crate's own unit tests cover grants to unconfirmed or
closing channels (`src/session.rs`) and the rekey bound's cost per message
type, its saturation and the cut-off of a flooding peer
(`src/server/session.rs`). The crate is not a workspace member, so CI's
`vendored-russh-tests` job runs them from a copy outside the workspace
(`cargo test --manifest-path <copy>/Cargo.toml --lib --locked`). In `tests/ssh_stdio.rs`,
`a_jammed_forward_stops_only_its_own_client`,
`a_command_or_a_forward_gets_one_wssp_window`,
`a_client_that_sends_past_the_window_has_its_channel_reset` and
`window_grants_survive_frequent_rekeys` prove the same through OpenSSH and the
endpoint.

### When to drop the vendored copy

As soon as a russh release offers the same thing (a server option under which
received data does not refill the window, plus a non-blocking way to grant
window to a channel; proposed upstream with this patch, which is the
`server-manual-window` branch of `christopher-kapic/russh` with only
`#![allow(warnings)]` added):

1. switch `apps/cli/src/commands/sandbox/ssh/` to the upstream API;
2. delete `third_party/russh-*` and its patch (with
   `russh-key-fixtures.sha256` and the scanner's `KEY_FIXTURE_PINS` support in
   `scripts/check-template-secret-patterns.mjs`), the `[patch.crates-io]` entry,
   the russh section's "modified" paragraph in `THIRD-PARTY-LICENSES.md`, the
   `vendored-russh` xtask and its CI steps, and the russh `ignore` in
   `.github/dependabot.yml`;
3. keep or relax the `=` pin as for any other dependency; cargo-deny then sees
   russh's advisories again;
4. keep `tests/russh_manual_window.rs` (renamed to the upstream API): it pins
   the behaviour wssp relies on.
