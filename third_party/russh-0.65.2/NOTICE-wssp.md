# Notice of modification (wssp)

This directory is russh 0.65.2 as published on crates.io
(`russh-0.65.2.crate`, SHA-256
`78229f06e4d96d83bea5f5133ad3b6e4b5f0ce22d8e31c1ff7243ec8e18d5ba1`; upstream
commit `56a999871aa134072e4f2a7395fe2de313870e21` of
<https://github.com/warp-tech/russh>, see `.cargo_vcs_info.json`), licensed under
the Apache License, Version 2.0 (<https://www.apache.org/licenses/LICENSE-2.0>).
Copyright Pierre-Étienne Meunier and the russh contributors.

The wssp project changed these files (Apache-2.0 §4(b)); every change is in
`../russh-0.65.2.patch`, and `cargo xtask vendored-russh --check` proves that the
published crate plus that patch is exactly this directory:

- `src/server/mod.rs`: a `Config::manual_window` flag (default off), and the
  key-exchange bound below applied to what the client sends.
- `src/session.rs`: `Encrypted::consume_window`, `Encrypted::grant_window` (not
  for a channel that is unconfirmed or closing) and
  `Encrypted::receive_window_total`, with unit tests.
- `src/server/encrypted.rs`: with `manual_window`, received data only uses up the
  channel's receive window instead of refilling it.
- `src/server/session.rs`: `Msg::WindowGrant` and `Handle::grant_window`, sent on
  the session's priority queue; with `manual_window`, the bound on what the
  client may send during a server-initiated key exchange covers the window
  granted across channels (saturating) and counts channel data by payload
  (nothing for a channel that is not open), with unit tests.
- `src/lib.rs`: `#![allow(warnings)]`, so the crate builds under the workspace's
  `-D warnings`.

This file is the only file added. Everything else is byte-identical to the
published crate; only the executable bit the crate sets on `src/pty.rs` and
`benches/ciphers.rs` is dropped (neither is a program).
