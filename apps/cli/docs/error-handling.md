# Error handling

## Default: `anyhow`

Application code (everything in `src/`) uses `anyhow::Result<T>`. It gives you
cheap `?` propagation and a context chain that prints a clear story:

```rust
let text = std::fs::read_to_string(&path)
    .with_context(|| format!("reading config file `{}`", path.display()))?;
```

`main.rs` renders errors through `exit::message_for`, writes diagnostics to
stderr via `src/output.rs`, and exits with a code from `src/exit.rs`. That's all
most CLIs need.

## When to reach for `thiserror`

Add `thiserror` only if you split logic into a **library crate with a public,
stable error type** that callers match on. For a single binary, it's overkill —
`anyhow` is better because you don't have to enumerate every failure.

If you do need it:

```sh
cargo add thiserror
```

```rust
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("no item named `{0}`")]
    NotFound(String),
    #[error("database error")]
    Db(#[from] rusqlite::Error),
}
```

Return `Result<T, StoreError>` from the library; the binary can still wrap those
in `anyhow` with `?` and add context.

## Exit codes

`src/exit.rs` defines the stable codes. To make a specific error exit non-`1`,
attach a `CodedError`:

```rust
use crate::exit::{CodedError, ExitCode};
return Err(anyhow::Error::msg("no profile named `default`"))
    .context(CodedError::new(ExitCode::NotFound));
```

`code_for` walks the error chain and returns that code; everything else exits
`1`.

## Rules

- Add context at boundaries (file, network, parse), not on every line.
- Quote identifiers/paths in `` `backticks` ``.
- Never `unwrap()`/`panic!` in non-test code — clippy enforces this.

## Host resource detection

`wssp host config show` treats a daemon resource detection error as diagnostic data,
not a command failure. JSON has null `detected` and a short scalar
`detectionError`; text stays valid TOML. Raw daemon/subprocess errors never enter
these fields. The output states the inspected runtime and retains configured
overrides. The resource query uses the existing bounded Incus host timeout.

`wssp host run` proceeds with a warning after detection failure when both valid
capacity overrides are available. Otherwise its error names only the missing
`--sandbox-memory-mib` and/or `--max-sandbox-cpu-count` flag. Flags override
TOML independently. Invalid overrides fail; overrides above detection warn but
are accepted. Warnings contain scalar policy descriptions, no subprocess text.

A local allocation conflict retains the larger memory reservation and refuses
that sandbox's start, without declaring the host globally unschedulable. It is
not proof that a previous effect stopped. Existing receipt replay precedes any
fresh capacity acquisition. See the [hosts guide](../../../docs/guide/hosts.md#guest-ram-budget-and-cpu-cap).

## Sized launch refusals

Protocol 10.6 launches require both accepted size fields. Immutable intent,
lease, placement or effective-config disagreement uses `vm_size_mismatch`;
it never proves a prior VM absent. Reconnect refusals are UNKNOWN, including
definite host failures, and preserve the shared slot/RAM hold until positive
inventory or completed cleanup evidence. A first proven-unsent create can use
the existing failure/release path; a refused redispatch cannot. No success
size echo is needed: every actual start verifies exact effective limits.
