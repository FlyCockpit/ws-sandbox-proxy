# Contributing to WS Sandbox Proxy

This project is preparing its first release, 1.0.0. Open an issue to discuss
larger changes before starting. Everyone participating follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Report vulnerabilities privately using [SECURITY.md](SECURITY.md); do not open
public issues or pull requests containing security details.

## Licensing and the Developer Certificate of Origin

WS Sandbox Proxy is licensed under `MIT` (see [LICENSE](./LICENSE)). Contributions are accepted under the same license: by submitting a contribution you agree that it is licensed to the project and its users under `MIT` (inbound = outbound). There is no separate contributor license agreement.

Every commit must be signed off to certify the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) 1.1, reproduced below. Sign off by adding a `Signed-off-by` trailer with your real name and an email address you can be reached at:

```text
Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` adds the trailer for you, using your `user.name` and `user.email`.

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Development setup

Follow [local development](README.md#local-development): Node 26 LTS (26.13.1+),
pnpm 12.18.0, Postgres 18 and Valkey 9. Install pnpm with
`npm install -g pnpm@12.18.0`, then run `pnpm install`, `pnpm setup:app` and
`pnpm dev`. The Rust CLI uses the workspace's pinned toolchain separately.

## Repository rules

Read [AGENTS.md](AGENTS.md) and, for Rust work, [apps/cli/AGENTS.md](apps/cli/AGENTS.md).
Keep changes focused and discuss new dependencies first. Preserve authentication,
owner scoping, rate limits and CSRF/CORS/CSP protections. Never commit secrets
or reset a database to make a change pass. Schema changes use `pnpm db:migrate <name>`, SQL review and
`pnpm db:migrate:apply`; commit history and fixtures. See
[schema migrations](docs/schema-migrations.md).
User-facing strings go through `t()`; environment variables, public routes and
authorization gates follow the documented registration and generation rules.

## Checks

Before opening a pull request, run:

```sh
pnpm verify:fast
```

For Rust changes, also run from the repository root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked -- --test-threads=1
cargo test --doc --workspace --locked
cargo xtask sync-docs --check
```

Unit tests mock database and queue I/O and use `FakeRuntime`. Database race and
locking proofs use `pnpm test:pg` with disposable PostgreSQL. Live Incus VMs
require separate operator authorization. See [testing](docs/testing.md).
Never bypass verification hooks.

## Pull requests

Describe the problem, resulting behavior and checks run in the pull request
template. Sign off every commit under the DCO above. Update relevant guides,
contracts and generated outputs using their documented generators.
