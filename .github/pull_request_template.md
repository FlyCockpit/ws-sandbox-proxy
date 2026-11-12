## Summary

<!-- What does this change do, and why? Link related issues (for example "Closes #123"). -->

## Checks run

- [ ] `pnpm verify:fast`
- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --all-targets --locked` (Rust changes only)
- [ ] Other (describe):

## Checklist

- [ ] Every commit is signed off (`git commit -s`) under the [Developer Certificate of Origin](https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/CONTRIBUTING.md#licensing-and-the-developer-certificate-of-origin).
- [ ] If this adds or changes an oRPC procedure, route gate or schema field, the gate is registered in `packages/api/src/index.ts` and `pnpm policy:access-matrix` passes.
- [ ] User-facing strings go through `t()`; new environment variables, public pages and docs are updated as described in `AGENTS.md`.
- [ ] No secrets, guest content or personal data in code, tests, fixtures or logs.
