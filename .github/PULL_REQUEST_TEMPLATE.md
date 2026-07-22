<!-- SPDX-License-Identifier: Apache-2.0 -->

## Summary

<!-- What does this PR change and why? -->

## Checklist

- [ ] Commit messages follow Conventional Commits (`feat(scope): ...`, `fix(scope): ...`, ...).
- [ ] `cargo test --offline` passes (unit + integration + KAT).
- [ ] `cargo clippy --all-targets -- -D warnings` is clean.
- [ ] `cargo build --offline --target wasm32-unknown-unknown` still builds.
- [ ] New/changed source files carry the `// SPDX-License-Identifier: Apache-2.0` header; comments are concise English; public APIs have rustdoc.
- [ ] No secrets, keys, or credentials added (code, tests, or fixtures).
- [ ] No hand-rolled cryptography — primitives delegate to an audited crate; consensus/crypto-sensitive changes flagged for extra review.
- [ ] If dependencies changed: `Cargo.lock` updated and `vendor/` re-generated (`cargo vendor`) so offline builds keep working.
- [ ] Commits are signed off (DCO): `git commit -s`.
