# Contributing to phi-crypto

Thank you for your interest in contributing. phi-crypto is the **cryptographic core** of the Phi
network — the privacy-preserving cryptography behind proof of personhood, authentication, and
verifiable credentials. *The network does not claim; it shows*, and open, verifiable code is part of
that promise. Because a bug here is amplified across phi-chain, the mobile app, and the web,
contributions are held to a high bar.

## Scope

This repository contains one Rust crate compiled to three outputs (WASM / FFI / C-ABI): BBS+
unlinkable selective disclosure (`bbs`, `bbs_2023`), dual-curve DID operations (`did`), a WebAuthn
verifier (`webauthn`), private-participation primitives (`voting`, `semaphore`), and the C-ABI
boundary (`ffi`). Company backend services, websites, and apps are **not** part of this repository.

## The non-negotiable rule: never hand-roll cryptography

Every cryptographic primitive **must** delegate to a mature, audited crate (`docknetwork/crypto` and
`pairing_crypto` for BBS+, RustCrypto's `k256`/`p256`/`sha2`, arkworks/blst for BLS12-381). New crypto
code that reimplements a primitive instead of wrapping an audited one will be rejected. The BBS+
suites are pinned behind the single `CryptoSuite` trait — do not bypass it.

## Code standards

- Rust stable. `#![deny(unsafe_code)]` everywhere **except** the reviewed `ffi` module — the only
  place `unsafe` is allowed, and it must never let a `panic` cross the C-ABI boundary (return an error
  code / `0` instead).
- `cargo clippy --all-targets -- -D warnings` must pass clean.
- Constant-time comparison of secret material with `subtle` — never `==`; zeroize secret material
  (`zeroize`) after use.
- Enforce low-S on signing; verifiers must **fail safe** — reject on any doubt.
- `Cargo.lock` is committed; all crates are pinned (git dependencies pinned to a `rev`).
- Comments in **English**, concise and standard (rustdoc on public APIs); identifiers, code, and
  public API names in English. Every source file carries the `// SPDX-License-Identifier: Apache-2.0`
  header.

## Tests (mandatory)

No change is merged without tests. For proof-related changes, **round-trip** and **unlinkability**
tests are mandatory.

```bash
cargo test                                   # unit + integration (offline, from vendor)
cargo test --release -- --ignored            # standard / W3C test vectors
cargo clippy --all-targets -- -D warnings
```

Required coverage:

- **round-trip:** sign → derive proof → verify.
- **unlinkability:** two proofs derived from one credential are not correlatable.
- reject a proof under the wrong issuer key; reject a revoked or tampered credential.
- **WebAuthn:** reject a wrong challenge or origin, a missing User-Presence, and a high-S signature.

Pull requests that reduce coverage or skip these will not be merged.

## Branches & commits

- Base work on `main`. Branch naming: `feat/…`, `fix/…`, `docs/…`, `test/…`, `chore/…`. Keep pull
  requests small and focused — one logical change each.
- [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <summary>` with
  types `feat|fix|docs|test|refactor|chore|perf|ci` and a module scope — for example
  `feat(bbs): add predicate proof`, `fix(webauthn): reject high-S`.
- Sign off your commits (DCO): `git commit -s`.
- Every pull request should describe what changed and why, include tests, and note any
  soundness-affecting implications. Cryptographic changes require additional maintainer review.

## Security issues

**Do not open public issues for security vulnerabilities.** See [`SECURITY.md`](./SECURITY.md) —
report privately to **security@portphi.com**.

## License

By submitting a contribution you agree it is licensed under this repository's
[Apache License 2.0](./LICENSE) (per Section 5 of the license). The Phi protocol and the original
source in this repository are the intellectual property of Homaan Smart Data Co.

---

*Homaan Smart Data Co. — portphi.com*
