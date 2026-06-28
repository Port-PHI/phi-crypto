# Governance

This document describes the governance of the **phi-crypto** open-source project — how this repository
is stewarded, how decisions are made, how changes are reviewed, and how releases are cut.

It concerns the **project**, not the protocol. It is separate from the *on-chain* governance of the
Phi network (the one-human-one-vote mechanism), which is a feature of the blockchain and is documented
there.

## Mission

phi-crypto is the cryptographic core of an identity-first network — the privacy-preserving
cryptography behind proof of personhood, authentication, and verifiable credentials. Because a flaw
here would be amplified across the chain, the mobile app, and the web, this project is run to the
highest standard of cryptographic rigor and review.

## Principles

- **Never hand-roll cryptography.** Every primitive is a thin, reviewed wrapper over a mature, audited
  crate. New cryptography that reimplements a primitive instead of wrapping an audited one is not
  accepted.
- **Open and verifiable.** The cryptography is public and auditable, with known-answer vectors
  published alongside the code.
- **Fail safe.** Verifiers reject on any doubt; no panic crosses the C-ABI boundary.
- **Correctness over speed.** Cryptographic changes ship only when they are complete, tested against
  standard vectors, and reviewed.

## Stewardship

phi-crypto is stewarded by **Homaan Smart Data Co.** under the
[`Port-PHI`](https://github.com/Port-PHI) organization. During the pre-mainnet phase the project
follows a maintainer-led model: the steward sets direction and has final say on changes, with all
work happening in the open.

## Roles

- **Steward (Homaan Smart Data Co.)** — owns the project's direction, the release process, and final
  decisions; holds the project's intellectual-property and trademark rights.
- **Maintainers** — review and merge changes, uphold the standards in this document and
  [`CONTRIBUTING.md`](CONTRIBUTING.md), and triage security reports. Maintainers are listed via
  [`CODEOWNERS`](.github/CODEOWNERS).
- **Contributors** — anyone who proposes an issue or a pull request. Sustained, high-quality
  contributions may lead to a maintainer invitation at the steward's discretion.

## Decision-making

- Changes land via pull requests reviewed under [`CODEOWNERS`](.github/CODEOWNERS); every change is
  reviewed before it merges to `main`.
- **Cryptographic and soundness-sensitive changes** — signature schemes, ciphersuites, key-type
  acceptance, the proof systems, and the FFI boundary — require explicit maintainer review and a clear
  rationale citing a standard or an audited reference.
- Substantial design changes should be raised as an issue first, so the approach can be discussed
  before implementation.
- Disagreements are resolved through discussion on the issue or pull request; where consensus is not
  reached, the steward decides.

## Review & quality bar

- No change merges without tests; for proof-related changes, round-trip and unlinkability tests are
  mandatory, and pull requests that reduce coverage are not merged.
- `cargo clippy --all-targets -- -D warnings` must pass clean, and the build and test suite must be
  green and fully offline (vendored, locked).
- Continuous integration must pass on every pull request before merge.

## Releases

- Versioning follows [SemVer](https://semver.org/); user-visible changes are recorded in
  [`CHANGELOG.md`](CHANGELOG.md).
- Release tags are signed. The cryptographic suites are versioned (`phi-bbs-v1`, `bbs-2023`) and
  known-answer vectors are published alongside the code.
- The library is delivered in stages; remaining outputs and capabilities are completed across upcoming
  updates as their consumers are wired.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for coding standards, the offline build/test workflow,
Conventional Commits, and the developer sign-off.

## Security

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md)
(**security@portphi.com**) — never via a public issue.

## License

phi-crypto is licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE)). The Phi protocol and the original source in this repository are the intellectual
property of Homaan Smart Data Co.

---

*Homaan Smart Data Co. — portphi.com*
