# Security Policy — phi-crypto

phi-crypto is the cryptographic core of the Phi network — the privacy-preserving cryptography behind
proof of personhood, authentication, and verifiable credentials. A flaw here would be amplified across
the chain, the mobile app, and the web, so this library is held to the highest bar. We take
vulnerabilities seriously and appreciate responsible disclosure.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately to **security@portphi.com**.

Please include:

- A clear description of the issue and its impact.
- Steps to reproduce — a failing test or a minimal proof-of-concept where possible.
- The affected module (for example `bbs`, `bbs_2023`, `did`, `webauthn`, `voting`/`semaphore`, or the
  `ffi` boundary) and the commit you tested against.
- Any suggested remediation.

We aim to acknowledge reports promptly and will coordinate a fix and a disclosure timeline with you.
Please give us reasonable time to remediate before any public disclosure; we are glad to credit
reporters who follow coordinated disclosure.

## Our security model

phi-crypto is built so that correctness and privacy hold by construction. Reports that demonstrate a
way to break any of the following are especially valuable.

- **Never hand-roll cryptography.** Every primitive is a thin, reviewed wrapper over a mature, audited
  crate; the library never invents its own cryptography. A finding that a wrapper diverges unsafely
  from its underlying primitive is in scope.

- **Selective-disclosure soundness and unlinkability.** A BBS+ proof must reveal only the claims it
  asserts; two proofs derived from one credential must not be correlatable; a proof must not verify
  under the wrong issuer key, against a tampered or revoked credential, or replayed into a different
  context.

- **Authentication soundness.** The WebAuthn verifier must reject a wrong challenge, a wrong
  origin/relying-party, a missing User-Presence, a malformed assertion, and a non-canonical (high-S)
  signature.

- **Verifiers fail closed.** Every verification entry point returns a safe negative on any error or
  malformed input; no panic ever crosses the C-ABI boundary (the boundary returns `0` on bad input).
  Any input that causes a verifier to accept invalid data — or to panic, hang, or over-allocate — is
  in scope.

- **Side-channel resistance.** Secret material is compared in constant time (`subtle`) and zeroized
  after use (`zeroize`); signing enforces low-S. Timing or memory side channels that leak secret
  material are in scope.

- **Reproducible, pinned supply chain.** `Cargo.lock` is committed and every dependency is pinned and
  vendored; the build is fully offline. Any way to introduce an unpinned or tampered dependency is in
  scope.

## No secrets in the repository

No keys, secrets, or credentials are ever committed to this repository — not in code, tests, or
comments. If you ever find a committed secret, please report it through the channel above.

## Test vectors

Known-answer test vectors are published alongside the code, so anyone can independently verify that
the cryptographic suites match the official IETF/W3C reference outputs byte-for-byte.

---

*Homaan Smart Data Co. — portphi.com*
