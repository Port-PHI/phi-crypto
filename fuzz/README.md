<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing the C-ABI decoders

`fuzz_targets/ffi_decoders.rs` drives the `#[no_mangle]` exports in `src/ffi.rs` with libFuzzer-generated
input. The property under test is **panic-freedom**: the shipped staticlib is built with
`panic = "abort"`, so on that path a panic does not become an error — it halts the validator. A panic,
an abort or a sanitizer report is a crash.

## Dependencies are fetched, not vendored

This is the one crate in the repository without a vendor tree. It is a test-only tool, nothing links it
into a shipped artifact, and vendoring it would add a large third-party source tree to a public repo to
support a build that never ships. `Cargo.lock` is committed and pins every dependency; `cargo fetch
--locked` fails rather than resolving anything else.

Everything that *does* ship — the library, the staticlib linked into phi-chain, the WASM module — still
builds strictly offline from the committed `../vendor`, and none of this affects that.

## Running it

Cargo applies source replacement repo-wide, and the repo-root `.cargo/config.toml` redirects crates.io
to `../vendor`. A sub-crate cannot opt out of that — a child config can only point `replace-with` at a
*different* source, and no valid source is crates.io itself (cargo rejects a duplicate definition of the
same registry, and self-replacement as a cycle). So the redirect has to be set aside while fuzzing:

```bash
# from the repository root
mv .cargo/config.toml .cargo/config.toml.unused

cd fuzz
cargo +nightly fetch --locked                                   # pinned; the only network step
CARGO_NET_OFFLINE=true cargo +nightly fuzz build ffi_decoders    # cannot deviate from the pin
cargo +nightly fuzz run ffi_decoders -- -max_total_time=60 -max_len=4096

cd .. && mv .cargo/config.toml.unused .cargo/config.toml         # put it back
```

Nightly is required: cargo-fuzz passes unstable sanitizer and coverage flags
(`-Zsanitizer=address`, `-Cpasses=sancov-module`). The library itself is built and tested on stable
everywhere else.

A crash leaves a reproducer under `artifacts/`; replay it with
`cargo +nightly fuzz run ffi_decoders artifacts/ffi_decoders/<file>`.

## Scope

CI runs this bounded (60s), as a regression gate rather than a campaign. There is no committed seed
corpus, so each run starts cold — the coverage is shallow by construction and is not evidence of
exhaustive fuzzing. Deep campaigns are run out of band.
