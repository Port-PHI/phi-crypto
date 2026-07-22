#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Fails if a committed C-ABI header has drifted from the Rust `#[no_mangle] extern "C"` exports.
#
# WHY THIS EXISTS
# ---------------
# The headers are what phi-chain compiles against. If a header's declaration and the Rust export
# disagree about a function's arity or types, the C caller builds the wrong stack frame and the
# validator corrupts memory — with no compile error on either side, because C trusts the header and
# Rust trusts the symbol. Nothing regenerated or diffed them, so that drift could ship silently.
#
# WHAT IS COMPARED, AND WHY NOT THE WHOLE FILE
# --------------------------------------------
# The committed headers are hand-maintained: they carry prose the Go consumer depends on (the
# return-code contract, the cgo usage snippet, the fail-closed note) that cbindgen does not emit. A
# byte-for-byte diff against raw generator output would therefore fail on the prose, every time, and
# a gate that always fails is a gate that gets disabled.
#
# So the comparison is over the DECLARATIONS, which is where drift actually hurts: this regenerates
# each header with cbindgen, reduces both the generated and the committed file to their normalized
# `phi_*` prototypes — name, return type, and every parameter type in order — and diffs those. Any
# added, removed, renamed, retyped or reordered parameter fails. Prose does not.
#
# Run locally exactly as CI does:
#   scripts/check_c_abi_headers.sh
#
# Regenerating after a deliberate ABI change (the recipe the headers themselves document):
#   cargo build --release && cbindgen --config cbindgen.toml --output phi_crypto.h
#   cargo build --release --features voting_snark \
#     && cbindgen --config cbindgen-voting-snark.toml --output phi_crypto_voting_snark.h
#   # then re-apply the hand-written prose header block, and re-run this script.
set -euo pipefail

cd "$(dirname "$0")/.."

# Reduce a C header to one normalized prototype per line: `name|ret|type1,type2,...`.
# Whitespace, parameter NAMES and comments are dropped; types, order and arity are kept, because
# those are what decide the call frame.
normalize_decls() {
    python3 - "$1" <<'PY'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
# Strip block and line comments so prose can never influence the comparison.
src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
src = re.sub(r"//[^\n]*", " ", src)
out = []
for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_ \*]*?)\b(phi_[A-Za-z0-9_]+)\s*\(([^)]*)\)\s*;", src, re.S):
    ret, name, params = m.group(1).strip(), m.group(2), m.group(3)
    types = []
    for p in params.split(","):
        p = " ".join(p.split())
        if not p or p == "void":
            continue
        # Drop the parameter name: the last identifier, unless the whole thing is just a type.
        p = re.sub(r"\s+[A-Za-z_][A-Za-z0-9_]*$", "", p).strip()
        types.append(" ".join(p.split()))
    out.append(f"{name}|{' '.join(ret.split())}|{','.join(types)}")
print("\n".join(sorted(out)))
PY
}

fail=0
skipped=0

# Every symbol name in a normalized declaration list.
names_of() { cut -d'|' -f1; }

# One generation, not two.
#
# cbindgen resolves `#[cfg(feature = ...)]` from `cargo metadata --all-features`, so a single run
# already emits EVERY export including the feature-gated one. The previous invocation tried to select
# features with `--config-features`, which is not a cbindgen flag: cbindgen rejected it, and under
# `set -e` the script died there — before either comparison had produced a verdict, with cbindgen's
# usage exit code 2, which is the same code this script reserves for "SKIPPED, not a pass". The gate
# could not complete in the one environment it exists for.
#
# So the featured header is compared against that generation directly, and the default header against
# the same generation restricted to the symbols it declares. What that leaves unproven — that the
# symbols the default header omits are exactly the feature-gated ones — is what the offline Rust test
# below establishes from the sources, where the `#[cfg]` attributes actually live.
GENERATED=""

generate() {
    if ! command -v cbindgen >/dev/null 2>&1; then
        echo "==> SKIPPED — cbindgen not on PATH, so no header was regenerated or compared."
        skipped=1
        return 1
    fi
    GENERATED="$(mktemp)"
    # Run guarded rather than bare: a tool failure must report as a tool failure, distinctly from
    # both a drift and a skip, instead of aborting the gate mid-way under errexit.
    if ! cbindgen --quiet --config cbindgen.toml --output "${GENERATED}"; then
        echo "RESULT: ERROR — cbindgen failed to generate. The gate did NOT run."
        rm -f "${GENERATED}"
        exit 3
    fi
    return 0
}

# check_full requires the header to match the generation exactly: same symbols, same types, same order.
check_full() {
    local header="$1"
    echo "==> ${header} (complete declaration set)"
    if ! diff -u <(normalize_decls "${header}") <(normalize_decls "${GENERATED}"); then
        echo ""
        echo "    C-ABI HEADER DRIFT in ${header}."
        echo "    Left = committed header, right = regenerated from the Rust exports."
        echo "    A caller compiled against the committed header would build a frame the Rust"
        echo "    export does not expect. Regenerate and re-apply the prose block."
        fail=1
    else
        echo "    declarations match the Rust exports"
    fi
}

# check_subset requires every declaration the header DOES carry to match the generation exactly, and
# reports the symbols it leaves out. Omission is legitimate here — the default header must not declare
# an export that is compiled out of the default build — but a WRONG type never is.
check_subset() {
    local header="$1"
    echo "==> ${header} (declared subset)"

    local decls generated_subset omitted
    decls="$(mktemp)"; generated_subset="$(mktemp)"; omitted="$(mktemp)"
    normalize_decls "${header}" > "${decls}"
    normalize_decls "${GENERATED}" > "${generated_subset}.all"

    # Split the generation into the declarations this header carries and the ones it leaves out,
    # keyed on the symbol name (the field before the first `|`).
    python3 - "${decls}" "${generated_subset}.all" "${generated_subset}" "${omitted}" <<'SPLIT'
import sys
declared = {l.split("|", 1)[0] for l in open(sys.argv[1], encoding="utf-8").read().splitlines() if l}
kept, left_out = [], []
for line in open(sys.argv[2], encoding="utf-8").read().splitlines():
    if not line:
        continue
    (kept if line.split("|", 1)[0] in declared else left_out).append(line)
def write(path, rows):
    open(path, "w", encoding="utf-8").write("".join(r + "\n" for r in rows))
write(sys.argv[3], kept)
write(sys.argv[4], sorted(r.split("|", 1)[0] for r in left_out))
SPLIT

    if ! diff -u "${decls}" "${generated_subset}"; then
        echo ""
        echo "    C-ABI HEADER DRIFT in ${header}."
        echo "    A declaration it carries does not match the Rust export of the same name."
        fail=1
    else
        echo "    every declaration it carries matches the Rust exports"
    fi

    if [ -s "${omitted}" ]; then
        echo "    omits (must be exactly the feature-gated exports, which the offline gate proves):"
        sed 's/^/      /' "${omitted}"
    fi
    rm -f "${decls}" "${generated_subset}" "${generated_subset}.all" "${omitted}"
}

if generate; then
    check_full   phi_crypto_voting_snark.h
    check_subset phi_crypto.h
    rm -f "${GENERATED}"
fi

# The toolchain-free half: symbol set and arity, parsed straight from the sources. This runs whether
# or not cbindgen is available, which is what makes the gate meaningful in the offline tree too.
echo "==> offline shape gate"
cargo test --locked --offline --test c_abi_header_drift --quiet

echo ""
if [ "${fail}" -ne 0 ]; then
    echo "RESULT: FAILED — a committed header has drifted from the Rust exports."
    exit 1
fi

# A SKIP IS NOT A PASS, and it must not be reported as one.
#
# Without cbindgen the regeneration half of this gate does not run at all: the offline shape gate below
# still checks the symbol set and arity, but nothing compares parameter TYPES or their order against
# what the generator would emit. Exiting 0 there told a developer their headers were verified when the
# check that verifies them had not executed — and the drift this gate exists to catch is precisely the
# kind that compiles cleanly on both sides.
#
# So a skipped run exits non-zero, with a code distinct from a real drift failure. Set
# ALLOW_MISSING_CBINDGEN=1 to acknowledge the reduced coverage deliberately (the offline tree, where
# cbindgen cannot be installed); CI has cbindgen and never takes either path.
if [ "${skipped}" -ne 0 ]; then
    if [ "${ALLOW_MISSING_CBINDGEN:-0}" = "1" ]; then
        echo "RESULT: SKIPPED (acknowledged) — headers were NOT regenerated; only the offline shape gate ran."
        echo "        Install cbindgen and re-run for the full check before relying on this."
        exit 0
    fi
    echo "RESULT: SKIPPED — headers were NOT regenerated, so this is NOT a pass."
    echo "        Install cbindgen (cargo install cbindgen) and re-run, or set ALLOW_MISSING_CBINDGEN=1"
    echo "        to acknowledge that only the offline shape gate ran."
    exit 2
fi

echo "RESULT: PASSED — every committed header matches the Rust exports."
exit 0
