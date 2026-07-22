// SPDX-License-Identifier: Apache-2.0
//! The committed C headers must describe the Rust `#[no_mangle] extern "C"` exports exactly.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(name: &str) -> String {
    fs::read_to_string(repo_root().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// One `#[no_mangle] extern "C"` export: the C types it presents, and whether it sits behind the `voting_snark` feature.
#[derive(Debug, PartialEq, Eq)]
struct Export {
    /// C parameter types in order, normalized the way the header spells them.
    params: Vec<String>,
    /// C return type.
    ret: String,
    gated: bool,
}

/// Parses the Rust sources for C-ABI exports.
fn rust_type_to_c(rust: &str) -> String {
    let t = rust.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(inner) = t.strip_prefix("*const ") {
        return format!("const {} *", rust_type_to_c(inner.trim()));
    }
    if let Some(inner) = t.strip_prefix("*mut ") {
        return format!("{} *", rust_type_to_c(inner.trim()));
    }
    match t.as_str() {
        "u8" => "uint8_t",
        "u16" => "uint16_t",
        "u32" => "uint32_t",
        "u64" => "uint64_t",
        "i8" => "int8_t",
        "i16" => "int16_t",
        "i32" => "int32_t",
        "i64" => "int64_t",
        "usize" => "uintptr_t",
        "isize" => "intptr_t",
        "bool" => "bool",
        "()" => "void",
        other => panic!(
            "no C mapping for the Rust FFI type `{other}`. Add it to rust_type_to_c — an unmapped \
             type would let this export's signature drift without the gate noticing"
        ),
    }
    .to_string()
}

/// Normalizes a C type the way both sides must agree on it: `const uint8_t *`, `uintptr_t`, `void`.
fn normalize_c_type(decl: &str) -> String {
    let t = decl.split_whitespace().collect::<Vec<_>>().join(" ");

    let trimmed = t.trim_end();
    let ident_start = trimmed
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map(|i| i + 1)
        .unwrap_or(0);
    let ident = &trimmed[ident_start..];
    let body = if !ident.is_empty() && !is_c_type_keyword(ident) {
        &trimmed[..ident_start]
    } else {
        trimmed
    };

    let stars = body.matches('*').count();
    let base = body
        .replace('*', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if stars == 0 {
        base
    } else {
        format!("{base} {}", "*".repeat(stars))
    }
}

/// The C type spellings this ABI uses.
fn is_c_type_keyword(tok: &str) -> bool {
    matches!(
        tok,
        "uint8_t"
            | "uint16_t"
            | "uint32_t"
            | "uint64_t"
            | "int8_t"
            | "int16_t"
            | "int32_t"
            | "int64_t"
            | "uintptr_t"
            | "intptr_t"
            | "size_t"
            | "bool"
            | "void"
            | "char"
            | "const"
    )
}

fn rust_exports() -> BTreeMap<String, Export> {
    let mut out = BTreeMap::new();
    for file in ["src/ffi.rs", "src/voting_snark.rs"] {
        let src = read(file);
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim() != "#[no_mangle]" {
                continue;
            }
            let mut attrs: Vec<&str> = Vec::new();
            let mut j = i;
            while j > 0 {
                let prev = lines[j - 1].trim();
                if prev.starts_with("#[")
                    || prev.starts_with("///")
                    || prev.starts_with("//!")
                    || prev.starts_with("//")
                    || prev.is_empty() && !attrs.is_empty()
                {
                    attrs.push(prev);
                    j -= 1;
                    continue;
                }
                break;
            }
            let gated = attrs.iter().any(|l| {
                let squashed: String = l.chars().filter(|c| !c.is_whitespace()).collect();
                !squashed.starts_with("///")
                    && !squashed.starts_with("//!")
                    && squashed.contains("cfg(")
                    && squashed.contains("feature=\"voting_snark\"")
                    && !squashed.contains("not(")
            }) || file == "src/voting_snark.rs";

            let sig_start = (i..lines.len())
                .find(|&j| lines[j].contains("extern \"C\" fn "))
                .unwrap_or_else(|| panic!("{file}: #[no_mangle] at line {i} has no extern fn"));
            let name = lines[sig_start]
                .split("extern \"C\" fn ")
                .nth(1)
                .and_then(|s| s.split('(').next())
                .expect("function name")
                .trim()
                .to_string();

            let mut sig = String::new();
            for l in &lines[sig_start..] {
                sig.push_str(l);
                if sig.matches('(').count() == sig.matches(')').count() {
                    break;
                }
            }
            let inner = sig
                .split_once('(')
                .and_then(|(_, rest)| rest.rsplit_once(')'))
                .map(|(inner, _)| inner.to_string())
                .unwrap_or_default();
            let params: Vec<String> = split_top_level(&inner)
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| {
                    let ty = p
                        .split_once(':')
                        .map(|(_, ty)| ty.trim())
                        .unwrap_or_else(|| panic!("{file}: parameter `{p}` of {name} has no type"));
                    rust_type_to_c(ty)
                })
                .collect();

            // The return type follows `->`, up to the opening brace. No arrow means unit.
            let ret = sig
                .split_once("->")
                .and_then(|(_, rest)| rest.split('{').next())
                .map(|r| rust_type_to_c(r.trim()))
                .unwrap_or_else(|| "void".to_string());

            out.insert(name, Export { params, ret, gated });
        }
    }
    out
}

/// Splits a parameter list on top-level commas only, so a generic or array type never splits.
fn split_top_level(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut depth, mut cur) = (0i32, String::new());
    for c in inner.chars() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// One declaration as a header spells it.
#[derive(Debug, PartialEq, Eq)]
struct Decl {
    params: Vec<String>,
    ret: String,
}

/// Parses a C header for its `phi_*` declarations, with their return and parameter types.
fn header_decls(header: &str) -> BTreeMap<String, Decl> {
    let raw = read(header);
    let src = strip_c_comments(&raw);

    let mut out = BTreeMap::new();
    for (i, _) in src.match_indices("phi_") {
        let rest = &src[i..];
        let Some(open) = rest.find('(') else { continue };
        let name = &rest[..open];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue; // not a declaration head
        }
        let Some(close) = rest.find(')') else {
            continue;
        };
        if close < open {
            continue;
        }
        let params: Vec<String> = split_top_level(&rest[open + 1..close])
            .iter()
            .filter(|p| !p.is_empty() && p.as_str() != "void")
            .map(|p| normalize_c_type(p))
            .collect();

        let head = &src[..i];
        let ret = head
            .rsplit([';', '}', '\n'])
            .next()
            .map(|r| normalize_c_type(r.trim()))
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "void".to_string());

        out.insert(name.to_string(), Decl { params, ret });
    }
    out
}

/// Removes C block and line comments, so prose can never be parsed as a declaration.
fn strip_c_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let b: Vec<char> = src.chars().collect();
    let (mut i, mut in_block, mut in_line) = (0usize, false, false);
    while i < b.len() {
        if in_block {
            if b[i] == '*' && i + 1 < b.len() && b[i + 1] == '/' {
                in_block = false;
                out.push(' ');
                i += 2;
                continue;
            }
            if b[i] == '\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if in_line {
            if b[i] == '\n' {
                in_line = false;
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
            in_block = true;
            i += 2;
            continue;
        }
        if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            in_line = true;
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// The default header must declare exactly the ungated exports — no more, no fewer.
#[test]
fn default_header_matches_the_ungated_rust_exports() {
    let exports = rust_exports();
    let decls = header_decls("phi_crypto.h");

    let expected: BTreeMap<&String, &Export> = exports.iter().filter(|(_, e)| !e.gated).collect();

    for (name, export) in &expected {
        let declared = decls.get(name.as_str()).unwrap_or_else(|| {
            panic!(
                "phi_crypto.h does not declare the exported symbol {name}; regenerate the header"
            )
        });
        assert_eq!(
            declared.params, export.params,
            "SIGNATURE DRIFT on {name}: the header declares parameters {:?}, the Rust export takes \
             {:?}. A C caller would build a frame the callee does not expect — regenerate the header",
            declared.params, export.params
        );
        assert_eq!(
            declared.ret, export.ret,
            "RETURN-TYPE DRIFT on {name}: the header says {}, the Rust export returns {}",
            declared.ret, export.ret
        );
    }

    for name in decls.keys() {
        assert!(
            exports.contains_key(name),
            "phi_crypto.h declares {name}, which no Rust export provides — a caller would link \
             against a symbol that does not exist"
        );
    }
    assert_eq!(
        decls.len(),
        expected.len(),
        "phi_crypto.h declares {} symbols but there are {} ungated exports",
        decls.len(),
        expected.len()
    );
}

/// The featured header must declare every export, gated ones included.
#[test]
fn featured_header_matches_all_rust_exports() {
    let exports = rust_exports();
    let decls = header_decls("phi_crypto_voting_snark.h");

    for (name, export) in &exports {
        let declared = decls.get(name.as_str()).unwrap_or_else(|| {
            panic!(
                "phi_crypto_voting_snark.h does not declare {name}; regenerate with \
                 cbindgen-voting-snark.toml"
            )
        });
        assert_eq!(
            declared.params, export.params,
            "SIGNATURE DRIFT on {name}: header declares {:?}, Rust export takes {:?}",
            declared.params, export.params
        );
        assert_eq!(
            declared.ret, export.ret,
            "RETURN-TYPE DRIFT on {name}: header says {}, Rust export returns {}",
            declared.ret, export.ret
        );
    }
    assert_eq!(
        decls.len(),
        exports.len(),
        "the featured header must declare every export and nothing else"
    );
}

/// The gated export appears in the featured header ONLY.
#[test]
fn the_gated_export_is_absent_from_the_default_header() {
    let exports = rust_exports();
    let gated: Vec<&String> = exports
        .iter()
        .filter(|(_, e)| e.gated)
        .map(|(n, _)| n)
        .collect();
    assert!(!gated.is_empty(), "the fixture must have a gated export");

    let default = header_decls("phi_crypto.h");
    for name in gated {
        assert!(
            !default.contains_key(name),
            "{name} is behind the voting_snark feature and must not be declared in the default header"
        );
    }
}

/// Each header must state, in the header itself, how to regenerate it.
#[test]
fn headers_document_their_own_regeneration() {
    for (header, config) in [
        ("phi_crypto.h", "cbindgen.toml"),
        ("phi_crypto_voting_snark.h", "cbindgen-voting-snark.toml"),
    ] {
        let src = read(header);
        assert!(
            src.contains("cbindgen") && src.contains(config),
            "{header} must document regeneration via {config}"
        );
    }
}

/// The regeneration recipe must stay discoverable and in step with the headers: the CI gate runs it, and anyone adding an export needs to find it without archaeology.
#[test]
fn the_regeneration_recipe_is_documented() {
    for (config, guard) in [
        ("cbindgen.toml", "PHI_CRYPTO_H"),
        ("cbindgen-voting-snark.toml", "PHI_CRYPTO_VOTING_SNARK_H"),
    ] {
        let src = read(config);
        assert!(
            src.contains("cbindgen --config"),
            "{config} must document the exact regeneration command"
        );
        assert!(
            src.contains(guard),
            "{config} must pin the include guard it generates"
        );
    }
}
