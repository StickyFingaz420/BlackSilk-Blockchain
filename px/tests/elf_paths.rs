//! R15-6: the consensus-pinned guest programs carry no build path.
//!
//! A path in a pinned ELF makes its program id depend on where it was built
//! (and on the host's path separator). Before testnet v3 the kernel held the
//! developer's absolute path to `px-core\src\hash.rs` (the location of an
//! `assert!` panic) and path-dependent crate hashes in its symbol table. The
//! guests are now linked with `--strip-all` and px-core's guest paths have no
//! located panic (`Permutation::invalid_input`); this test keeps it so.

use blacksilk_px::prove::KERNEL_ELF;
use blacksilk_px::vault::VAULT_ELF;

/// Printable ASCII runs of at least `min` bytes (what `strings` shows).
fn strings(bytes: &[u8], min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in bytes.iter().chain(std::iter::once(&0u8)) {
        if (0x20..0x7f).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min {
                out.push(String::from_utf8(cur.clone()).expect("ASCII"));
            }
            cur.clear();
        }
    }
    out
}

/// Path-like strings: a source file name, a directory separator inside a
/// word (code bytes can contain a lone `\` or `/`, so short runs are
/// ignored), or a home directory.
fn path_like(s: &str) -> bool {
    s.contains(".rs")
        || s.contains("/src/")
        || s.contains("\\src\\")
        || s.contains(":\\")
        || s.contains("Users\\")
        || s.contains("/home/")
        || s.contains("/Users/")
        || s.contains(".cargo")
        || s.contains("rustc/")
}

#[test]
fn pinned_guests_contain_no_path_strings() {
    for (name, elf) in [("kernel", KERNEL_ELF), ("vault", VAULT_ELF)] {
        let found: Vec<String> = strings(elf, 6)
            .into_iter()
            .filter(|s| path_like(s))
            .collect();
        assert!(
            found.is_empty(),
            "{name}.elf holds path-like strings (a located panic or debug data \
             crept back in; see zkvm/guests/README.md): {found:?}"
        );
        // No symbol table either (`--strip-all`): its names carry crate
        // hashes derived from the build path.
        assert!(
            !elf.windows(7).any(|w| w == b".symtab"),
            "{name}.elf has a symbol table"
        );
    }
}

/// The detector finds the strings the pre-v3 kernel held.
#[test]
fn the_detector_finds_a_source_path() {
    let mut elf = vec![0u8; 16];
    elf.extend_from_slice(b"C:\\Users\\dev\\BlackSilk\\px-core\\src\\hash.rs");
    elf.push(0);
    let found: Vec<String> = strings(&elf, 6).into_iter().filter(|s| path_like(s)).collect();
    assert_eq!(found.len(), 1);
    let mut unix = vec![1u8; 3];
    unix.extend_from_slice(b"/home/ci/work/px-core/src/hash.rs");
    assert!(strings(&unix, 6).iter().any(|s| path_like(s)));
    assert!(strings(b"\x00a\\c/d\x00", 6).is_empty(), "short code-byte runs are ignored");
}
