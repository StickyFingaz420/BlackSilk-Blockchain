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
    let found: Vec<String> = strings(&elf, 6)
        .into_iter()
        .filter(|s| path_like(s))
        .collect();
    assert_eq!(found.len(), 1);
    let mut unix = vec![1u8; 3];
    unix.extend_from_slice(b"/home/ci/work/px-core/src/hash.rs");
    assert!(strings(&unix, 6).iter().any(|s| path_like(s)));
    assert!(
        strings(b"\x00a\\c/d\x00", 6).is_empty(),
        "short code-byte runs are ignored"
    );
}

/// Little-endian fields of an ELF32 file.
fn u16_at(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}

fn u32_at(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes")) as usize
}

/// `(p_type, p_offset, p_filesz)` of every program header.
fn program_headers(elf: &[u8]) -> Vec<(usize, usize, usize)> {
    let (phoff, phentsize, phnum) = (u32_at(elf, 28), u16_at(elf, 42), u16_at(elf, 44));
    (0..phnum)
        .map(|i| {
            let h = phoff + i * phentsize;
            (u32_at(elf, h), u32_at(elf, h + 4), u32_at(elf, h + 16))
        })
        .collect()
}

/// The section names.
fn section_names(elf: &[u8]) -> Vec<String> {
    let (shoff, shentsize, shnum, shstrndx) = (
        u32_at(elf, 32),
        u16_at(elf, 46),
        u16_at(elf, 48),
        u16_at(elf, 50),
    );
    let strtab = u32_at(elf, shoff + shstrndx * shentsize + 16);
    (0..shnum)
        .map(|i| {
            let name = strtab + u32_at(elf, shoff + i * shentsize);
            let end = name + elf[name..].iter().position(|&c| c == 0).expect("NUL");
            String::from_utf8(elf[name..end].to_vec()).expect("ASCII name")
        })
        .collect()
}

const PT_LOAD: usize = 1;

/// CI-1 (zkvm/guests/README.md, "Header bytes in the id"): a program id
/// covers the file-backed bytes of every `PT_LOAD` segment. The pinned
/// guests are linked with `zkvm/guests/guest.ld`, so no `PT_LOAD` covers the
/// ELF header or the program headers (whose `e_shoff` moves with every
/// non-loaded byte), and `.comment` (the host-specific rustc and LLD
/// identification strings) is discarded: the id depends only on loaded code
/// and data, and the whole file is the same on every host.
#[test]
fn pinned_guests_load_no_header_and_carry_no_comment() {
    for (name, elf) in [("kernel", KERNEL_ELF), ("vault", VAULT_ELF)] {
        assert_eq!(&elf[..4], b"\x7fELF", "{name}");
        let loads: Vec<_> = program_headers(elf)
            .into_iter()
            .filter(|h| h.0 == PT_LOAD)
            .collect();
        assert!(!loads.is_empty(), "{name}.elf has no PT_LOAD");
        let header_end = u32_at(elf, 28) + u16_at(elf, 42) * u16_at(elf, 44);
        for (_, offset, filesz) in &loads {
            assert!(
                *offset >= header_end && *offset != 0,
                "{name}.elf: a PT_LOAD at file offset {offset:#x} (size {filesz:#x})                  covers the ELF or program headers; relink with guest.ld"
            );
        }
        let names = section_names(elf);
        assert!(
            !names.iter().any(|n| n == ".comment"),
            "{name}.elf has a .comment section: {names:?}"
        );
    }
}

/// The checks above find what the default LLD layout produces: a first
/// `PT_LOAD` at offset 0 and a `.comment` section (a minimal ELF32 built
/// here).
#[test]
fn the_layout_checks_detect_the_default_layout() {
    // ELF header (52 bytes), one program header at 52, section headers at 96
    // (null, .comment, .shstrtab), names at 216.
    let mut elf = vec![0u8; 240];
    elf[..4].copy_from_slice(b"\x7fELF");
    let put16 =
        |e: &mut Vec<u8>, at: usize, v: u16| e[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let put32 =
        |e: &mut Vec<u8>, at: usize, v: u32| e[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put32(&mut elf, 28, 52); // e_phoff
    put32(&mut elf, 32, 96); // e_shoff
    put16(&mut elf, 42, 32); // e_phentsize
    put16(&mut elf, 44, 1); // e_phnum
    put16(&mut elf, 46, 40); // e_shentsize
    put16(&mut elf, 48, 3); // e_shnum
    put16(&mut elf, 50, 2); // e_shstrndx
    put32(&mut elf, 52, PT_LOAD as u32); // p_type
    put32(&mut elf, 56, 0); // p_offset: the headers are loaded
    put32(&mut elf, 68, 240); // p_filesz
    let names = b"\x00.comment\x00.shstrtab\x00";
    elf[216..216 + names.len()].copy_from_slice(names);
    put32(&mut elf, 96 + 40, 1); // section 1 name: .comment
    put32(&mut elf, 96 + 80, 10); // section 2 name: .shstrtab
    put32(&mut elf, 96 + 80 + 16, 216); // section 2 offset
    let loads = program_headers(&elf);
    assert_eq!(loads, vec![(PT_LOAD, 0, 240)]);
    assert!(section_names(&elf).contains(&".comment".to_string()));
}
