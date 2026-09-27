//! Prints the BVM-1 program id (docs/zkvm.md §3) of each ELF file given, one
//! `<hex id>  <path>` line per file. Used to check that a guest rebuilt from
//! source matches a pinned id (docs/px.md §4.3, `zkvm/guests/README.md`).
//!
//! `cargo run --release -p blacksilk-zkvm --example program_id -- px/kernel.elf`
fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: program_id <elf>...");
        std::process::exit(2);
    }
    for path in paths {
        let elf = std::fs::read(&path).unwrap_or_else(|e| {
            eprintln!("{path}: {e}");
            std::process::exit(1)
        });
        let program = blacksilk_zkvm::Program::from_elf(&elf).unwrap_or_else(|e| {
            eprintln!("{path}: {e:?}");
            std::process::exit(1)
        });
        let id: String = program.id().iter().map(|b| format!("{b:02x}")).collect();
        println!("{id}  {path}");
    }
}
