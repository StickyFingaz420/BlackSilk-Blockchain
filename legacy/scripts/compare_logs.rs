use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn main() -> io::Result<()> {
    let ref_log = "ref-zero.log";
    let rust_log = "rust-zero.log";
    let ref_file = File::open(ref_log)?;
    let rust_file = File::open(rust_log)?;
    let ref_lines = io::BufReader::new(ref_file).lines();
    let rust_lines = io::BufReader::new(rust_file).lines();

    for (i, (ref_line, rust_line)) in ref_lines.zip(rust_lines).enumerate() {
        let ref_line = ref_line?;
        let rust_line = rust_line?;
        if ref_line.trim() != rust_line.trim() {
            println!("Mismatch at line {}:", i + 1);
            println!("C:    {}", ref_line);
            println!("Rust: {}", rust_line);
            return Ok(());
        }
    }
    println!("Logs match: all lines are identical.");
    Ok(())
}
