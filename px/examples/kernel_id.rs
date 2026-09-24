//! Prints the program id of the pinned kernel (for `px/kernel.id`).
fn main() {
    let id = blacksilk_px::prove::kernel_program().id();
    println!(
        "{}",
        id.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}
