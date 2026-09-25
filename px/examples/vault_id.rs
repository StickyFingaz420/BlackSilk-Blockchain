//! Prints the program id of the pinned vault contract (for `px/vault.id`).
fn main() {
    let id = blacksilk_px::vault::program().id();
    println!(
        "{}",
        id.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}
