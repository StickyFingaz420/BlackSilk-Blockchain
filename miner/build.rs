// Temporarily disabled RandomX linking for testnet development
// TODO: Enable RandomX linking when library is available
fn main() {
    println!("cargo:warning=RandomX linking temporarily disabled for development");
    println!("cargo:rerun-if-changed=build.rs");
}
