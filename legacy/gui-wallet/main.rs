//! Main entry point for the BlackSilk GUI Wallet

mod wallet_core;
mod node_interface;
mod storage;
mod ui;

fn main() {
    // Launch the GUI (iced)
    ui::run();
}
