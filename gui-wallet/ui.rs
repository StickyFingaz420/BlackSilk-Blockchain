//! UI: iced-based frontend, main window, navigation, event loop

use crate::types::Screen;
use crate::wallet_core::WalletCore;
use crate::storage::Storage;
use std::path::PathBuf;
use iced::{Application, Command, Element, Settings, executor, widget::{Column, Row, Button, Text, TextInput, Slider, Space, Scrollable, PickList}};
use primitives::QuantumScheme;

pub fn run() {
    WalletApp::run(Settings::default()).unwrap();
}

pub struct WalletApp {
    pub balance: f64,
    pub active_screen: Screen,
    // Send screen state
    send_address: String,
    send_amount: String,
    send_fee: f32,
    pub send_status: Option<String>,
    pub receive_address: String,
    pub history: Vec<String>,
    pub wallet_core: WalletCore,
    pub storage: Storage,
    pub import_export_status: Option<String>,
    pub selected_scheme: QuantumScheme,
}

impl Default for WalletApp {
    fn default() -> Self {
        let storage = Storage::new(PathBuf::from("wallet_data"));
        let history = storage.load_tx_history().unwrap_or_default();
        Self {
            balance: 0.0,
            active_screen: Screen::Dashboard,
            send_address: String::new(),
            send_amount: String::new(),
            send_fee: 1.0,
            send_status: None,
            receive_address: "Blk1...".to_string(),
            history,
            wallet_core: WalletCore::new(),
            storage,
            import_export_status: None,
            selected_scheme: QuantumScheme::MLDSA44,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    GoToSend,
    GoToReceive,
    GoToHistory,
    GoToDashboard,
    SendAddressChanged(String),
    SendAmountChanged(String),
    SendFeeChanged(f32),
    SendTransaction,
    GenerateNewAddress,
    ExportWallet,
    ImportWallet(String),
    SelectScheme(QuantumScheme),
}

impl Application for WalletApp {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = iced::Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, Command<Self::Message>) {
        (Self::default(), Command::none())
    }

    fn title(&self) -> String {
        String::from("BlackSilk GUI Wallet")
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::GoToSend => self.active_screen = Screen::Send,
            Message::GoToReceive => self.active_screen = Screen::Receive,
            Message::GoToHistory => self.active_screen = Screen::History,
            Message::GoToDashboard => self.active_screen = Screen::Dashboard,
            Message::SendAddressChanged(addr) => self.send_address = addr,
            Message::SendAmountChanged(amt) => self.send_amount = amt,
            Message::SendFeeChanged(fee) => self.send_fee = fee,
            Message::SendTransaction => {
                if let Ok(amount) = self.send_amount.parse::<f64>() {
                    let node = crate::node_interface::NodeClient::new("http://127.0.0.1:9333");
                    // Fetch ring members from node
                    let ring = node.get_ring_members(5).unwrap_or_else(|_| vec![[0u8; 32]; 5]);
                    let real_index = 0; // TODO: Set real index appropriately
                    if let Some(sig) = self.wallet_core.build_and_sign_transaction(
                        &self.send_address,
                        amount as u64,
                        ring.clone(),
                        real_index,
                        self.selected_scheme.clone(),
                    ) {
                        self.send_status = Some(format!("Transaction signed ({} bytes)", sig.len()));
                        let entry = format!("Sent: {} to {} (signed, scheme: {:?}, ring: {:?})", amount, self.send_address, self.selected_scheme, ring);
                        self.history.push(entry.clone());
                        let _ = self.storage.save_tx_history(&entry);
                    } else {
                        self.send_status = Some("Failed to sign transaction".to_string());
                    }
                } else {
                    self.send_status = Some("Invalid amount".to_string());
                }
            }
            Message::SelectScheme(scheme) => {
                self.selected_scheme = scheme;
            }
            Message::GenerateNewAddress => {
                if let Some(addr) = self.wallet_core.generate_new_address_with_scheme(Some(self.selected_scheme.clone())) {
                    self.receive_address = addr;
                }
            }
            Message::ExportWallet => {
                // Export wallet file (copy to export path)
                let src = self.storage.wallet_path.join("wallet.dat");
                let dst = self.storage.wallet_path.join("wallet_export.dat");
                match std::fs::copy(&src, &dst) {
                    Ok(_) => self.import_export_status = Some("Wallet exported to wallet_export.dat".to_string()),
                    Err(e) => self.import_export_status = Some(format!("Export failed: {}", e)),
                }
            }
            Message::ImportWallet(path) => {
                // Import wallet file (copy from import path)
                let dst = self.storage.wallet_path.join("wallet.dat");
                match std::fs::copy(&path, &dst) {
                    Ok(_) => self.import_export_status = Some("Wallet imported successfully".to_string()),
                    Err(e) => self.import_export_status = Some(format!("Import failed: {}", e)),
                }
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        Column::new()
            .push(Text::new(format!("Balance: {:.4} BSX", self.balance)))
            .push(
                Row::new()
                    .push(Button::new(Text::new("Send")).on_press(Message::GoToSend))
                    .push(Button::new(Text::new("Receive")).on_press(Message::GoToReceive))
                    .push(Button::new(Text::new("History")).on_press(Message::GoToHistory))
                    .push(Button::new(Text::new("Settings")).on_press(Message::GoToDashboard))
            )
            .push(match self.active_screen {
                Screen::Send => self.send_view(),
                Screen::Receive => self.receive_view(),
                Screen::History => self.history_view(),
                Screen::Settings => self.settings_view(),
                _ => Column::new().into(),
            })
            .into()
    }
}

impl WalletApp {
    fn send_view(&self) -> Element<'_, Message> {
        Column::new()
            .push(Text::new("Send Coins"))
            .push(Row::new()
                .push(Text::new("Recipient Address:"))
                .push(TextInput::new(
                    "Enter address",
                    &self.send_address,
                    Message::SendAddressChanged,
                ))
            )
            .push(Row::new()
                .push(Text::new("Amount:"))
                .push(TextInput::new(
                    "0.0",
                    &self.send_amount,
                    Message::SendAmountChanged,
                ))
            )
            .push(Row::new()
                .push(Text::new("Fee:"))
                .push(Slider::new(0.0..=2.0, self.send_fee, Message::SendFeeChanged))
            )
            .push(Space::with_height(20))
            .push(Button::new(Text::new("Send Transaction")).on_press(Message::SendTransaction))
            .push(
                if let Some(status) = &self.send_status {
                    Text::new(status).into()
                } else {
                    Space::with_height(0).into()
                }
            )
            .into()
    }
    fn receive_view(&self) -> Element<'_, Message> {
        use iced::widget::{TextInput, PickList};
        let scheme_options = vec![
            QuantumScheme::MLDSA44,
            QuantumScheme::Dilithium2,
            QuantumScheme::Falcon512,
        ];
        Column::new()
            .push(Text::new("Receive Coins"))
            .push(Row::new()
                .push(Text::new("Current Address:"))
                .push(TextInput::new(
                    "Your address",
                    &self.receive_address,
                    |_| Message::GoToReceive,
                ))
            )
            .push(Row::new()
                .push(Text::new("Signature Scheme:"))
                .push(PickList::new(
                    scheme_options,
                    Some(self.selected_scheme.clone()),
                    Message::SelectScheme,
                ))
            )
            .push(Button::new(Text::new("Generate New Address")).on_press(Message::GenerateNewAddress))
            .into()
    }
    fn history_view(&self) -> Element<'_, Message> {
        use iced::widget::Scrollable;
        let mut col = Column::new().push(Text::new("Transaction History"));
        if self.history.is_empty() {
            col = col.push(Text::new("(No history yet)"));
        } else {
            for entry in &self.history {
                col = col.push(Text::new(entry));
            }
        }
        Scrollable::new(col).into()
    }
    fn settings_view(&self) -> Element<'_, Message> {
        use iced::widget::TextInput;
        Column::new()
            .push(Text::new("Settings"))
            .push(Button::new(Text::new("Export Wallet")).on_press(Message::ExportWallet))
            .push(Row::new()
                .push(Text::new("Import Wallet from: "))
                .push(TextInput::new(
                    "Path to wallet file",
                    "",
                    |s| Message::ImportWallet(s),
                ))
            )
            .push(
                if let Some(status) = &self.import_export_status {
                    Text::new(status).into()
                } else {
                    Space::with_height(0).into()
                }
            )
            .push(Text::new("Exported/Imported wallet files include all keys and settings. Keep your mnemonic and files safe!"))
            .into()
    }
}
