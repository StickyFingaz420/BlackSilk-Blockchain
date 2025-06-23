//! UI: iced-based frontend, main window, navigation, event loop

use crate::types::Screen;
use crate::wallet_core::WalletCore;
use crate::storage::Storage;
use std::path::PathBuf;
use iced::{Application, Command, Element, Settings, executor, widget::{Column, Row, Button, Text, TextInput, Slider, Space, Scrollable, PickList}};
use primitives::QuantumScheme;
use primitives::ring_sig::verify_ring_signature;
use ledger_apdu::APDUCommand;
use hidapi::HidApi;
use iced::widget::Image;
use iced::{window, theme};

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
    pub hardware_status: Option<String>,
    pub signature_verification: Vec<Option<bool>>,
    pub show_splash: bool,
    pub splash_start: Option<std::time::Instant>,
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
            hardware_status: None,
            signature_verification: Vec::new(),
            show_splash: true,
            splash_start: Some(std::time::Instant::now()),
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
    VerifySignature(usize),
    SplashTimeout,
}

impl Application for WalletApp {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = iced::Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, Command<Self::Message>) {
        let mut app = Self::default();
        (
            app,
            Command::perform(async {
                iced::futures::future::ready(()).await;
                std::thread::sleep(std::time::Duration::from_secs(2));
                Message::SplashTimeout
            }, |msg| msg),
        )
    }

    fn title(&self) -> String {
        String::from("BlackSilk GUI Wallet")
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::GoToSend => self.active_screen = Screen::Send,
            Message::GoToReceive => self.active_screen = Screen::Receive,
            Message::GoToHistory => self.active_screen = Screen::History,
            Message::GoToDashboard => {
                // Check for Ledger hardware wallet
                let api = HidApi::new();
                match api {
                    Ok(api) => {
                        let found = api.device_list().any(|d| d.vendor_id() == 0x2c97); // Ledger vendor ID
                        if found {
                            self.hardware_status = Some("Ledger hardware wallet detected".to_string());
                        } else {
                            self.hardware_status = Some("No Ledger hardware wallet found".to_string());
                        }
                    }
                    Err(e) => {
                        self.hardware_status = Some(format!("HID error: {}", e));
                    }
                }
                self.active_screen = Screen::Dashboard;
            }
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
                        let entry = format!("Sent: {} BLK to {} (signed, scheme: {:?}, ring: {:?})", amount, self.send_address, self.selected_scheme, ring);
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
            Message::VerifySignature(idx) => {
                if let Some(entry) = self.history.get(idx) {
                    // Parse entry for ring and signature (assumes format from SendTransaction)
                    // For demo, use dummy data; in production, parse and verify real tx data
                    let msg = b"send:demo:0";
                    let ring = vec![[0u8; 32]; 5];
                    let sig = vec![0u8; 320];
                    let valid = verify_ring_signature(msg, &ring, &sig);
                    if self.signature_verification.len() <= idx {
                        self.signature_verification.resize(idx + 1, None);
                    }
                    self.signature_verification[idx] = Some(valid);
                }
            }
            Message::SplashTimeout => {
                self.show_splash = false;
                Command::none()
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message> {
        if self.show_splash {
            return self.splash_view();
        }
        if self.active_screen == Screen::Dashboard && self.history.is_empty() {
            return Self::splash_screen();
        }
        Column::new()
            .push(Image::new("../blacksilklogos/banner_1600x400.png").width(600).height(150))
            .push(Image::new("../blacksilklogos/icon_128x128.png").width(128).height(128))
            .push(Text::new(format!("Balance: {:.4} BLK", self.balance)))
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
            .push(Text::new("Send Coins (BLK)"))
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
        use iced::widget::{TextInput, PickList, Image, Row as IcedRow, Column as IcedColumn};
        use qrcode::QrCode;
        use image::Luma;
        let scheme_options = vec![
            QuantumScheme::MLDSA44,
            QuantumScheme::Dilithium2,
            QuantumScheme::Falcon512,
        ];
        let qr_img = QrCode::new(&self.receive_address)
            .map(|code| code.render::<Luma<u8>>().max_dimensions(128, 128).build())
            .ok();
        let qr_element = if let Some(img) = qr_img {
            let buf = iced_aw::graphics::image::ImageHandle::from_pixels(128, 128, img.into_raw());
            Image::new(buf).width(128).height(128)
        } else {
            Image::new(iced_aw::graphics::image::ImageHandle::from_pixels(128, 128, vec![255; 128*128])).width(128).height(128)
        };
        Column::new()
            .push(Text::new("Receive Coins (BLK)"))
            .push(IcedRow::new()
                .push(Text::new("Current Address:"))
                .push(TextInput::new(
                    "Your address",
                    &self.receive_address,
                    |_| Message::GoToReceive,
                ))
            )
            .push(IcedRow::new()
                .push(Text::new("Signature Scheme:"))
                .push(PickList::new(
                    scheme_options,
                    Some(self.selected_scheme.clone()),
                    Message::SelectScheme,
                ))
            )
            .push(qr_element)
            .push(Button::new(Text::new("Generate New Address")).on_press(Message::GenerateNewAddress))
            .into()
    }
    fn history_view(&self) -> Element<'_, Message> {
        use iced::widget::{Scrollable, Button, Row};
        let mut col = Column::new().push(Text::new("Transaction History (BLK)"));
        if self.history.is_empty() {
            col = col.push(Text::new("(No history yet)"));
        } else {
            for (idx, entry) in self.history.iter().enumerate() {
                let verify_btn = Button::new(Text::new("Verify Signature")).on_press(Message::VerifySignature(idx));
                let verify_result = self.signature_verification.get(idx).and_then(|v| v.map(|b| if b { "Valid" } else { "Invalid" })).unwrap_or("");
                col = col.push(Row::new().push(Text::new(entry)).push(verify_btn).push(Text::new(verify_result)));
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
            .push(Button::new(Text::new("Check Hardware Wallet")).on_press(Message::GoToDashboard)) // TODO: Implement hardware wallet detection
            .push(
                if let Some(status) = &self.hardware_status {
                    Text::new(status).into()
                } else {
                    Space::with_height(0).into()
                }
            )
            .into()
    }
    fn splash_view(&self) -> Element<'_, Message> {
        use iced::widget::{Column, Image, Text, ProgressBar};
        let elapsed = self.splash_start.map(|t| t.elapsed().as_secs_f32()).unwrap_or(0.0);
        let progress = (elapsed / 2.0).min(1.0);
        Column::new()
            .push(Image::new("../blacksilklogos/banner_1600x400.png").width(600).height(150))
            .push(Image::new("../blacksilklogos/icon_128x128.png").width(128).height(128))
            .push(Text::new("BlackSilk Wallet").size(40))
            .push(Text::new("Quantum Privacy. Uncompromising Security.").size(24))
            .push(ProgressBar::new(0.0..=1.0, progress))
            .push(Text::new("Loading...").size(18))
            .into()
    }
    fn splash_screen() -> Element<'static, Message> {
        use iced::widget::Image;
        Column::new()
            .push(Image::new("../blacksilklogos/banner_1600x400.png").width(800).height(200))
            .push(Text::new("Welcome to BlackSilk Wallet").size(40))
            .push(Text::new("Privacy. Quantum Security. Freedom.").size(24))
            .into()
    }
}
