use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct Cli {
    #[arg(long, default_value = "./wallet_data", value_name = "DIR")]
    pub data_dir: PathBuf,
    #[arg(long, value_name = "FILE")]
    pub wallet_file: Option<PathBuf>,
    #[arg(long, value_name = "PASS")]
    pub password: Option<String>,
    #[arg(long, default_value = "127.0.0.1:9333", value_name = "ADDR")]
    pub node: String,
    #[arg(long)]
    pub daemon: bool,
    #[arg(long, value_name = "FILE")]
    pub pid_file: Option<PathBuf>,
    #[arg(long)]
    pub rpc_server: bool,
    #[arg(long, default_value = "127.0.0.1:18332", value_name = "ADDR")]
    pub rpc_bind: String,
    #[arg(long, value_name = "USER")]
    pub rpc_user: Option<String>,
    #[arg(long, value_name = "PASS")]
    pub rpc_password: Option<String>,
    #[arg(long)]
    pub rpc_ssl: bool,
    #[arg(long, value_name = "FILE")]
    pub ssl_cert: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    pub ssl_key: Option<PathBuf>,
    #[arg(long)]
    pub testnet: bool,
    #[arg(long)]
    pub offline: bool,
    #[arg(long, value_name = "HEIGHT")]
    pub rescan: Option<u64>,
    #[arg(long, default_value = "1000")]
    pub max_fee_rate: u64,
    #[arg(long)]
    pub coin_control: bool,
    #[arg(long, default_value = "11")]
    pub ring_size: usize,
    #[arg(long)]
    pub auto_consolidate: bool,
    #[arg(long, default_value = "10")]
    pub consolidate_threshold: usize,
    #[arg(long, default_value = "true")]
    pub background_sync: bool,
    #[arg(long, default_value = "30")]
    pub sync_interval: u64,
    #[arg(long, default_value = "info")]
    pub log_level: String,
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<PathBuf>,
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,
    #[arg(long, default_value = "true")]
    pub color: bool,
    #[arg(long, short = 'q')]
    pub quiet: bool,
    #[arg(long, short = 'v')]
    pub verbose: bool,
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Create {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long, value_name = "MNEMONIC")]
        import_seed: Option<String>,
        #[arg(long)]
        import_keys: bool,
    },
    Open {
        #[arg(value_name = "WALLET")]
        wallet: String,
    },
    Close,
    Balance {
        #[arg(long)]
        detailed: bool,
        #[arg(long)]
        unconfirmed: bool,
    },
    Send {
        #[arg(value_name = "ADDRESS")]
        address: String,
        #[arg(value_name = "AMOUNT")]
        amount: u64,
        #[arg(long)]
        fee: Option<u64>,
        #[arg(long, default_value = "11")]
        ring_size: usize,
        #[arg(long, value_name = "ID")]
        payment_id: Option<String>,
        #[arg(long, default_value = "1")]
        priority: u8,
    },
    Address {
        #[arg(long, value_name = "ID")]
        payment_id: Option<String>,
        #[arg(long)]
        qr: bool,
    },
    History {
        #[arg(long, default_value = "20")]
        limit: usize,
        #[arg(long, value_name = "TXID")]
        txid: Option<String>,
        #[arg(long)]
        incoming: bool,
        #[arg(long)]
        outgoing: bool,
    },
    Sync {
        #[arg(long)]
        force: bool,
        #[arg(long, value_name = "HEIGHT")]
        from_height: Option<u64>,
    },
    Info,
    Seed {
        #[arg(long, value_name = "FILE")]
        export: Option<PathBuf>,
    },
    Keys {
        #[arg(long)]
        view_key: bool,
        #[arg(long)]
        spend_key: bool,
        #[arg(long, value_name = "FILE")]
        export: Option<PathBuf>,
    },
    Backup {
        #[arg(value_name = "FILE")]
        output: PathBuf,
        #[arg(long)]
        include_history: bool,
    },
    Restore {
        #[arg(value_name = "FILE")]
        input: PathBuf,
        #[arg(value_name = "NAME")]
        name: String,
    },
    Multisig {
        #[command(subcommand)]
        action: MultisigCommands,
    },
    Privacy {
        #[command(subcommand)]
        action: PrivacyCommands,
    },
    Hardware {
        #[command(subcommand)]
        action: HardwareCommands,
    },
    AddressBook {
        #[command(subcommand)]
        action: AddressBookCommands,
    },
    Settings {
        #[command(subcommand)]
        action: SettingsCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum PrivacyCommands {
    Stealth,
    Ring {
        #[arg(long, default_value = "11")]
        size: usize,
    },
    ZkProof {
        #[arg(value_name = "AMOUNT")]
        amount: u64,
    },
    Verify {
        #[arg(value_name = "PROOF")]
        proof: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum MultisigCommands {
    Create {
        #[arg(value_name = "M")]
        required: usize,
        #[arg(value_name = "N")]
        total: usize,
    },
    Join {
        #[arg(value_name = "INFO")]
        info: String,
    },
    Sign {
        #[arg(value_name = "TX")]
        tx: String,
    },
    Submit {
        #[arg(value_name = "TX")]
        tx: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum HardwareCommands {
    List,
    Connect {
        #[arg(value_name = "ID")]
        device: String,
    },
    Sign {
        #[arg(value_name = "TX")]
        tx: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AddressBookCommands {
    Add {
        #[arg(value_name = "ADDRESS")]
        address: String,
        #[arg(value_name = "LABEL")]
        label: String,
    },
    Remove {
        #[arg(value_name = "LABEL")]
        label: String,
    },
    List,
    Search {
        #[arg(value_name = "TERM")]
        term: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum SettingsCommands {
    Show,
    Fee {
        #[arg(value_name = "RATE")]
        rate: u64,
    },
    RingSize {
        #[arg(value_name = "SIZE")]
        size: usize,
    },
    AutoBackup {
        #[arg(value_name = "ENABLE")]
        enable: bool,
    },
    Reset,
}
