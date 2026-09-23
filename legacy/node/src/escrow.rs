use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use primitives::escrow::{DisputeVote, EscrowContract, EscrowStatus};
use primitives::types::Hash;
use std::fs;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::{Json, extract::{Path, State}};

lazy_static::lazy_static! {
    static ref ESCROW_REGISTRY: Arc<Mutex<HashMap<Hash, EscrowContract>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Serialize, Deserialize)]
struct SerializableEscrow {
    contract: EscrowContract,
}

const ESCROW_FILE: &str = "escrows.json";

fn log_event(action: &str, contract_id: &Hash, party: Option<&Hash>) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let party_str = party.map(|h| format!("{:x?}", h)).unwrap_or_else(|| "-".to_string());
    let line = format!("{} | {} | {:x?} | {}\n", now, action, contract_id, party_str);
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("escrow_events.log")
        .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
}

/// Save all escrows to disk
pub fn save_escrows() {
    let reg = ESCROW_REGISTRY.lock().unwrap();
    let list: Vec<_> = reg.values().cloned().map(|contract| SerializableEscrow { contract }).collect();
    if let Ok(json) = serde_json::to_string_pretty(&list) {
        let _ = fs::write(ESCROW_FILE, json);
    }
}

/// Load all escrows from disk
pub fn load_escrows() {
    if let Ok(data) = fs::read_to_string(ESCROW_FILE) {
        if let Ok(list) = serde_json::from_str::<Vec<SerializableEscrow>>(&data) {
            let mut reg = ESCROW_REGISTRY.lock().unwrap();
            reg.clear();
            for item in list {
                reg.insert(item.contract.contract_id, item.contract);
            }
        }
    }
}

/// Create a new escrow contract and store it in the registry
pub fn create_escrow(contract: EscrowContract) {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    reg.insert(contract.contract_id, contract.clone());
    drop(reg);
    save_escrows();
    log_event("create", &contract.contract_id, None);
}

/// Get an escrow contract by ID
pub fn get_escrow(contract_id: &Hash) -> Option<EscrowContract> {
    let reg = ESCROW_REGISTRY.lock().unwrap();
    reg.get(contract_id).cloned()
}

/// Fund an escrow contract (buyer locks funds)
pub fn fund_escrow(contract_id: &Hash, buyer_sig: Hash) -> bool {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    let result = if let Some(contract) = reg.get_mut(contract_id) {
        contract.fund(buyer_sig);
        lock_funds(contract);
        true
    } else {
        false
    };
    drop(reg);
    if result {
        save_escrows();
        log_event("fund", contract_id, Some(&buyer_sig));
    }
    result
}

/// Sign for release (multisig)
pub fn sign_escrow(contract_id: &Hash, signer: Hash) -> bool {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    let result = if let Some(contract) = reg.get_mut(contract_id) {
        contract.sign_release(signer);
        true
    } else {
        false
    };
    drop(reg);
    if result {
        save_escrows();
        log_event("sign", contract_id, Some(&signer));
    }
    result
}

/// Release funds to seller
pub fn release_escrow(contract_id: &Hash) -> bool {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    let result = if let Some(contract) = reg.get_mut(contract_id) {
        let released = contract.release();
        if released {
            release_funds(contract);
        }
        released
    } else {
        false
    };
    drop(reg);
    if result {
        save_escrows();
        log_event("release", contract_id, None);
    }
    result
}

/// Refund to buyer
pub fn refund_escrow(contract_id: &Hash) -> bool {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    let result = if let Some(contract) = reg.get_mut(contract_id) {
        let refunded = contract.refund();
        if refunded {
            refund_funds(contract);
        }
        refunded
    } else {
        false
    };
    drop(reg);
    if result {
        save_escrows();
        log_event("refund", contract_id, None);
    }
    result
}

/// Raise a dispute
pub fn dispute_escrow(contract_id: &Hash, by: Hash) -> bool {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    let result = if let Some(contract) = reg.get_mut(contract_id) {
        contract.dispute(by);
        true
    } else {
        false
    };
    drop(reg);
    if result {
        save_escrows();
        log_event("dispute", contract_id, Some(&by));
    }
    result
}

// Start voting on a dispute
pub async fn start_voting(State(_): State<Arc<()>>, Path(contract_id): Path<Hash>) -> Json<&'static str> {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    if let Some(contract) = reg.get_mut(&contract_id) {
        contract.start_voting();
        save_escrows();
        log_event("start_voting", &contract_id, None);
        Json("Voting started")
    } else {
        Json("Escrow not found")
    }
}

// Submit a vote
#[derive(serde::Deserialize)]
pub struct VoteInput {
    pub voter: Hash,
    pub vote: bool,
}

pub async fn submit_vote(State(_): State<Arc<()>>, Path(contract_id): Path<Hash>, Json(input): Json<VoteInput>) -> Json<&'static str> {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    if let Some(contract) = reg.get_mut(&contract_id) {
        contract.submit_vote(input.voter, input.vote);
        save_escrows();
        log_event("submit_vote", &contract_id, Some(&input.voter));
        Json("Vote submitted")
    } else {
        Json("Escrow not found")
    }
}

// Tally votes
pub async fn tally_votes(State(_): State<Arc<()>>, Path(contract_id): Path<Hash>) -> Json<Option<bool>> {
    let mut reg = ESCROW_REGISTRY.lock().unwrap();
    if let Some(contract) = reg.get_mut(&contract_id) {
        let result = contract.tally_votes();
        save_escrows();
        log_event("tally_votes", &contract_id, None);
        Json(result)
    } else {
        Json(None)
    }
}

// --- Transaction stubs ---
fn lock_funds(contract: &EscrowContract) {
    println!("[TX] Locking {} BLK from buyer {:x?} for escrow {:x?}", contract.amount, contract.buyer, contract.contract_id);
    // TODO: Implement actual transaction to lock funds
}

fn release_funds(contract: &EscrowContract) {
    println!("[TX] Releasing {} BLK to seller {:x?} for escrow {:x?}", contract.amount, contract.seller, contract.contract_id);
    // TODO: Implement actual transaction to release funds
}

fn refund_funds(contract: &EscrowContract) {
    println!("[TX] Refunding {} BLK to buyer {:x?} for escrow {:x?}", contract.amount, contract.buyer, contract.contract_id);
    // TODO: Implement actual transaction to refund funds
}
// --- End transaction stubs ---