//! Node interface: JSON-RPC HTTP client for BlackSilk node

use reqwest::blocking::Client;
use serde_json::json;

pub struct NodeClient {
    pub url: String,
    client: Client,
}

impl NodeClient {
    pub fn new(url: &str) -> Self {
        NodeClient {
            url: url.to_string(),
            client: Client::new(),
        }
    }

    pub fn get_balance(&self, address: &str) -> Result<f64, String> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_balance",
            "params": { "address": address }
        });
        let resp = self.client.post(&self.url)
            .json(&req)
            .send()
            .map_err(|e| e.to_string())?;
        let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        json["result"].as_f64().ok_or("Invalid response".to_string())
    }

    pub fn send_transaction(&self, to: &str, amount: f64) -> Result<String, String> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "send_transaction",
            "params": { "to": to, "amount": amount }
        });
        let resp = self.client.post(&self.url)
            .json(&req)
            .send()
            .map_err(|e| e.to_string())?;
        let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        json["result"]["txid"].as_str().map(|s| s.to_string()).ok_or("Invalid response".to_string())
    }

    /// Fetch decoy public keys for ring signature (from node)
    pub fn get_ring_members(&self, count: usize) -> Result<Vec<[u8; 32]>, String> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_ring_members",
            "params": { "count": count }
        });
        let resp = self.client.post(&self.url)
            .json(&req)
            .send()
            .map_err(|e| e.to_string())?;
        let json: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        if let Some(arr) = json["result"].as_array() {
            let mut ring = Vec::new();
            for pk in arr {
                if let Some(pk_str) = pk.as_str() {
                    if let Ok(bytes) = hex::decode(pk_str) {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            ring.push(arr);
                        }
                    }
                }
            }
            Ok(ring)
        } else {
            Err("Invalid ring member response".to_string())
        }
    }
    // TODO: Add get_history, validate address, etc.
}
