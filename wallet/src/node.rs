//! The node interface the wallet needs, implemented by the RPC client.

use blacksilk_rpc as rpc;

pub trait NodeApi {
    fn info(&self) -> Result<rpc::Info, String>;
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String>;
    fn distribution(&self, to: u64) -> Result<rpc::Distribution, String>;
    fn outputs(&self, indices: &[u64]) -> Result<rpc::Outputs, String>;
    fn submit_tx(&self, tx: &[u8]) -> Result<rpc::SubmitResult, String>;
}

impl NodeApi for rpc::Client {
    fn info(&self) -> Result<rpc::Info, String> {
        rpc::Client::info(self).map_err(|e| e.to_string())
    }
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
        rpc::Client::blocks(self, from, count).map_err(|e| e.to_string())
    }
    fn distribution(&self, to: u64) -> Result<rpc::Distribution, String> {
        rpc::Client::distribution(self, to).map_err(|e| e.to_string())
    }
    fn outputs(&self, indices: &[u64]) -> Result<rpc::Outputs, String> {
        rpc::Client::outputs(self, indices).map_err(|e| e.to_string())
    }
    fn submit_tx(&self, tx: &[u8]) -> Result<rpc::SubmitResult, String> {
        rpc::Client::submit_tx(self, tx).map_err(|e| e.to_string())
    }
}
