//! The node interface the wallet needs, implemented by the RPC client.

use blacksilk_rpc as rpc;

pub trait NodeApi {
    fn info(&self) -> Result<rpc::Info, String>;
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String>;
    /// The headers of blocks `from..from + count` (`/headers`, docs/blocks.md
    /// §9): the header check reads the chain from the genesis with it, and
    /// the reorganization check and the backfill read single headers. The
    /// default is a node that does not serve it: the wallet then refuses
    /// what needs it.
    fn headers(&self, _from: u64, _count: u64) -> Result<rpc::Headers, String> {
        Err("/headers is not available".into())
    }
    fn distribution(&self, to: u64) -> Result<rpc::Distribution, String>;
    fn outputs(&self, indices: &[u64]) -> Result<rpc::Outputs, String>;
    fn submit_tx(&self, tx: &[u8]) -> Result<rpc::SubmitResult, String>;
    fn px_commitments(&self, from: u64) -> Result<rpc::PxCommitments, String>;
    fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String>;
    /// Whether the node has transaction `id` pooled or mined (`/tx/status`,
    /// docs/blocks.md §9). The wallet checks on its pending transactions
    /// with it instead of re-posting them (docs/px.md §12). The default is a
    /// node that cannot answer: the wallet then sends nothing before the
    /// network expiry window ends.
    fn tx_status(&self, _id: &[u8; 32]) -> Result<rpc::TxStatus, String> {
        Err("/tx/status is not available".into())
    }
}

impl NodeApi for rpc::Client {
    fn info(&self) -> Result<rpc::Info, String> {
        rpc::Client::info(self).map_err(|e| e.to_string())
    }
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
        rpc::Client::blocks(self, from, count).map_err(|e| e.to_string())
    }
    fn headers(&self, from: u64, count: u64) -> Result<rpc::Headers, String> {
        rpc::Client::headers(self, from, count).map_err(|e| e.to_string())
    }
    fn distribution(&self, to: u64) -> Result<rpc::Distribution, String> {
        rpc::Client::distribution(self, to).map_err(|e| e.to_string())
    }
    fn outputs(&self, indices: &[u64]) -> Result<rpc::Outputs, String> {
        rpc::Client::outputs(self, indices).map_err(|e| e.to_string())
    }
    fn px_commitments(&self, from: u64) -> Result<rpc::PxCommitments, String> {
        rpc::Client::px_commitments(self, from).map_err(|e| e.to_string())
    }
    fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String> {
        rpc::Client::px_contracts(self, from).map_err(|e| e.to_string())
    }
    fn submit_tx(&self, tx: &[u8]) -> Result<rpc::SubmitResult, String> {
        rpc::Client::submit_tx(self, tx).map_err(|e| e.to_string())
    }
    fn tx_status(&self, id: &[u8; 32]) -> Result<rpc::TxStatus, String> {
        rpc::Client::tx_status(self, id).map_err(|e| e.to_string())
    }
}
