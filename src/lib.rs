#![deny(warnings)]

// Klomang Core Engine
// Production-ready BlockDAG engine implementation

pub mod core;

// Re-export public API for external node integration
pub use core::crypto::Hash;
pub use core::dag::{BlockNode, Dag};
pub use core::consensus::ghostdag::GhostDag;
pub use core::state::transaction::Transaction;
pub use core::state::BlockchainState;
pub use core::state::utxo::UtxoSet;
pub use core::state::{MemoryStorage, Storage};
pub use core::errors::CoreError;
pub use core::config::Config;
pub use core::consensus::emission::{COIN_UNIT, MAX_SUPPLY, block_reward};
pub use core::daa::difficulty::Daa;
pub use core::pow::Pow;

#[no_mangle]
pub extern "C" fn __rust_probestack() {}

