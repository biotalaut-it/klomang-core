// Informasi lengkap mengenai lisensi dan aspek hukum dalam Bahasa Indonesia tersedia di docs/LISENSI_DAN_HUKUM.md

// Copyright 2026 Klomang Core Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![deny(warnings)]

//! # Klomang Core Engine
//!
//! Production-ready BlockDAG engine implementation optimized for large-scale deployment.
//!
//! ## Key Features
//! - **GhostDAG Consensus**: BlockDAG with parallel block ordering
//! - **Verkle State Tree**: Efficient state management with O(log n) operations
//! - **Schnorr Signatures**: Batch verification for high TPS
//! - **Economic Policy**: 80/20 miner/fullnode reward distribution
//! - **Atomic State Transitions**: Rollback-safe state management
//!
//! ## Performance Optimizations
//! - Schnorr batch signature verification for block validation
//! - Incremental Verkle commitment caching for O(log n) state updates
//! - Reduced redundant root recomputation and path invalidation
//! - Parallel transaction processing with conflict detection
//!
//! ## Integration Guide
//!
//! ### Basic Usage
//! ```rust
//! use klomang_core::{GhostDag, UtxoSet, MemoryStorage, Dag, BlockNode, BlockHeader, Hash};
//! use std::collections::HashSet;
//!
//! let storage = MemoryStorage::new();
//! let mut ghostdag = GhostDag::new(64);
//! let mut utxo = UtxoSet::new();
//! let mut dag = Dag::new();
//!
//! let genesis = BlockNode {
//!     header: BlockHeader {
//!         id: Hash::new(b"genesis"),
//!         parents: HashSet::new(),
//!         timestamp: 0,
//!         difficulty: 1,
//!         nonce: 0,
//!         verkle_root: Hash::new(b"root"),
//!         verkle_proofs: None,
//!         signature: None,
//!     },
//!     children: HashSet::new(),
//!     selected_parent: None,
//!     blue_set: HashSet::new(),
//!     red_set: HashSet::new(),
//!     blue_score: 0,
//!     transactions: Vec::new(),
//! };
//!
//! dag.add_block(genesis).expect("add genesis block");
//!
//! // Process blocks with automatic signature batch verification
//! // and Verkle state updates
//! ```
//!
//! ### State Management
//! ```rust
//! use klomang_core::core::state_manager::StateManager;
//! use klomang_core::core::state::v_trie::VerkleTree;
//! use klomang_core::core::state::MemoryStorage;
//! use klomang_core::core::state::utxo::UtxoSet;
//! use klomang_core::core::dag::{BlockNode, BlockHeader};
//! use klomang_core::core::crypto::Hash;
//! use std::collections::HashSet;
//!
//! # let storage = MemoryStorage::new();
//! # let tree = VerkleTree::new(storage.clone()).expect("create Verkle tree");
//! # let mut manager = StateManager::new(tree).expect("state manager");
//! # let mut utxo = UtxoSet::new();
//! # let block = BlockNode {
//! #     header: BlockHeader {
//! #         id: Hash::new(b"block1"),
//! #         parents: HashSet::new(),
//! #         timestamp: 0,
//! #         difficulty: 1,
//! #         nonce: 0,
//! #         verkle_root: Hash::new(b"root"),
//! #         verkle_proofs: None,
//! #         signature: None,
//! #     },
//! #     children: HashSet::new(),
//! #     selected_parent: None,
//! #     blue_set: HashSet::new(),
//! #     red_set: HashSet::new(),
//! #     blue_score: 0,
//! #     transactions: Vec::new(),
//! # };
//!
//! // Atomic block application with rollback capability
//! manager.apply_block(&block, &mut utxo).expect("apply block");
//! ```
//!
//! ## Security
//! - Anti-burn address enforcement
//! - Supply cap validation
//! - Double-spend prevention
//! - Cryptographic signature verification

pub mod core;

// Re-export public API for external node integration
pub use core::crypto::Hash;
pub use core::dag::{BlockNode, BlockHeader, Dag};
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
pub use core::crypto::verkle::{VerkleTree, VerkleProof};
pub use core::crypto::schnorr::verify_block_signature;
pub use core::mempool::{Mempool, MempoolError, SignedTransaction, TransactionID};
pub use core::state_manager::StateManager;
pub use core::state_manager::BlockUndo;

// Re-export modules for direct access
pub use core::{mempool, state, consensus, crypto, dag, state_manager};

/// Prelude module for convenient imports of core types
pub mod prelude {
    pub use super::core::crypto::Hash;
    pub use super::core::dag::{BlockNode, BlockHeader, Dag};
    pub use super::core::state::transaction::Transaction;
    pub use super::core::state::BlockchainState;
    pub use super::core::state::utxo::UtxoSet;
    pub use super::core::state_manager::StateManager;
    pub use super::core::consensus::ghostdag::GhostDag;
    pub use super::core::crypto::verkle::VerkleTree;
    pub use super::core::mempool::Mempool;
    pub use super::core::errors::CoreError;
}

#[no_mangle]
pub extern "C" fn __rust_probestack() {}

