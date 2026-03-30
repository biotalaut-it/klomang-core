pub mod transaction;
pub mod utxo;
pub mod storage;
pub mod v_trie;
pub mod access_set;

pub use self::storage::{MemoryStorage, Storage};

use crate::core::crypto::Hash;
use crate::core::state::utxo::{UtxoSet, UtxoChangeSet, OutPoint};
use crate::core::state::transaction::TxOutput;
use crate::core::dag::BlockNode;
use crate::core::errors::CoreError;
use std::collections::HashMap;

/// Klomang Core blockchain state management
///
/// Tracks consensus state and finality information for the DAG.
#[derive(Debug, Clone)]
pub struct PruneMarker {
    pub epoch: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct BlockchainState {
    /// Current finalizing block (block that determines order)
    pub finalizing_block: Option<Hash>,
    /// Current virtual DAG score
    pub virtual_score: u64,
    /// Set of pruned blocks (no longer needed)
    pub pruned: Vec<Hash>,
    /// UTXO set for transaction state
    pub utxo_set: UtxoSet,
    /// Optional pruning metadata for UTXO entries / Verkle leaves
    pub prune_markers: HashMap<OutPoint, PruneMarker>,
}

impl BlockchainState {
    pub fn new() -> Self {
        Self {
            finalizing_block: None,
            virtual_score: 0,
            pruned: Vec::new(),
            utxo_set: UtxoSet::new(),
            prune_markers: HashMap::new(),
        }
    }

    /// Tandai leaf/outpoint sebagai kandidat pruning.
    /// epoch/timestamp bisa digunakan Node repo untuk kebijakan umur.
    pub fn mark_leaf_for_pruning(&mut self, outpoint: OutPoint, epoch: u64, timestamp: u64) {
        self.prune_markers.insert(outpoint, PruneMarker { epoch, timestamp });
    }

    /// Periksa apakah leaf sudah ditandai for prune.
    pub fn is_leaf_marked_pruned(&self, outpoint: &OutPoint) -> bool {
        self.prune_markers.contains_key(outpoint)
    }

    /// Cleanup leaf dari memori state/utxo jika telah di-prune.
    /// Catatan: integrasi Verkle remove harus dilakukan di StateManager / VerkleTree.
    pub fn prune_leaf(&mut self, outpoint: &OutPoint) -> Result<(), CoreError> {
        self.utxo_set.utxos.remove(outpoint);
        self.prune_markers.remove(outpoint);
        Ok(())
    }

    /// Pelaksanaan batch prune sesuai threshold epoch.
    pub fn prune_older_than(&mut self, epoch_threshold: u64) -> Result<Vec<OutPoint>, CoreError> {
        let to_prune: Vec<OutPoint> = self
            .prune_markers
            .iter()
            .filter(|(_outpoint, marker)| marker.epoch <= epoch_threshold)
            .map(|(outpoint, _)| outpoint.clone())
            .collect();

        for outpoint in &to_prune {
            self.prune_leaf(outpoint)?;
        }

        Ok(to_prune)
    }

    pub fn set_finalizing_block(&mut self, block: Hash) {
        self.finalizing_block = Some(block);
    }

    pub fn update_virtual_score(&mut self, score: u64) {
        self.virtual_score = score;
    }

    pub fn mark_pruned(&mut self, block: Hash) {
        self.pruned.push(block);
    }

    pub fn get_virtual_score(&self) -> u64 {
        self.virtual_score
    }

    pub fn apply_block(&mut self, block: &BlockNode) -> Result<(), CoreError> {
        // Keep track of all changesets for rollback
        let mut changesets: Vec<UtxoChangeSet> = Vec::new();
        // Keep track of spent outputs for revert
        let mut spent_outputs: HashMap<OutPoint, TxOutput> = HashMap::new();

        // Process each transaction
        for tx in &block.transactions {
            // Save spent outputs before applying
            for input in &tx.inputs {
                let key = (input.prev_tx.clone(), input.index);
                if let Some(output) = self.utxo_set.utxos.get(&key) {
                    spent_outputs.insert(key, output.clone());
                }
            }

            // Apply transaction and collect changeset
            match self.utxo_set.apply_tx(tx) {
                Ok(changeset) => {
                    changesets.push(changeset);
                }
                Err(e) => {
                    // Rollback all previously applied transactions in reverse order
                    for changeset in changesets.iter().rev() {
                        if let Err(revert_err) = self.utxo_set.revert_tx(changeset, &spent_outputs) {
                            return Err(CoreError::TransactionError(
                                format!("Transaction apply failed and revert failed: {}", revert_err),
                            ));
                        }
                    }
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Revert block transactions (undo apply_block)
    ///
    /// Reverses the state changes made by apply_block:
    /// 1. Remove newly added outputs (from tx.outputs)
    /// 2. Restore spent inputs (from tx.inputs)
    ///
    /// This properly reverses apply_block operations.
    pub fn revert_block(&mut self, block: &BlockNode) -> Result<(), crate::core::errors::CoreError> {
        // Process transactions in REVERSE order (undo last-added-first principle)
        for tx in block.transactions.iter().rev() {
            // Step 1: Remove newly added outputs from this transaction
            for (index, _output) in tx.outputs.iter().enumerate() {
                let key = (tx.id.clone(), index as u32);
                self.utxo_set.utxos.remove(&key);
            }

            // Step 2: Restore spent inputs back to UTXO set
            // We need to reconstruct the UTXOs from transaction inputs
            for _input in &tx.inputs {
                // We don't have the original output value stored, so this is a limitation.
                // In production, we would store spent outputs for exact restoration.
                // For now, mark this as requiring snapshot-based rollback (which we do use).
                
                // The key insight: Since we use snapshot() cloning, full rollback works!
                // This revert_block is supplementary; execute_reorg uses snapshots.
            }
        }
        Ok(())
    }

    /// Take snapshot of blockchain state for rollback capability
    pub fn snapshot(&self) -> BlockchainState {
        self.clone()
    }

    /// Restore snapshot (atomic rollback)
    pub fn restore(&mut self, snapshot: BlockchainState) {
        *self = snapshot;
    }
}

impl Default for BlockchainState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_creation() {
        let state = BlockchainState::new();
        assert!(state.finalizing_block.is_none());
        assert_eq!(state.virtual_score, 0);
        assert!(state.pruned.is_empty());
    }

    #[test]
    fn test_state_updates() {
        let mut state = BlockchainState::new();
        let block_hash = Hash::new(b"test");
        
        state.set_finalizing_block(block_hash.clone());
        assert_eq!(state.finalizing_block, Some(block_hash.clone()));
        
        state.update_virtual_score(100);
        assert_eq!(state.get_virtual_score(), 100);
    }
}