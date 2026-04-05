use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::crypto::{Hash, schnorr};
use crate::core::state::transaction::Transaction;
use crate::core::dag::BlockNode;
use crate::core::state_manager::StateManager;
use crate::core::state::storage::Storage;
use crate::core::state::utxo::UtxoSet;

pub type TransactionID = Hash;
pub type SignedTransaction = Transaction;

const DEFAULT_MAX_MEMPOOL_BYTES: usize = 100 * 1024 * 1024;
const DEFAULT_MAX_MEMPOOL_TXS: usize = 50_000;
const DEFAULT_MIN_FEE_PER_BYTE: u128 = 1;
const DEFAULT_TX_TTL_SECONDS: u64 = 60 * 60 * 24; // 24 hours
const MAX_TX_SIZE_BYTES: usize = 1 * 1024 * 1024; // 1MB per transaction

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    DuplicateTransaction,
    OversizedTransaction { size: usize, max: usize },
    FeeTooLow { received: u128, required: u128 },
    InvalidSignature(String),
    PoolFull,
    TransactionNotFound,
    ExpiredTransaction,
}

impl fmt::Display for MempoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MempoolError::DuplicateTransaction => write!(f, "Duplicate transaction"),
            MempoolError::OversizedTransaction { size, max } => {
                write!(f, "Transaction size {} exceeds max {} bytes", size, max)
            }
            MempoolError::FeeTooLow { received, required } => write!(f, "Fee per byte {} is below required {}", received, required),
            MempoolError::InvalidSignature(reason) => write!(f, "Invalid transaction signature: {}", reason),
            MempoolError::PoolFull => write!(f, "Mempool capacity reached"),
            MempoolError::TransactionNotFound => write!(f, "Transaction not found"),
            MempoolError::ExpiredTransaction => write!(f, "Transaction expired"),
        }
    }
}

impl std::error::Error for MempoolError {}

#[derive(Clone, Debug)]
pub struct PendingTransaction {
    tx: SignedTransaction,
    inserted_at: u64,
    size_bytes: usize,
    fee_per_byte: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PriorityKey {
    fee_per_byte: u128,
    inserted_at: u64,
    tx_id: TransactionID,
}

impl Ord for PriorityKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.fee_per_byte.cmp(&other.fee_per_byte).reverse() {
            Ordering::Equal => match self.inserted_at.cmp(&other.inserted_at) {
                Ordering::Equal => self.tx_id.cmp(&other.tx_id),
                other => other,
            },
            other => other,
        }
    }
}

impl PartialOrd for PriorityKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
struct MempoolInner {
    transactions: HashMap<TransactionID, PendingTransaction>,
    priority_index: BTreeSet<PriorityKey>,
    total_bytes: usize,
}

impl MempoolInner {
    fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            priority_index: BTreeSet::new(),
            total_bytes: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Mempool {
    inner: Arc<RwLock<MempoolInner>>,
    max_bytes: usize,
    max_transactions: usize,
    min_fee_per_byte: u128,
    ttl_seconds: u64,
}

impl Mempool {
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_MAX_MEMPOOL_BYTES,
            DEFAULT_MAX_MEMPOOL_TXS,
            DEFAULT_MIN_FEE_PER_BYTE,
            DEFAULT_TX_TTL_SECONDS,
        )
    }

    pub fn with_limits(
        max_bytes: usize,
        max_transactions: usize,
        min_fee_per_byte: u128,
        ttl_seconds: u64,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MempoolInner::new())),
            max_bytes,
            max_transactions,
            min_fee_per_byte,
            ttl_seconds,
        }
    }

    pub fn validate_transaction_stateless(&self, tx: &SignedTransaction) -> Result<(), MempoolError> {
        let size_bytes = Self::calculate_tx_size_bytes(tx);

        if size_bytes > MAX_TX_SIZE_BYTES {
            return Err(MempoolError::OversizedTransaction {
                size: size_bytes,
                max: MAX_TX_SIZE_BYTES,
            });
        }

        let fee_per_byte = Self::calculate_fee_per_byte(tx, size_bytes);
        if fee_per_byte < self.min_fee_per_byte {
            return Err(MempoolError::FeeTooLow {
                received: fee_per_byte,
                required: self.min_fee_per_byte,
            });
        }

        for (input_index, input) in tx.inputs.iter().enumerate() {
            if input.signature.len() != 64 {
                return Err(MempoolError::InvalidSignature("signature must be 64 bytes".into()));
            }
            if input.pubkey.len() != 32 && input.pubkey.len() != 33 {
                return Err(MempoolError::InvalidSignature("public key must be 32 or 33 bytes".into()));
            }

            let sighash = schnorr::compute_sighash(tx, input_index, input.sighash_type)
                .map_err(|err| MempoolError::InvalidSignature(err.to_string()))?;

            let mut pubkey_bytes = [0u8; 32];
            pubkey_bytes.copy_from_slice(&input.pubkey[..32]);

            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&input.signature[..64]);

            let pubkey = k256::schnorr::VerifyingKey::from_bytes(&pubkey_bytes)
                .map_err(|err| MempoolError::InvalidSignature(err.to_string()))?;
            let signature = k256::schnorr::Signature::try_from(&sig_bytes[..])
                .map_err(|err| MempoolError::InvalidSignature(err.to_string()))?;
            let valid = schnorr::verify(&pubkey, &sighash, &signature);
            if !valid {
                return Err(MempoolError::InvalidSignature(format!(
                    "input {} signature verification failed",
                    input_index
                )));
            }
        }

        Ok(())
    }

    pub fn validate_transaction_stateful<S: Storage + Clone + Send + Sync + 'static>(
        &self,
        tx: &SignedTransaction,
        state_manager: &mut StateManager<S>,
        utxo_set: &UtxoSet
    ) -> Result<(), MempoolError> {
        // First, perform stateless validation
        self.validate_transaction_stateless(tx)?;

        // Calculate total input value and verify UTXOs exist and are unspent
        let mut total_input_value = 0u128;
        for input in &tx.inputs {
            let outpoint = (input.prev_tx.clone(), input.index);

            // Check if UTXO exists in current set
            let utxo_entry = utxo_set.utxos.get(&outpoint)
                .ok_or_else(|| MempoolError::InvalidSignature("Input UTXO not found or already spent".into()))?;

            // Verify Verkle proof for this UTXO
            let key = state_manager.outpoint_to_key.get(&outpoint)
                .ok_or_else(|| MempoolError::InvalidSignature("UTXO key mapping not found".into()))?;

            // Generate proof for the UTXO key
            let proof = state_manager.tree.generate_proof(*key)
                .map_err(|e| MempoolError::InvalidSignature(format!("Failed to generate Verkle proof: {}", e)))?;

            // Verify the proof
            if !state_manager.tree.verify_proof(&proof)
                .map_err(|e| MempoolError::InvalidSignature(format!("Verkle proof verification failed: {}", e)))? {
                return Err(MempoolError::InvalidSignature("UTXO Verkle proof verification failed".into()));
            }

            total_input_value = total_input_value.checked_add(utxo_entry.value as u128)
                .ok_or_else(|| MempoolError::InvalidSignature("Input value overflow".into()))?;
        }

        // Calculate total output value
        let mut total_output_value = 0u128;
        for output in &tx.outputs {
            total_output_value = total_output_value.checked_add(output.value as u128)
                .ok_or_else(|| MempoolError::InvalidSignature("Output value overflow".into()))?;
        }

        // Calculate fee
        let fee = total_input_value.checked_sub(total_output_value)
            .ok_or_else(|| MempoolError::InvalidSignature("Insufficient input value for outputs".into()))?;

        // Verify fee meets minimum requirements based on economic rules
        let gas_fee = tx.max_fee_per_gas.saturating_mul(tx.gas_limit as u128);
        if fee < gas_fee {
            return Err(MempoolError::FeeTooLow {
                received: fee,
                required: gas_fee,
            });
        }

        // Check against global economic constraints
        if total_output_value > state_manager.current_total_supply {
            return Err(MempoolError::InvalidSignature("Transaction would exceed total supply".into()));
        }

        Ok(())
    }

    pub fn insert_transaction<S: Storage + Clone + Send + Sync + 'static>(
        &self, 
        tx: SignedTransaction, 
        state_manager: &mut StateManager<S>,
        utxo_set: &UtxoSet
    ) -> Result<(), MempoolError> {
        let tx_id = tx.id.clone();
        let size_bytes = Self::calculate_tx_size_bytes(&tx);
        let fee_per_byte = Self::calculate_fee_per_byte(&tx, size_bytes);

        self.validate_transaction_stateful(&tx, state_manager, utxo_set)?;

        let mut inner = self.inner.write().unwrap();

        if inner.transactions.contains_key(&tx_id) {
            return Err(MempoolError::DuplicateTransaction);
        }

        if inner.total_bytes + size_bytes > self.max_bytes || inner.transactions.len() + 1 > self.max_transactions {
            if !self.should_accept_new_transaction(&inner, fee_per_byte) {
                return Err(MempoolError::PoolFull);
            }
            self.evict_lowest_priority(&mut inner);
        }

        let inserted_at = Self::current_timestamp_secs();
        let pending = PendingTransaction {
            tx: tx.clone(),
            inserted_at,
            size_bytes,
            fee_per_byte,
        };

        let priority_key = PriorityKey {
            fee_per_byte,
            inserted_at,
            tx_id: tx.id.clone(),
        };

        inner.total_bytes += size_bytes;
        inner.priority_index.insert(priority_key);
        inner.transactions.insert(tx_id, pending);

        Ok(())
    }

    pub fn revalidate_pending_transactions<S: Storage + Clone + Send + Sync + 'static>(
        &self, 
        state_manager: &mut StateManager<S>,
        utxo_set: &UtxoSet
    ) -> usize {
        let mut inner = self.inner.write().unwrap();
        let mut to_remove = Vec::new();

        for (tx_id, pending) in &inner.transactions {
            if self.validate_transaction_stateful(&pending.tx, state_manager, utxo_set).is_err() {
                to_remove.push(tx_id.clone());
            }
        }

        let mut removed_count = 0;
        for tx_id in to_remove {
            if let Some(pending) = inner.transactions.remove(&tx_id) {
                inner.total_bytes = inner.total_bytes.saturating_sub(pending.size_bytes);
                let priority_key = PriorityKey {
                    fee_per_byte: pending.fee_per_byte,
                    inserted_at: pending.inserted_at,
                    tx_id: tx_id.clone(),
                };
                inner.priority_index.remove(&priority_key);
                removed_count += 1;
            }
        }

        removed_count
    }

    pub fn get_top_transactions(&self, limit: usize) -> Vec<SignedTransaction> {
        let inner = self.inner.read().unwrap();
        inner
            .priority_index
            .iter()
            .take(limit)
            .filter_map(|key| inner.transactions.get(&key.tx_id).map(|pending| pending.tx.clone()))
            .collect()
    }

    pub fn remove_on_block_inclusion(&self, block: &BlockNode) -> usize {
        let tx_ids: Vec<TransactionID> = block.transactions.iter().map(|tx| tx.id.clone()).collect();
        self.remove_transactions(&tx_ids)
    }

    pub fn remove_transactions(&self, tx_ids: &[TransactionID]) -> usize {
        let mut inner = self.inner.write().unwrap();
        let mut removed = 0;

        for tx_id in tx_ids {
            if let Some(pending) = inner.transactions.remove(tx_id) {
                inner.total_bytes = inner.total_bytes.saturating_sub(pending.size_bytes);
                let priority_key = PriorityKey {
                    fee_per_byte: pending.fee_per_byte,
                    inserted_at: pending.inserted_at,
                    tx_id: tx_id.clone(),
                };
                inner.priority_index.remove(&priority_key);
                removed += 1;
            }
        }

        removed
    }

    pub fn expire_old_transactions(&self) -> usize {
        let mut inner = self.inner.write().unwrap();
        let now = Self::current_timestamp_secs();
        let expired_ids: Vec<TransactionID> = inner
            .transactions
            .iter()
            .filter_map(|(tx_id, pending)| {
                if pending.inserted_at + self.ttl_seconds <= now {
                    Some(tx_id.clone())
                } else {
                    None
                }
            })
            .collect();

        for tx_id in &expired_ids {
            if let Some(pending) = inner.transactions.remove(tx_id) {
                inner.total_bytes = inner.total_bytes.saturating_sub(pending.size_bytes);
                let priority_key = PriorityKey {
                    fee_per_byte: pending.fee_per_byte,
                    inserted_at: pending.inserted_at,
                    tx_id: tx_id.clone(),
                };
                inner.priority_index.remove(&priority_key);
            }
        }

        expired_ids.len()
    }

    pub fn contains(&self, tx_id: &TransactionID) -> bool {
        self.inner.read().unwrap().transactions.contains_key(tx_id)
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().transactions.len()
    }

    pub fn total_bytes(&self) -> usize {
        self.inner.read().unwrap().total_bytes
    }

    fn current_timestamp_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn calculate_tx_size_bytes(tx: &SignedTransaction) -> usize {
        bincode::serialized_size(tx).map(|size| size as usize).unwrap_or_default()
    }

    fn calculate_fee_per_byte(tx: &SignedTransaction, size_bytes: usize) -> u128 {
        if size_bytes == 0 {
            return 0;
        }

        // Use max_fee_per_gas as a fee density proxy when gas usage is unknown.
        let base_fee = tx.max_fee_per_gas.saturating_mul(tx.gas_limit as u128 + 1);
        let density = base_fee.saturating_div(size_bytes as u128);
        std::cmp::max(density, tx.max_fee_per_gas)
    }

    fn should_accept_new_transaction(&self, inner: &MempoolInner, fee_per_byte: u128) -> bool {
        if inner.transactions.len() < self.max_transactions && inner.total_bytes < self.max_bytes {
            return true;
        }
        if let Some(lowest) = inner.priority_index.iter().next_back() {
            fee_per_byte > lowest.fee_per_byte
        } else {
            true
        }
    }

    fn evict_lowest_priority(&self, inner: &mut MempoolInner) {
        if let Some(lowest) = inner.priority_index.iter().next_back().cloned() {
            inner.priority_index.remove(&lowest);
            if let Some(pending) = inner.transactions.remove(&lowest.tx_id) {
                inner.total_bytes = inner.total_bytes.saturating_sub(pending.size_bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::schnorr::KeyPairWrapper;
    use crate::core::crypto::Hash;
    use crate::core::state::transaction::{SigHashType, TxInput, TxOutput};
    use crate::core::state::storage::MemoryStorage;
    use crate::core::state_manager::StateManager;
    use crate::core::state::v_trie::VerkleTree;

    fn build_test_state_manager() -> (StateManager<MemoryStorage>, UtxoSet) {
        let storage = MemoryStorage::new();
        let tree = VerkleTree::new(storage).unwrap();
        let mut state_manager = StateManager::new(tree).unwrap();
        
        // Create UTXO set
        let mut utxo_set = UtxoSet::new();

        // Add a valid UTXO to the state
        let prev_tx_hash = Hash::new(b"prev");
        let outpoint = (prev_tx_hash.clone(), 0);
        let utxo_output = TxOutput {
            value: 2000, // Enough for the transaction
            pubkey_hash: Hash::new(b"sender"),
        };
        
        // Insert into UTXO set
        utxo_set.utxos.insert(outpoint.clone(), utxo_output.clone());
        
        // Create key for Verkle tree
        let mut data = prev_tx_hash.as_bytes().to_vec();
        data.extend_from_slice(&0u32.to_le_bytes());
        let hash = Hash::new(&data);
        let key = hash.as_bytes();
        state_manager.outpoint_to_key.insert(outpoint, *key);
        
        // Insert into Verkle tree
        state_manager.tree.insert(*key, utxo_output.serialize());
        
        // Update total supply
        state_manager.current_total_supply = 2000;
        
        (state_manager, utxo_set)
    }

    fn build_signed_transaction() -> SignedTransaction {
        let mut tx = Transaction::new(vec![TxInput {
            prev_tx: Hash::new(b"prev"),
            index: 0,
            signature: vec![0u8; 64],
            pubkey: vec![0u8; 32],
            sighash_type: SigHashType::All,
        }], vec![TxOutput {
            value: 1000,
            pubkey_hash: Hash::new(b"dest"),
        }]);
        tx.max_fee_per_gas = 10;
        tx.gas_limit = 20; // Reduced gas limit to make fee requirement reasonable
        tx.id = tx.calculate_id();
        tx
    }

    #[test]
    fn test_insert_and_get_top_transactions() {
        let mempool = Mempool::new();
        let (mut state_manager, utxo_set) = build_test_state_manager();
        let mut tx = build_signed_transaction();

        let keypair = KeyPairWrapper::new();
        let pubkey = keypair.public_key();
        tx.inputs[0].pubkey = pubkey.to_bytes().to_vec();
        let sighash = schnorr::compute_sighash(&tx, 0, SigHashType::All).unwrap();
        let signature = keypair.sign(&sighash);
        tx.inputs[0].signature = signature.to_bytes().to_vec();

        mempool.insert_transaction(tx.clone(), &mut state_manager, &utxo_set).expect("failed to insert valid transaction");
        assert!(mempool.contains(&tx.id));
        assert_eq!(mempool.len(), 1);
        let top = mempool.get_top_transactions(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].id, tx.id);
    }

    #[test]
    fn test_duplicate_transaction_rejected() {
        let mempool = Mempool::new();
        let (mut state_manager, utxo_set) = build_test_state_manager();
        let mut tx = build_signed_transaction();
        let keypair = KeyPairWrapper::new();
        let pubkey = keypair.public_key();
        tx.inputs[0].pubkey = pubkey.to_bytes().to_vec();
        let sighash = schnorr::compute_sighash(&tx, 0, SigHashType::All).unwrap();
        let signature = keypair.sign(&sighash);
        tx.inputs[0].signature = signature.to_bytes().to_vec();

        mempool.insert_transaction(tx.clone(), &mut state_manager, &utxo_set).expect("failed to insert valid transaction");
        assert_eq!(mempool.insert_transaction(tx, &mut state_manager, &utxo_set).unwrap_err(), MempoolError::DuplicateTransaction);
    }

    #[test]
    fn test_expire_old_transactions() {
        let mempool = Mempool::with_limits(1_000_000, 50, 1, 0);
        let (mut state_manager, utxo_set) = build_test_state_manager();
        let mut tx = build_signed_transaction();
        let keypair = KeyPairWrapper::new();
        let pubkey = keypair.public_key();
        tx.inputs[0].pubkey = pubkey.to_bytes().to_vec();
        let sighash = schnorr::compute_sighash(&tx, 0, SigHashType::All).unwrap();
        let signature = keypair.sign(&sighash);
        tx.inputs[0].signature = signature.to_bytes().to_vec();

        mempool.insert_transaction(tx.clone(), &mut state_manager, &utxo_set).expect("failed to insert valid transaction");
        assert_eq!(mempool.expire_old_transactions(), 1);
        assert!(!mempool.contains(&tx.id));
    }

    #[test]
    fn test_remove_on_block_inclusion() {
        let mempool = Mempool::new();
        let (mut state_manager, utxo_set) = build_test_state_manager();
        let mut tx = build_signed_transaction();
        let keypair = KeyPairWrapper::new();
        let pubkey = keypair.public_key();
        tx.inputs[0].pubkey = pubkey.to_bytes().to_vec();
        let sighash = schnorr::compute_sighash(&tx, 0, SigHashType::All).unwrap();
        let signature = keypair.sign(&sighash);
        tx.inputs[0].signature = signature.to_bytes().to_vec();

        mempool.insert_transaction(tx.clone(), &mut state_manager, &utxo_set).expect("failed to insert valid transaction");

        let block = BlockNode {
            header: crate::core::dag::BlockHeader {
                id: Hash::new(b"block"),
                parents: std::collections::HashSet::new(),
                timestamp: 0,
                difficulty: 1,
                nonce: 0,
                verkle_root: Hash::new(b"root"),
                verkle_proofs: None,
                signature: None,
            },
            children: std::collections::HashSet::new(),
            selected_parent: None,
            blue_set: std::collections::HashSet::new(),
            red_set: std::collections::HashSet::new(),
            blue_score: 0,
            transactions: vec![tx.clone()],
        };

        assert_eq!(mempool.remove_on_block_inclusion(&block), 1);
        assert!(!mempool.contains(&tx.id));
    }
}
