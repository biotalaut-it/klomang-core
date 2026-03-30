use std::collections::HashMap;
use crate::core::crypto::Hash;
use crate::core::state::transaction::{Transaction, TxOutput};
use crate::core::crypto::schnorr;
use crate::core::errors::CoreError;

/// OutPoint: (tx_id, output_index)
pub type OutPoint = (Hash, u32);

/// UTXO Change Set untuk atomic transaction
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UtxoChangeSet {
    pub spent: Vec<OutPoint>,
    pub created: Vec<(OutPoint, TxOutput)>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UtxoSet {
    pub utxos: HashMap<OutPoint, TxOutput>,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
        }
    }

    /// Validate transaction inputs without mutations
    pub const ZERO_ADDRESS: [u8; 32] = [0u8; 32];

    pub fn validate_tx(&self, tx: &Transaction) -> Result<u64, CoreError> {
        // Anti-Deflationary: reject outputs to null/burn address, including coinbase
        let zero_address_hash = crate::core::crypto::Hash::new(&Self::ZERO_ADDRESS);
        for output in &tx.outputs {
            if output.pubkey_hash == zero_address_hash {
                println!(
                    "[utxo][validate_tx] reject tx {} output to ZERO_ADDRESS",
                    tx.id
                );
                return Err(CoreError::TransactionError(
                    "Output to zero address (burn) is prohibited".to_string(),
                ));
            }
        }

        if tx.is_coinbase() {
            return Ok(0);
        }

        let mut total_input = 0u64;
        for input in &tx.inputs {
            let key = (input.prev_tx.clone(), input.index);
            match self.utxos.get(&key) {
                Some(output) => {
                    total_input = total_input.checked_add(output.value)
                        .ok_or(CoreError::TransactionError("Input overflow".to_string()))?;

                    // Verify Schnorr signature using transaction sighash and public key
                    if input.pubkey.len() != 33 && input.pubkey.len() != 32 {
                        return Err(CoreError::InvalidPublicKey);
                    }
                    if input.signature.len() != 64 {
                        return Err(CoreError::InvalidSignature);
                    }

                    let pubkey = k256::schnorr::VerifyingKey::from_bytes(&input.pubkey)
                        .map_err(|_| CoreError::InvalidPublicKey)?;
                    let signature = k256::schnorr::Signature::try_from(&input.signature[..])
                        .map_err(|_| CoreError::InvalidSignature)?;

                    let msg = schnorr::tx_message(tx);
                    if !schnorr::verify(&pubkey, &msg, &signature) {
                        return Err(CoreError::SignatureVerificationFailed);
                    }
                }
                None => return Err(CoreError::TransactionError("Input UTXO not found".to_string())),
            }
        }

        let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if total_output > total_input {
            return Err(CoreError::TransactionError("Insufficient input value".to_string()));
        }

        Ok(total_input - total_output)
    }

    /// Apply transaction atomically, return changeset for potential revert
    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<UtxoChangeSet, CoreError> {
        // Validate first - no mutations yet
        self.validate_tx(tx)?;

        let mut changeset = UtxoChangeSet {
            spent: Vec::new(),
            created: Vec::new(),
        };

        // Remove spent inputs
        for input in &tx.inputs {
            let key = (input.prev_tx.clone(), input.index);
            if self.utxos.remove(&key).is_some() {
                changeset.spent.push(key);
            } else {
                return Err(CoreError::TransactionError(
                    "Input UTXO disappeared during apply".to_string(),
                ));
            }
        }

        // Add new outputs
        for (index, output) in tx.outputs.iter().enumerate() {
            let key = (tx.id.clone(), index as u32);
            self.utxos.insert(key.clone(), output.clone());
            changeset.created.push((key, output.clone()));
        }

        Ok(changeset)
    }

    /// Revert transaction using changeset (restore spent, remove created)
    pub fn revert_tx(&mut self, changes: &UtxoChangeSet, spent_outputs: &HashMap<OutPoint, TxOutput>) -> Result<(), CoreError> {
        // Remove created outputs
        for (key, _) in &changes.created {
            if self.utxos.remove(key).is_none() {
                return Err(CoreError::TransactionError(
                    "Created output not found during revert".to_string(),
                ));
            }
        }

        // Restore spent outputs
        for key in &changes.spent {
            if let Some(output) = spent_outputs.get(key) {
                self.utxos.insert(key.clone(), output.clone());
            } else {
                return Err(CoreError::TransactionError(
                    "Spent output not found in revert map".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn get_balance(&self, pubkey_hash: &Hash) -> u64 {
        self.utxos
            .values()
            .filter(|output| &output.pubkey_hash == pubkey_hash)
            .map(|output| output.value)
            .sum()
    }
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::schnorr::KeyPairWrapper;
    use crate::core::state::transaction::{TxInput, SigHashType};

    fn sign_transaction(tx: &mut Transaction, keypair: &KeyPairWrapper) {
        let msg = schnorr::tx_message(tx);
        let signature = keypair.sign(&msg);
        let pubkey_bytes = keypair.public_key().to_bytes();
        let sig_bytes = signature.to_bytes();

        for input in tx.inputs.iter_mut() {
            input.signature = sig_bytes.to_vec();
            input.pubkey = pubkey_bytes.to_vec();
        }
    }

    #[test]
    fn test_apply_revert_success() {
        let mut utxo = UtxoSet::new();
        let pubkey_hash = Hash::new(b"pubkey1");

        // Create initial UTXO
        utxo.utxos.insert(
            (Hash::new(b"tx0"), 0),
            TxOutput {
                value: 100,
                pubkey_hash: pubkey_hash.clone(),
            },
        );

        // Create transaction that spends from tx0:0
        let keypair = KeyPairWrapper::new();
        let mut tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"tx1"),
            inputs: vec![TxInput {
                prev_tx: Hash::new(b"tx0"),
                index: 0,
                signature: vec![],
                pubkey: vec![],
                sighash_type: SigHashType::All,
            }],
            outputs: vec![TxOutput {
                value: 50,
                pubkey_hash: pubkey_hash.clone(),
            }],
            chain_id: 1,
            locktime: 0,
        };

        sign_transaction(&mut tx, &keypair);

        // Apply transaction
        let changeset = utxo.apply_tx(&tx).expect("apply_tx failed");

        // Verify UTXO set changed
        assert!(utxo.utxos.get(&(Hash::new(b"tx0"), 0)).is_none());
        assert_eq!(
            utxo.utxos.get(&(tx.id.clone(), 0)).unwrap().value,
            50
        );

        // Revert transaction
        let spent_outputs = [(
            (Hash::new(b"tx0"), 0),
            TxOutput {
                value: 100,
                pubkey_hash: pubkey_hash.clone(),
            },
        )]
        .iter()
        .cloned()
        .collect();

        utxo.revert_tx(&changeset, &spent_outputs).expect("revert_tx failed");

        // Verify UTXO set restored
        assert_eq!(
            utxo.utxos.get(&(Hash::new(b"tx0"), 0)).unwrap().value,
            100
        );
        assert!(utxo.utxos.get(&(tx.id.clone(), 0)).is_none());
    }

    #[test]
    fn test_apply_revert_fail() {
        let mut utxo = UtxoSet::new();
        let pubkey_hash = Hash::new(b"pubkey1");

        // Create transaction with non-existent input
        let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"tx1"),
            inputs: vec![TxInput {
                prev_tx: Hash::new(b"nonexistent"),
                index: 0,
                signature: vec![],
                pubkey: vec![],
                sighash_type: SigHashType::All,
            }],
            outputs: vec![TxOutput {
                value: 50,
                pubkey_hash: pubkey_hash.clone(),
            }],
            chain_id: 1,
            locktime: 0,
        };

        // Apply should fail
        let result = utxo.apply_tx(&tx);
        assert!(result.is_err());

        // UTXO set should remain empty
        assert!(utxo.utxos.is_empty());
    }

    #[test]
    fn test_coinbase_valid() {
        let pubkey_hash = Hash::new(b"pubkey1");
        let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"coinbase_tx"),
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 50,
                pubkey_hash: pubkey_hash.clone(),
            }],
            chain_id: 1,
            locktime: 0,
        };

        // Verify coinbase
        assert!(tx.is_coinbase());

        // Should validate against reward of 50
        let sum: u128 = tx.outputs.iter().map(|o| o.value as u128).sum();
        assert_eq!(sum, 50);
    }

    #[test]
    fn test_coinbase_invalid_reward() {
        let pubkey_hash = Hash::new(b"pubkey1");
        let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"coinbase_tx"),
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 100,
                pubkey_hash: pubkey_hash.clone(),
            }],
            chain_id: 1,
            locktime: 0,
        };

        // Should fail because output (100) > reward (50)
        let sum: u128 = tx.outputs.iter().map(|o| o.value as u128).sum();
        assert_eq!(sum, 100);
    }

    #[test]
    fn test_validate_tx_reject_zero_address_output() {
        let utxo = UtxoSet::new();
        let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"tx1"),
            inputs: vec![],
            outputs: vec![TxOutput { value: 100, pubkey_hash: Hash::new(&[0u8; 32]) }],
            chain_id: 1,
            locktime: 0,
        };

        let result = utxo.validate_tx(&tx);
        assert!(result.is_err());
    }
}
