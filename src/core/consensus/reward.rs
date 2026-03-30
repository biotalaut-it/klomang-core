/// Fee + subsidy reward system for Klomang Core.
///
/// This module implements deterministic, in-memory reward calculations
/// based on UTXO transaction inputs and a halving schedule every 100,000 blocks.
use crate::core::config::Config;
use crate::core::consensus::emission;
use crate::core::dag::BlockNode;
use crate::core::errors::CoreError;
use crate::core::state::transaction::Transaction;
use crate::core::state::utxo::UtxoSet;

/// Full Node Provider validation interface
/// This trait allows Repo Node to inject a validator that checks if an address
/// is a valid full node provider eligible for the 20% reward pool
pub trait FullNodeValidator: Send + Sync {
    /// Verify if the given address is a valid full node provider
    /// Returns true if address is a registered, data-available full node
    fn is_valid_full_node(&self, address: &[u8; 32]) -> bool;
    
    /// Get the list of all valid full nodes (for auditing/admin purposes)
    fn get_valid_nodes(&self) -> Vec<[u8; 32]>;
    
    /// Verify Verkle proof of data availability (future extensibility)
    fn verify_data_availability(&self, address: &[u8; 32], _proof: Option<&[u8]>) -> bool {
        // Default: rely on registration only
        self.is_valid_full_node(address)
    }
}

/// Default implementation: empty validator (conservative, no nodes eligible)
pub struct DefaultNodeValidator;

impl FullNodeValidator for DefaultNodeValidator {
    fn is_valid_full_node(&self, _address: &[u8; 32]) -> bool {
        false
    }
    
    fn get_valid_nodes(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }
}

/// Calculate fee for a transaction using the current UTXO set.
///
/// Fee = sum(inputs) - sum(outputs)
/// Returns an error if the transaction is invalid or spends more than its inputs.
pub fn calculate_fees(tx: &Transaction, utxo: &UtxoSet) -> Result<u64, CoreError> {
    utxo.validate_tx(tx)
}

/// Calculate total fees for all non-coinbase transactions in a block.
///
/// This uses a cloned UTXO state and applies each transaction sequentially so
/// fees are computed deterministically for blocks with dependent transactions.
fn calculate_tx_total_fee(tx: &Transaction, utxo: &UtxoSet) -> Result<u128, CoreError> {
    let base_fee = calculate_fees(tx, utxo)? as u128;
    let gas_used = tx.gas_limit; // best effort if no persistent executed gas data
    let total_gas_fee = (gas_used as u128).saturating_mul(tx.max_fee_per_gas);

    Ok(base_fee.saturating_add(total_gas_fee))
}

pub fn calculate_accepted_fees(block: &BlockNode, utxo: &UtxoSet) -> Result<u64, CoreError> {
    let mut total_fees: u128 = 0;
    let mut working_utxo = utxo.clone();

    for tx in &block.transactions {
        if tx.is_coinbase() {
            continue;
        }

        let fee = calculate_tx_total_fee(tx, &working_utxo)?;
        working_utxo.apply_tx(tx)?;

        total_fees = total_fees.saturating_add(fee);
        if total_fees > u64::MAX as u128 {
            return Err(CoreError::TransactionError(
                "Fee overflow in accepted fee calculation".to_string(),
            ));
        }
    }

    Ok(total_fees as u64)
}

const MINER_SHARE_PERCENT: u128 = 80;
const FULLNODE_SHARE_PERCENT: u128 = 20;

/// Calculate the halving block reward in whole coins.
///
/// Uses the default config block reward as the initial reward and halves it every
/// 100,000 blocks using integer division.
pub fn calculate_block_reward(height: u64) -> u64 {
    let initial_reward = Config::default().block_reward;
    let halvings = height / emission::HALVING_INTERVAL;

    if halvings >= 64 {
        return 0;
    }

    initial_reward >> halvings
}

/// Calculate total block reward (subsidy + transaction fees) in smallest units.
///
/// Requires the block height for halving and the active UTXO state for fee calculation.
pub fn block_total_reward(
    block: &BlockNode,
    height: u64,
    is_blue: bool,
    utxo: &UtxoSet,
) -> Result<u64, CoreError> {
    if !is_blue {
        return Ok(0);
    }

    let subsidy_units = emission::capped_reward(height);
    let fees = calculate_accepted_fees(block, utxo)?;
    let total = subsidy_units
        .checked_add(fees as u128)
        .ok_or_else(|| {
            CoreError::TransactionError("Reward overflow: subsidy + fees exceed max limit".to_string())
        })?;

    total
        .try_into()
        .map_err(|_| CoreError::TransactionError("Total reward overflow u64".to_string()))
}

pub fn create_coinbase_tx(
    miner_reward_address: &crate::core::crypto::Hash,
    node_reward_pool_address: Option<&crate::core::crypto::Hash>,
    active_node_count: u32,
    total_reward: u128,
) -> crate::core::state::transaction::Transaction {
    if miner_reward_address.as_bytes() == &[0u8; 32] {
        panic!("Miner address may not be zero address");
    }

    let miner_reward: u128 = if active_node_count == 0 {
        total_reward
    } else {
        (total_reward * MINER_SHARE_PERCENT) / 100
    };

    let node_reward_pool: u128 = if active_node_count == 0 {
        0
    } else {
        (total_reward * FULLNODE_SHARE_PERCENT) / 100
    };

    let mut outputs = Vec::new();

    outputs.push(crate::core::state::transaction::TxOutput {
        value: miner_reward as u64,
        pubkey_hash: miner_reward_address.clone(),
    });

    if active_node_count > 0 {
        if let Some(pool_addr) = node_reward_pool_address {
            outputs.push(crate::core::state::transaction::TxOutput {
                value: node_reward_pool as u64,
                pubkey_hash: pool_addr.clone(),
            });
        } else {
            outputs.push(crate::core::state::transaction::TxOutput {
                value: node_reward_pool as u64,
                pubkey_hash: miner_reward_address.clone(),
            });
        }
    }

    let mut tx = crate::core::state::transaction::Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        id: crate::core::crypto::Hash::new(b""),
        inputs: Vec::new(),
        outputs,
        chain_id: 1,
        locktime: 0,
    };
    tx.id = tx.calculate_id();
    tx
}

/// Validate that coinbase outputs correctly split the reward:
/// - 80% to miner (Coinbase Address)
/// - 20% to node reward pool (Full Node Provider Address)
/// 
/// Returns error if:
/// - Total value doesn't match expected reward
/// - Split ratio is incorrect (not 80/20)
/// - Missing miner or node output
/// - Node reward address is not a valid full node (if validator provided)
pub fn validate_coinbase_reward(
    block: &BlockNode,
    actual_reward: u128,
) -> Result<(), CoreError> {
    validate_coinbase_reward_internal(block, actual_reward, None)
}

/// Internal validation with optional full node validator
/// Supports both strict mode (with validator) and permissive mode (without)
fn validate_coinbase_reward_internal(
    block: &BlockNode,
    actual_reward: u128,
    validator: Option<&dyn FullNodeValidator>,
) -> Result<(), CoreError> {
    let coinbase_tx = block
        .transactions
        .iter()
        .find(|tx| tx.is_coinbase());

    match coinbase_tx {
        Some(tx) if !tx.outputs.is_empty() => {
            let total_value: u128 = tx.outputs.iter().map(|o| o.value as u128).sum();

            if total_value != actual_reward {
                return Err(CoreError::TransactionError(format!(
                    "Invalid coinbase reward: expected {} total, got {}",
                    actual_reward, total_value
                )));
            }

            // Require exactly 2 outputs for protocol-locked 80/20 split
            if tx.outputs.len() != 2 {
                return Err(CoreError::TransactionError(
                    "Coinbase must have exactly 2 outputs for 80/20 miner+node split".to_string(),
                ));
            }

            // Verify 80/20 split is exact
            let first_value = tx.outputs[0].value as u128;
            let second_value = tx.outputs[1].value as u128;
            
            let expected_miner = (actual_reward * MINER_SHARE_PERCENT) / 100;
            let expected_node = actual_reward.saturating_sub(expected_miner);
            
            // Allow both (miner, node) and (node, miner) orderings
            let split_valid = (first_value == expected_miner && second_value == expected_node) ||
                             (first_value == expected_node && second_value == expected_miner);
            
            if !split_valid {
                return Err(CoreError::TransactionError(format!(
                    "Invalid 80/20 split: expected [miner: {}, node: {}], got [{}, {}]",
                    expected_miner, expected_node, first_value, second_value
                )));
            }

            // If validator provided, verify node pool recipient is valid full node
            if let Some(validator) = validator {
                let node_address = if first_value == expected_node {
                    tx.outputs[0].pubkey_hash.as_bytes()
                } else {
                    tx.outputs[1].pubkey_hash.as_bytes()
                };
                
                if !validator.is_valid_full_node(node_address) {
                    return Err(CoreError::TransactionError(format!(
                        "Node reward address {:?} is not a valid full node provider",
                        hex::encode(node_address)
                    )));
                }
            }

            Ok(())
        }
        Some(_) => Err(CoreError::TransactionError(
            "Coinbase transaction has no outputs".to_string(),
        )),
        None => Err(CoreError::TransactionError(
            "Block must contain a coinbase transaction".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::Hash;
    use crate::core::crypto::schnorr::KeyPairWrapper;
    use crate::core::state::transaction::{SigHashType, Transaction, TxInput, TxOutput};
    use crate::core::state::utxo::UtxoSet;

    fn sign_transaction(tx: &mut Transaction, keypair: &KeyPairWrapper) {
        let msg = crate::core::crypto::schnorr::tx_message(tx);
        let signature = keypair.sign(&msg);
        let pubkey_bytes = keypair.public_key().to_bytes();
        let sig_bytes = signature.to_bytes();

        for input in tx.inputs.iter_mut() {
            input.signature = sig_bytes.to_vec();
            input.pubkey = pubkey_bytes.to_vec();
        }
    }

    #[test]
    fn test_calculate_fees_valid_transaction() {
        let mut utxo = UtxoSet::new();
        let prev_tx = Hash::new(b"prev_tx");
        let sender_hash = Hash::new(b"sender");

        utxo.utxos.insert(
            (prev_tx.clone(), 0),
            TxOutput {
                value: 200,
                pubkey_hash: sender_hash.clone(),
            },
        );

        let keypair = KeyPairWrapper::new();
        let mut tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"tx1"),
            inputs: vec![TxInput {
                prev_tx: prev_tx.clone(),
                index: 0,
                signature: vec![],
                pubkey: vec![],
                sighash_type: SigHashType::All,
            }],
            outputs: vec![TxOutput {
                value: 150,
                pubkey_hash: Hash::new(b"recipient"),
            }],
            chain_id: 1,
            locktime: 0,
        };

        sign_transaction(&mut tx, &keypair);
        tx.id = tx.calculate_id();

        assert_eq!(calculate_fees(&tx, &utxo).unwrap(), 50);
    }

    #[test]
    fn test_calculate_fees_invalid_transaction() {
        let mut utxo = UtxoSet::new();
        let prev_tx = Hash::new(b"prev_tx");

        utxo.utxos.insert(
            (prev_tx.clone(), 0),
            TxOutput {
                value: 100,
                pubkey_hash: Hash::new(b"sender"),
            },
        );

        let keypair = KeyPairWrapper::new();
        let mut tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"tx2"),
            inputs: vec![TxInput {
                prev_tx: prev_tx.clone(),
                index: 0,
                signature: vec![],
                pubkey: vec![],
                sighash_type: SigHashType::All,
            }],
            outputs: vec![TxOutput {
                value: 150,
                pubkey_hash: Hash::new(b"recipient"),
            }],
            chain_id: 1,
            locktime: 0,
        };

        sign_transaction(&mut tx, &keypair);
        tx.id = tx.calculate_id();

        assert!(calculate_fees(&tx, &utxo).is_err());
    }

    #[test]
    fn test_calculate_accepted_fees_sequential_block() {
        let mut utxo = UtxoSet::new();
        let prev_tx = Hash::new(b"prev_tx");

        utxo.utxos.insert(
            (prev_tx.clone(), 0),
            TxOutput {
                value: 200,
                pubkey_hash: Hash::new(b"sender"),
            },
        );

        let keypair = KeyPairWrapper::new();
        let mut tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"tx3"),
            inputs: vec![TxInput {
                prev_tx: prev_tx.clone(),
                index: 0,
                signature: vec![],
                pubkey: vec![],
                sighash_type: SigHashType::All,
            }],
            outputs: vec![TxOutput {
                value: 120,
                pubkey_hash: Hash::new(b"recipient"),
            }],
            chain_id: 1,
            locktime: 0,
        };

        sign_transaction(&mut tx, &keypair);
        tx.id = tx.calculate_id();

        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 100,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![tx],
        };

        let total_fees = calculate_accepted_fees(&block, &utxo).unwrap();
        assert_eq!(total_fees, 80);
    }

    #[test]
    fn test_calculate_block_reward_halving() {
        assert_eq!(calculate_block_reward(0), 100);
        assert_eq!(calculate_block_reward(100_000), 50);
        assert_eq!(calculate_block_reward(200_000), 25);
    }

    #[test]
    fn test_red_block_reward_is_zero() {
        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 100,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![],
        };

        let utxo = UtxoSet::new();
        let reward = block_total_reward(&block, 0, false, &utxo);

        assert_eq!(reward.ok(), Some(0));
    }

    #[test]
    fn test_blue_block_includes_subsidy() {
        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 0,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![],
        };

        let utxo = UtxoSet::new();
        let reward = block_total_reward(&block, 0, true, &utxo);

        assert_eq!(reward.ok(), Some((100u128 * emission::UNIT).try_into().unwrap()));
    }

    #[test]
    fn test_coinbase_validation_success() {
        let total_reward = 100u128;
        let miner_value = (total_reward * 80) / 100;
        let node_value = total_reward - miner_value;

        let coinbase_tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"coinbase"),
            inputs: vec![],
            outputs: vec![
                TxOutput {
                    value: miner_value as u64,
                    pubkey_hash: Hash::new(b"miner"),
                },
                TxOutput {
                    value: node_value as u64,
                    pubkey_hash: Hash::new(b"node_pool"),
                },
            ],
            chain_id: 1,
            locktime: 0,
        };

        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 0,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![coinbase_tx],
        };

        assert!(validate_coinbase_reward(&block, total_reward).is_ok());
    }

    /// New test: Validate exact 80/20 split is enforced
    #[test]
    fn test_coinbase_validation_strict_80_20_split() {
        let total_reward = 1000u128;
        let expected_miner = (total_reward * 80) / 100;
        let expected_node = total_reward - expected_miner;

        // Test: correct split
        let coinbase_tx = Transaction {
            execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"coinbase"),
            inputs: vec![],
            outputs: vec![
                TxOutput {
                    value: expected_miner as u64,
                    pubkey_hash: Hash::new(b"miner"),
                },
                TxOutput {
                    value: expected_node as u64,
                    pubkey_hash: Hash::new(b"node"),
                },
            ],
            chain_id: 1,
            locktime: 0,
        };

        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 0,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![coinbase_tx.clone()],
        };

        assert!(validate_coinbase_reward(&block, total_reward).is_ok());
    }

    /// New test: Reject incorrect split ratios
    #[test]
    fn test_coinbase_validation_rejects_wrong_split() {
        let total_reward = 1000u128;

        // Wrong split: 90/10 instead of 80/20
        let coinbase_tx = Transaction {
            execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"coinbase"),
            inputs: vec![],
            outputs: vec![
                TxOutput {
                    value: 900,
                    pubkey_hash: Hash::new(b"miner"),
                },
                TxOutput {
                    value: 100,
                    pubkey_hash: Hash::new(b"node"),
                },
            ],
            chain_id: 1,
            locktime: 0,
        };

        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 0,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![coinbase_tx],
        };

        let result = validate_coinbase_reward(&block, total_reward);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid 80/20 split"));
    }

    /// New test: Reject when outputs != 2 (protocol lock)
    #[test]
    fn test_coinbase_validation_rejects_single_output() {
        let total_reward = 1000u128;

        // Single output instead of 80/20 split
        let coinbase_tx = Transaction {
            execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"coinbase"),
            inputs: vec![],
            outputs: vec![
                TxOutput {
                    value: total_reward as u64,
                    pubkey_hash: Hash::new(b"miner"),
                },
            ],
            chain_id: 1,
            locktime: 0,
        };

        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 0,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![coinbase_tx],
        };

        let result = validate_coinbase_reward(&block, total_reward);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exactly 2 outputs"));
    }

    /// New test: Full node validator integration
    #[test]
    fn test_full_node_validator_rejects_invalid_node() {
        let total_reward = 1000u128;
        let expected_miner = (total_reward * 80) / 100;
        let expected_node = total_reward - expected_miner;
        
        let invalid_node_address = Hash::new(b"not_a_node");

        let coinbase_tx = Transaction {
            execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"coinbase"),
            inputs: vec![],
            outputs: vec![
                TxOutput {
                    value: expected_miner as u64,
                    pubkey_hash: Hash::new(b"miner"),
                },
                TxOutput {
                    value: expected_node as u64,
                    pubkey_hash: invalid_node_address.clone(),
                },
            ],
            chain_id: 1,
            locktime: 0,
        };

        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 0,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![coinbase_tx],
        };

        // Without validator: should pass (backward compatible)
        assert!(validate_coinbase_reward(&block, total_reward).is_ok());

        // With strict validator: should fail
        let strict_validator = DefaultNodeValidator;
        let result = validate_coinbase_reward_internal(&block, total_reward, Some(&strict_validator));
        assert!(result.is_err());
    }

    #[test]
    fn test_create_coinbase_tx_with_active_node_count() {
        let total_reward = emission::BASE_REWARD;
        let miner_address = Hash::new(b"miner");
        let node_pool_address = Hash::new(b"pool");
        let active_node_count = 90;

        let tx = create_coinbase_tx(&miner_address, Some(&node_pool_address), active_node_count, total_reward);

        let expected_miner = ((total_reward * 80) / 100) as u64;
        let expected_pool = (total_reward - (total_reward * 80 / 100)) as u64;

        assert_eq!(tx.outputs[0].value, expected_miner);
        assert_eq!(tx.outputs.iter().map(|o| o.value as u128).sum::<u128>(), total_reward);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[1].value, expected_pool);
    }

    #[test]
    fn test_coinbase_validation_wrong_amount() {
        let coinbase_output = TxOutput {
            value: 50,
            pubkey_hash: Hash::new(b"miner"),
        };

        let coinbase_tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
            id: Hash::new(b"coinbase"),
            inputs: vec![],
            outputs: vec![coinbase_output],
            chain_id: 1,
            locktime: 0,
        };

        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 0,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![coinbase_tx],
        };

        let result = validate_coinbase_reward(&block, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_overflow_in_reward_calculation() {
        let block = BlockNode {
            id: Hash::new(b"test"),
            parents: Default::default(),
            children: Default::default(),
            selected_parent: None,
            blue_set: Default::default(),
            red_set: Default::default(),
            blue_score: 50,
            timestamp: 1000,
            difficulty: 1000,
            nonce: 0,
            transactions: vec![],
        };

        let utxo = UtxoSet::new();
        let reward = block_total_reward(&block, 50, true, &utxo);

        assert!(reward.is_ok());
    }
}


