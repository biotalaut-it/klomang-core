/// Fee + Subsidy Reward System (Bitcoin-style, DAG-aware)
///
/// Implements block reward calculation combining:
/// - Subsidy: Base emission from `emission.rs` (capped by hard supply limit)
/// - Fees: Transaction fees from accepted transactions (prevents double-claim)
///
/// DAG Rules:
/// - Only BLUE blocks receive reward
/// - RED blocks have 0 reward
/// - Fees calculated only from accepted transactions (virtual chain)

use crate::core::dag::BlockNode;
use crate::core::crypto::Hash;
use crate::core::errors::CoreError;
use super::emission;
use std::collections::HashSet;

/// Calculate total fees from all transactions in a block
/// 
/// Fee = sum(input_values) - sum(output_values)
/// For coinbase transactions (no inputs), fee is 0.
///
/// Note: This requires access to UTXO state to get input values.
/// In the reward system context, we sum fees from accepted transactions only.
pub fn calculate_fees(_block: &BlockNode, _accepted_txs: &HashSet<Hash>) -> Result<u64, CoreError> {
    // Initial implementation: fees will be calculated from accepted transactions
    // For now, return 0 as placeholder - will be filled with actual fee calculation
    // when UTXO state is available during validation
    Ok(0)
}

/// Calculate fees from only accepted transactions (DAG-aware)
///
/// This prevents double-counting fees:
/// - Only transactions in the virtual chain (accepted by consensus) contribute fees
/// - Orphaned or rejected transactions don't count
///
/// Parameters:
/// - block: The block containing transactions
/// - accepted_txs: Set of transaction hashes accepted in the virtual chain
///
/// Returns: Total fees from accepted transactions, or error
pub fn calculate_accepted_fees(
    block: &BlockNode,
    accepted_txs: &HashSet<Hash>,
) -> Result<u64, CoreError> {
    let mut total_fees: u64 = 0;

    for tx in &block.transactions {
        // Skip coinbase transactions (no inputs, no fees)
        if tx.is_coinbase() {
            continue;
        }

        // Only count fees from accepted transactions
        if accepted_txs.contains(&tx.id) {
            // Fee calculation requires UTXO state (sum of inputs - sum of outputs)
            // This is a placeholder - actual implementation needs state context
            //
            // In practice:
            // fee = sum(prev_outputs[input.prev_tx][input.index].value for each input)
            //       - sum(output.value for each output)

            // For now, we conservatively assume 0 fees from each transaction
            // The actual fee calculation happens in the transaction validation layer
            // where UTXO state is available
            let _tx_fee: u64 = 0;

            // Safely add to total, preventing overflow
            match total_fees.checked_add(_tx_fee) {
                Some(new_total) => total_fees = new_total,
                None => {
                    return Err(CoreError::TransactionError(
                        "Fee overflow in reward calculation".to_string(),
                    ))
                }
            }
        }
    }

    Ok(total_fees)
}

/// Calculate total block reward combining subsidy + accepted fees
///
/// Rules:
/// - BLUE blocks: reward = subsidy + accepted_fees
/// - RED blocks: reward = 0 (no reward for red blocks)
///
/// Parameters:
/// - block: The block node
/// - daa_score: Blue/DAA score for subsidy calculation
/// - is_blue: Whether this block is in the blue set
/// - accepted_txs: Set of accepted transactions for fee calculation
///
/// Returns: Total reward amount in satoshis, or error
pub fn create_coinbase_tx(
    miner_reward_address: &crate::core::crypto::Hash,
    node_reward_pool_address: Option<&crate::core::crypto::Hash>,
    active_node_count: u32,
    total_reward: u128,
) -> crate::core::state::transaction::Transaction {
    let miner_reward: u128 = if active_node_count == 0 {
        total_reward
    } else {
        (total_reward * 80) / 100
    };

    let node_reward_pool: u128 = total_reward.saturating_sub(miner_reward);

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

    let mut tx = crate::core::state::transaction::Transaction {
        id: crate::core::crypto::Hash::new(b""),
        inputs: Vec::new(),
        outputs,
        chain_id: 1,
        locktime: 0,
    };
    tx.id = tx.calculate_id();
    tx
}

pub fn block_total_reward(
    block: &BlockNode,
    daa_score: u64,
    is_blue: bool,
    accepted_txs: &HashSet<Hash>,
) -> Result<u64, CoreError> {
    // RED blocks get 0 reward
    if !is_blue {
        return Ok(0);
    }

    // Get subsidy from emission system (includes cap check)
    let subsidy = emission::capped_reward(daa_score);

    // Calculate fees from accepted transactions only (prevents double-counting)
    let fees = calculate_accepted_fees(block, accepted_txs)?;

    // Total reward = subsidy + fees
    // Use checked_add to detect overflow
    let total = subsidy
        .checked_add(fees as u128)
        .ok_or_else(|| {
            CoreError::TransactionError("Reward overflow: subsidy + fees exceed max supply".to_string())
        })?;

    total
        .try_into()
        .map_err(|_| CoreError::TransactionError("Total reward overflow u64".to_string()))
}

/// Validate coinbase transaction value against computed reward
///
/// Called after GHOSTDAG consensus (when we know if block is BLUE/RED)
/// to ensure coinbase exactly matches the allowed reward.
///
/// Parameters:
/// - block: Block containing the coinbase
/// - actual_reward: The exact amount the coinbase should contain
///
/// Returns: Ok if valid, error if coinbase doesn't match expected reward
pub fn validate_coinbase_reward(
    block: &BlockNode,
    actual_reward: u128,
) -> Result<(), CoreError> {
    // Find coinbase transaction (transaction with no inputs)
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

            // At least miner split + node split must exist
            if tx.outputs.len() < 2 {
                return Err(CoreError::TransactionError(
                    "Coinbase must have at least 2 outputs for miner+node split".to_string(),
                ));
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
    use crate::core::state::transaction::{Transaction, TxOutput};

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

        let accepted_txs = HashSet::new();
        let reward = block_total_reward(&block, 100, false, &accepted_txs);

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

        let accepted_txs = HashSet::new();
        let reward = block_total_reward(&block, 0, true, &accepted_txs);

        // Genesis block (daa_score=0) has subsidy of 100 coins in smallest unit 8 decimal
        assert_eq!(
            reward.ok(),
            Some((100u128 * crate::core::consensus::emission::UNIT).try_into().unwrap()),
        );
    }

    #[test]
    fn test_coinbase_validation_success() {
        let total_reward = 100u128;
        let miner_value = (total_reward * 80) / 100;
        let node_value = total_reward - miner_value;

        let coinbase_tx = Transaction {
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

    #[test]
    fn test_create_coinbase_tx_with_active_node_count() {
        let total_reward = crate::core::consensus::emission::BASE_REWARD;
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

        let coinbase_tx = Transaction {
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
    fn test_calculate_accepted_fees() {
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

        let accepted_txs = HashSet::new();
        let fees = calculate_accepted_fees(&block, &accepted_txs);

        assert_eq!(fees.ok(), Some(0));
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

        let accepted_txs = HashSet::new();
        let reward = block_total_reward(&block, 50, true, &accepted_txs);

        // Should be ok and not overflow
        assert!(reward.is_ok());
    }
}
