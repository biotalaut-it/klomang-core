//! State Management Edge Cases and Error Scenarios
//! Tests error handling, boundary conditions, and stress scenarios

use klomang_core::core::crypto::Hash;
use klomang_core::core::dag::BlockNode;
use klomang_core::core::state::transaction::{Transaction, TxOutput, TxInput, SigHashType};
use klomang_core::core::state::utxo::UtxoSet;
use klomang_core::core::state::MemoryStorage;
use klomang_core::core::state_manager::{StateManager, StateManagerError};
use klomang_core::core::state::v_trie::VerkleTree;
use wasmer::wat2wasm;
use std::collections::HashSet;

fn make_tx(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Transaction {
    let mut tx = Transaction::new(inputs, outputs);
    tx.id = Hash::new(b"test_tx");
    tx.chain_id = 1;
    tx.locktime = 0;
    tx
}

fn make_block(id: &[u8], txs: Vec<Transaction>) -> BlockNode {
    BlockNode {
        id: Hash::new(id),
        parents: {
            let mut parents = HashSet::new();
            parents.insert(Hash::new(b"genesis"));
            parents
        },
        children: HashSet::new(),
        selected_parent: None,
        blue_set: HashSet::new(),
        red_set: HashSet::new(),
        blue_score: 0,
        timestamp: 0,
        difficulty: 0,
        nonce: 0,
        transactions: txs,
    }
}

/// Test 1: Empty block handling
#[test]
fn test_empty_block_handling() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    let empty_block = make_block(b"empty_block", vec![]);
    
    let result = manager.apply_block(&empty_block, &mut utxo_set);
    assert!(result.is_ok());
    
    // Height should still increment
    assert_eq!(manager.current_height, 1);
}

/// Test 2: Block with no outputs transaction
#[test]
fn test_block_no_outputs() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        id: Hash::new(b"no_output_tx"),
        inputs: vec![],
        outputs: vec![],
        chain_id: 1,
        locktime: 0,
    };
    
    let block = make_block(b"block_no_outputs", vec![tx]);
    
    let result = manager.apply_block(&block, &mut utxo_set);
    assert!(result.is_ok());
}

/// Test 3: Rollback to same height (idempotent)
#[test]
fn test_rollback_same_height() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    let block = make_block(b"block1", vec![]);
    manager.apply_block(&block, &mut utxo_set)
        .expect("Failed to apply block");
    
    // Rollback to same height should succeed
    let result = manager.rollback_state(1);
    assert!(result.is_ok());
    
    assert_eq!(manager.current_height, 1);
}

/// Test 4: Sequential rollbacks
#[test]
fn test_sequential_rollbacks() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage)
        .expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    // Build chain of 3 blocks
    for i in 1..=3 {
        let block = make_block(
            format!("block{}", i).as_bytes(),
            vec![],
        );
        manager.apply_block(&block, &mut utxo_set)
            .expect("Failed to apply block");
    }
    
    assert_eq!(manager.current_height, 3);
    
    // Rollback to height 2
    manager.rollback_state(2)
        .expect("Failed to rollback to 2");
    assert_eq!(manager.current_height, 2);
    
    // Rollback to height 1
    manager.rollback_state(1)
        .expect("Failed to rollback to 1");
    assert_eq!(manager.current_height, 1);
    
    // Rollback to height 0
    manager.rollback_state(0)
        .expect("Failed to rollback to 0");
    assert_eq!(manager.current_height, 0);
}

/// Test 5: Invalid rollback forward
#[test]
fn test_invalid_rollback_forward() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage)
        .expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    // Try to rollback to height 100 when current is 0
    let result = manager.rollback_state(100);
    
    assert!(result.is_err());
    match result {
        Err(StateManagerError::InvalidRollback(_)) => {},
        _ => panic!("Expected InvalidRollback error"),
    }
}

/// Test 6: Restore from snapshot with matching root
#[test]
fn test_restore_from_snapshot_success() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage)
        .expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    // Apply block to create snapshot
    let block = make_block(b"block1", vec![]);
    manager.apply_block(&block, &mut utxo_set)
        .expect("Failed to apply block");
    
    let snapshot_root = manager.get_state_at(1)
        .expect("Failed to get snapshot")
        .root;
    
    // Apply another block
    let block2 = make_block(b"block2", vec![]);
    manager.apply_block(&block2, &mut utxo_set)
        .expect("Failed to apply block2");
    
    // Restore to height 1
    let result = manager.restore_from_snapshot(snapshot_root, 1);
    assert!(result.is_ok());
    
    assert_eq!(manager.current_height, 1);
}

/// Test 7: Restore from non-existent snapshot
#[test]
fn test_restore_from_nonexistent_snapshot() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage)
        .expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    // Try to restore non-existent snapshot
    let result = manager.restore_from_snapshot([0xFF; 32], 999);
    
    assert!(result.is_err());
    match result {
        Err(StateManagerError::SnapshotNotFound(_)) => {},
        _ => panic!("Expected SnapshotNotFound error"),
    }
}

/// Test 8: Contract out-of-gas with rollback to previous state
#[test]
fn test_contract_out_of_gas() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree).expect("Failed to create StateManager");

    let wasm = wat2wasm(r#"
        (module
            (import "env" "klomang_state_write" (func $state_write (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "abcdefghijklmnopqrstuvwx0123456789")
            (data (i32.const 64) "hello")
            (func (export "run")
                i32.const 0
                i32.const 32
                i32.const 64
                i32.const 5
                call $state_write
                drop
            )
        )
    "#.as_bytes()).expect("Failed to compile WAT to WASM").to_vec();

    let mut tx = Transaction::new(vec![], vec![]);
    tx.execution_payload = wasm;
    tx.contract_address = Some([0u8; 32]);
    tx.gas_limit = 40_000;
    tx.max_fee_per_gas = 1;
    tx.id = Hash::new(b"oogs_tx");

    let root_before = manager.tree.get_root().expect("Failed to get root");

    let block = make_block(b"oogs_block", vec![tx]);
    let result = manager.apply_block(&block, &mut utxo_set);

    assert!(result.is_err());
    assert_eq!(manager.current_height, 0);

    let root_after = manager.tree.get_root().expect("Failed to get root after out-of-gas");
    assert_eq!(root_before, root_after);
}

/// Test 9: Large value in transaction
#[test]
fn test_transaction_large_value() {
    let mut utxo_set = UtxoSet::new();
    
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        id: Hash::new(b"large_value_tx"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: u64::MAX,
            pubkey_hash: Hash::new(b"recipient"),
        }],
        chain_id: 1,
        locktime: 0,
    };
    
    // Should handle large values
    assert_eq!(tx.outputs[0].value, u64::MAX);
}

/// Test 9: Multiple outputs per transaction
#[test]
fn test_multiple_outputs_per_tx() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        id: Hash::new(b"multi_output_tx"),
        inputs: vec![],
        outputs: (0..100).map(|i| TxOutput {
            value: 100 + i,
            pubkey_hash: Hash::new(format!("recipient_{}", i).as_bytes()),
        }).collect(),
        chain_id: 1,
        locktime: 0,
    };
    
    assert_eq!(tx.outputs.len(), 100);
}

/// Test 10: State manager get_current_state
#[test]
fn test_get_current_state() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage)
        .expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    let state = manager.get_current_state()
        .expect("Failed to get current state");
    
    assert_eq!(state.height, 0);
    assert_eq!(state.root.len(), 32);
}

/// Test 11: Snapshot validation on valid chain
#[test]
fn test_validate_snapshots_valid() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage)
        .expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    for i in 1..=5 {
        let block = make_block(
            format!("block{}", i).as_bytes(),
            vec![],
        );
        manager.apply_block(&block, &mut utxo_set)
            .expect("Failed to apply block");
    }
    
    let result = manager.validate_snapshots();
    assert!(result.is_ok());
}

/// Test 12: Transaction with zero value output
#[test]
fn test_zero_value_output() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        id: Hash::new(b"zero_value_tx"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 0,
            pubkey_hash: Hash::new(b"recipient"),
        }],
        chain_id: 1,
        locktime: 0,
    };
    
    assert_eq!(tx.outputs[0].value, 0);
}

/// Test 13: Chain ID variations
#[test]
fn test_transaction_chain_id() {
    let tx1 = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        id: Hash::new(b"tx1"),
        inputs: vec![],
        outputs: vec![],
        chain_id: 1,
        locktime: 0,
    };
    
    let tx2 = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        id: Hash::new(b"tx2"),
        inputs: vec![],
        outputs: vec![],
        chain_id: 2,
        locktime: 0,
    };
    
    assert_ne!(tx1.chain_id, tx2.chain_id);
}

/// Test 14: Block with many transactions
#[test]
fn test_block_many_transactions() {
    let mut utxo_set = UtxoSet::new();
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage)
        .expect("Failed to create VerkleTree");
    let mut manager = StateManager::new(tree)
        .expect("Failed to create StateManager");
    
    let txs: Vec<Transaction> = (0..50).map(|i| Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        id: Hash::new(format!("tx{}", i).as_bytes()),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 100 + i,
            pubkey_hash: Hash::new(format!("recipient_{}", i).as_bytes()),
        }],
        chain_id: 1,
        locktime: 0,
    }).collect();
    
    let block = BlockNode {
        id: Hash::new(b"block_many_txs"),
        parents: {
            let mut parents = HashSet::new();
            parents.insert(Hash::new(b"genesis"));
            parents
        },
        children: HashSet::new(),
        selected_parent: None,
        blue_set: HashSet::new(),
        red_set: HashSet::new(),
        blue_score: 0,
        timestamp: 0,
        difficulty: 0,
        nonce: 0,
        transactions: txs,
    };
    
    let result = manager.apply_block(&block, &mut utxo_set);
    assert!(result.is_ok());
}

/// Test 15: UTXO set operations stress test
#[test]
fn test_utxo_set_stress() {
    let mut utxo_set = UtxoSet::new();
    
    // Add 1000 UTXOs
    for i in 0..1000 {
        let tx_hash = Hash::new(format!("tx{}", i).as_bytes());
        utxo_set.utxos.insert(
            (tx_hash, 0),
            TxOutput {
                value: 100 + i,
                pubkey_hash: Hash::new(b"recipient"),
            },
        );
    }
    
    assert_eq!(utxo_set.utxos.len(), 1000);
    
    // Remove all UTXOs
    for i in 0..1000 {
        let tx_hash = Hash::new(format!("tx{}", i).as_bytes());
        utxo_set.utxos.remove(&(tx_hash, 0));
    }
    
    assert_eq!(utxo_set.utxos.len(), 0);
}
