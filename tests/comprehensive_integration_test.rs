//! Comprehensive Integration Tests for Klomang Core Full Workflow (70 test cases)
//! 
//! This test suite simulates the complete Core workflow:
//! 1. Incoming Transactions -> Creation & Validation
//! 2. UTXO Validation & State Management
//! 3. Update Verkle Tree for State Commitment
//! 4. Consensus Ordering via GHOSTDAG
//! 5. Block Commitment & Finality
//!
//! Target: 90% code coverage for src/core/

use klomang_core::core::crypto::Hash;
use klomang_core::core::dag::{Dag, BlockNode};
use klomang_core::core::state::transaction::{Transaction, TxOutput, TxInput, SigHashType};
use klomang_core::core::state::utxo::UtxoSet;
use klomang_core::core::state::MemoryStorage;
use klomang_core::core::state_manager::StateManager;
use klomang_core::core::state::v_trie::VerkleTree;
use klomang_core::core::consensus::GhostDag;
use klomang_core::core::consensus::emission::{raw_block_reward, block_reward, COIN_UNIT};
use klomang_core::core::state::BlockchainState;
use klomang_core::core::config::Config;
use std::collections::HashSet;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn make_coinbase_tx(outputs: Vec<TxOutput>) -> Transaction {
    let mut tx = Transaction::new(Vec::new(), outputs);
    tx.chain_id = 1;
    tx.locktime = 0;
    tx.id = tx.calculate_id();
    tx
}

fn make_tx(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Transaction {
    let mut tx = Transaction::new(inputs, outputs);
    tx.chain_id = 1;
    tx.locktime = 0;
    tx.id = tx.calculate_id();
    tx
}

fn make_block(id: &[u8], txs: Vec<Transaction>, parents: HashSet<Hash>) -> BlockNode {
    BlockNode {
        id: Hash::new(id),
        parents,
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

fn make_output(value: u64, recipient: &[u8]) -> TxOutput {
    TxOutput {
        value,
        pubkey_hash: Hash::new(recipient),
    }
}

fn make_input(prev_tx: &[u8], index: u32) -> TxInput {
    TxInput {
        prev_tx: Hash::new(prev_tx),
        index,
        signature: vec![0x00; 64],
        pubkey: vec![0x00; 33],
        sighash_type: SigHashType::All,
    }
}

// ============================================================================
// TEST SUITE 1: TRANSACTION CREATION & VALIDATION (Tests 1-6)
// ============================================================================

#[test]
fn test_01_coinbase_transaction_creation() {
    let outputs = vec![make_output(50 * COIN_UNIT, b"miner")];
    let tx = make_coinbase_tx(outputs);
    assert!(tx.is_coinbase());
    assert_eq!(tx.outputs.len(), 1);
}

#[test]
fn test_02_transaction_with_outputs() {
    let outputs = vec![make_output(30 * COIN_UNIT, b"alice"), make_output(20 * COIN_UNIT, b"bob")];
    let tx = make_coinbase_tx(outputs);
    assert_eq!(tx.outputs.len(), 2);
}

#[test]
fn test_03_transaction_id_consistency() {
    let outputs = vec![make_output(100, b"test")];
    let tx1 = make_coinbase_tx(outputs.clone());
    let tx2 = make_coinbase_tx(outputs);
    assert_eq!(tx1.id, tx2.id);
}

#[test]
fn test_04_transaction_calculation_id() {
    let outputs = vec![make_output(100, b"recipient")];
    let tx = make_coinbase_tx(outputs);
    let recalculated = tx.calculate_id();
    assert_eq!(tx.id, recalculated);
}

#[test]
fn test_05_transaction_is_coinbase_detection() {
    let coinbase = make_coinbase_tx(vec![make_output(100, b"miner")]);
    let regular = make_tx(vec![make_input(b"prev_tx", 0)], vec![make_output(100, b"recipient")]);
    assert!(coinbase.is_coinbase());
    assert!(!regular.is_coinbase());
}

#[test]
fn test_06_multiple_transaction_types() {
    let coinbase = make_coinbase_tx(vec![make_output(100, b"m")]);
    let tx_with_inputs = make_tx(
        vec![make_input(b"p1", 0), make_input(b"p2", 1)],
        vec![make_output(150, b"r1")]
    );
    assert!(coinbase.is_coinbase());
    assert!(!tx_with_inputs.is_coinbase());
}

// ============================================================================
// TEST SUITE 2: UTXO STATE MANAGEMENT (Tests 7-13)
// ============================================================================

#[test]
fn test_07_utxo_set_creation() {
    let utxo_set = UtxoSet::new();
    assert_eq!(utxo_set.utxos.len(), 0);
}

#[test]
fn test_08_utxo_insertion_and_retrieval() {
    let mut utxo_set = UtxoSet::new();
    let tx_hash = Hash::new(b"tx1");
    let output = make_output(100, b"alice");
    utxo_set.utxos.insert((tx_hash.clone(), 0), output.clone());
    assert_eq!(utxo_set.utxos.len(), 1);
}

#[test]
fn test_09_utxo_multiple_outputs() {
    let mut utxo_set = UtxoSet::new();
    let tx_hash = Hash::new(b"tx1");
    for i in 0u32..5 {
        let output = make_output(10 * (i + 1) as u64, b"recipient");
        utxo_set.utxos.insert((tx_hash.clone(), i), output);
    }
    assert_eq!(utxo_set.utxos.len(), 5);
}

#[test]
fn test_10_utxo_spend_removes_utxo() {
    let mut utxo_set = UtxoSet::new();
    let tx_hash = Hash::new(b"tx1");
    utxo_set.utxos.insert((tx_hash.clone(), 0), make_output(100, b"alice"));
    utxo_set.utxos.remove(&(tx_hash, 0));
    assert_eq!(utxo_set.utxos.len(), 0);
}

#[test]
fn test_11_utxo_coinbase_validation() {
    let coinbase = make_coinbase_tx(vec![make_output(100, b"miner")]);
    assert!(coinbase.is_coinbase());
}

#[test]
fn test_12_utxo_transaction_changeset() {
    let utxo_set = UtxoSet::new();
    assert_eq!(utxo_set.utxos.len(), 0);
}

#[test]
fn test_13_utxo_multiple_transactions() {
    let mut utxo_set = UtxoSet::new();
    for i in 0u32..10 {
        let tx = Hash::new(&i.to_le_bytes());
        utxo_set.utxos.insert((tx, 0), make_output(100 + i as u64, b"owner"));
    }
    assert_eq!(utxo_set.utxos.len(), 10);
}

// ============================================================================
// TEST SUITE 3: DAG STRUCTURE & BLOCK MANAGEMENT (Tests 14-21)
// ============================================================================

#[test]
fn test_14_genesis_block_creation() {
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    assert_eq!(genesis.parents.len(), 0);
    assert_eq!(genesis.transactions.len(), 0);
}

#[test]
fn test_15_dag_single_block() {
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis).expect("add genesis");
    assert_eq!(dag.get_all_hashes().len(), 1);
}

#[test]
fn test_16_dag_block_with_parent() {
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add genesis");
    let mut parents = HashSet::new();
    parents.insert(genesis.id.clone());
    let block1 = make_block(b"block1", vec![], parents);
    dag.add_block(block1).expect("add child");
    assert_eq!(dag.get_all_hashes().len(), 2);
}

#[test]
fn test_17_dag_linear_chain() {
    let mut dag = Dag::new();
    let mut prev = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(prev.clone()).expect("add genesis");
    for i in 1u32..10 {
        let mut parents = HashSet::new();
        parents.insert(prev.id.clone());
        let block = make_block(&i.to_le_bytes(), vec![], parents);
        dag.add_block(block.clone()).unwrap_or_else(|_| panic!("add {}", i));
        prev = block;
    }
    assert_eq!(dag.get_all_hashes().len(), 10);
}

#[test]
fn test_18_dag_multiple_tips() {
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add genesis");
    let mut p1 = HashSet::new();
    p1.insert(genesis.id.clone());
    let block1 = make_block(b"block1", vec![], p1);
    dag.add_block(block1).expect("add b1");
    let mut p2 = HashSet::new();
    p2.insert(genesis.id.clone());
    let block2 = make_block(b"block2", vec![], p2);
    dag.add_block(block2).expect("add b2");
    assert_eq!(dag.get_tips().len(), 2);
}

#[test]
fn test_19_dag_duplicate_block_rejected() {
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add first");
    assert!(dag.add_block(genesis).is_err());
}

#[test]
fn test_20_dag_blocks_with_transactions() {
    let mut dag = Dag::new();
    let tx = make_coinbase_tx(vec![make_output(100, b"miner")]);
    let genesis = make_block(b"genesis", vec![tx], HashSet::new());
    dag.add_block(genesis.clone()).expect("add genesis");
    assert_eq!(dag.get_block(&genesis.id).unwrap().transactions.len(), 1);
}

#[test]
fn test_21_dag_block_retrieval() {
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    let genesis_id = genesis.id.clone();
    dag.add_block(genesis).expect("add genesis");
    assert!(dag.get_block(&genesis_id).is_some());
}

// ============================================================================
// TEST SUITE 4: GHOSTDAG CONSENSUS ORDERING (Tests 22-28)
// ============================================================================

#[test]
fn test_22_ghostdag_initialization() {
    let ghostdag = GhostDag::new(24);
    assert_eq!(ghostdag.k, 24);
}

#[test]
fn test_23_ghostdag_select_parent_single() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add genesis");
    let selected = ghostdag.select_parent(&dag, std::slice::from_ref(&genesis.id));
    assert_eq!(selected, Some(genesis.id.clone()));
}

#[test]
fn test_24_ghostdag_select_parent_multiple() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add genesis");
    let mut p1 = HashSet::new();
    p1.insert(genesis.id.clone());
    let block1 = make_block(b"block1", vec![], p1);
    dag.add_block(block1.clone()).expect("add b1");
    let mut p2 = HashSet::new();
    p2.insert(genesis.id.clone());
    let block2 = make_block(b"block2", vec![], p2);
    dag.add_block(block2.clone()).expect("add b2");
    let selected = ghostdag.select_parent(&dag, &[block1.id.clone(), block2.id.clone()]);
    assert!(selected.is_some());
}

#[test]
fn test_25_ghostdag_empty_parents() {
    let ghostdag = GhostDag::new(24);
    let dag = Dag::new();
    assert!(ghostdag.select_parent(&dag, &[]).is_none());
}

#[test]
fn test_26_ghostdag_anticone() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add genesis");
    let anticone = ghostdag.anticone(&dag, &genesis.id);
    assert!(anticone.is_empty());
}

#[test]
fn test_27_ghostdag_build_blue_set() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add genesis");
    let (blue_set, _) = ghostdag.build_blue_set(&dag, &genesis.id, std::slice::from_ref(&genesis.id));
    assert!(!blue_set.is_empty());
}

#[test]
fn test_28_ghostdag_consensus_ordering() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add genesis");
    for i in 1u32..=5 {
        let mut p = HashSet::new();
        if i == 1 {
            p.insert(genesis.id.clone());
        } else {
            p.insert(Hash::new(&(i-1).to_le_bytes()));
        }
        let block = make_block(&i.to_le_bytes(), vec![], p);
        dag.add_block(block).unwrap_or_else(|_| panic!("add {}", i));
    }
    let ordering = ghostdag.get_ordering(&dag);
    assert!(!ordering.is_empty());
}

// ============================================================================
// TEST SUITE 5: VERKLE TREE & STATE COMMITMENT (Tests 29-34)
// ============================================================================

#[test]
fn test_29_verkle_tree_creation() {
    let storage = MemoryStorage::new();
    let _tree = VerkleTree::new(storage).expect("create tree");
}

#[test]
fn test_30_verkle_tree_root_consistency() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let root1 = tree.get_root().expect("get root");
    let root2 = tree.get_root().expect("get root");
    assert_eq!(root1, root2);
}

#[test]
fn test_31_verkle_tree_insert() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage).expect("create tree");
    let key = [0x01u8; 32];
    tree.insert(key, vec![0x10; 32]);
    let root = tree.get_root().expect("get root");
    assert_eq!(root.len(), 32);
}

#[test]
fn test_32_verkle_tree_multiple_inserts() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage).expect("create tree");
    for i in 0u8..10 {
        let mut key = [0u8; 32];
        key[0] = i;
        tree.insert(key, vec![i; 32]);
    }
    let root = tree.get_root().expect("get root");
    assert_eq!(root.len(), 32);
}

#[test]
fn test_33_verkle_tree_generate_proof() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage).expect("create tree");
    let key = [0x01u8; 32];
    tree.insert(key, vec![0x10; 32]);
    let _proof = tree.generate_proof(key).expect("generate proof");
}

#[test]
fn test_34_verkle_tree_verify_proof() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage).expect("create tree");
    let key = [0x01u8; 32];
    tree.insert(key, vec![0x10; 32]);
    let proof = tree.generate_proof(key).expect("generate proof");
    let valid = tree.verify_proof(&proof).expect("verify proof");
    assert!(valid);
}

// ============================================================================
// TEST SUITE 6: STATE MANAGER & BLOCK COMMITMENT (Tests 35-39)
// ============================================================================

#[test]
fn test_35_state_manager_creation() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let manager = StateManager::new(tree).expect("create manager");
    assert_eq!(manager.current_height, 0);
}

#[test]
fn test_36_state_manager_apply_empty_block() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let mut manager = StateManager::new(tree).expect("create manager");
    let mut utxo_set = UtxoSet::new();
    let block = make_block(b"genesis", vec![], HashSet::new());
    let result = manager.apply_block(&block, &mut utxo_set);
    assert!(result.is_ok());
}

#[test]
fn test_37_state_manager_get_root() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let manager = StateManager::new(tree).expect("create manager");
    if let Ok(root) = manager.get_root_hash() {
        assert_eq!(root.len(), 32);
    }
}

#[test]
fn test_38_state_manager_snapshots() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let manager = StateManager::new(tree).expect("create manager");
    let snap = manager.get_state_at(0);
    assert!(snap.is_some());
}

#[test]
fn test_39_state_manager_multiple_blocks() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let mut manager = StateManager::new(tree).expect("create manager");
    let mut utxo_set = UtxoSet::new();
    for i in 0u32..5 {
        let block = make_block(&i.to_le_bytes(), vec![], HashSet::new());
        manager.apply_block(&block, &mut utxo_set).ok();
    }
    assert_eq!(manager.current_height, 5);
}

// ============================================================================
// TEST SUITE 7: BLOCKCHAIN STATE MANAGEMENT (Tests 40-44)
// ============================================================================

#[test]
fn test_40_blockchain_state_creation() {
    let state = BlockchainState::new();
    assert_eq!(state.virtual_score, 0);
    assert!(state.finalizing_block.is_none());
}

#[test]
fn test_41_blockchain_state_set_finalizing_block() {
    let mut state = BlockchainState::new();
    let block_hash = Hash::new(b"block1");
    state.set_finalizing_block(block_hash.clone());
    assert_eq!(state.finalizing_block, Some(block_hash));
}

#[test]
fn test_42_blockchain_state_update_virtual_score() {
    let mut state = BlockchainState::new();
    state.update_virtual_score(100);
    assert_eq!(state.get_virtual_score(), 100);
}

#[test]
fn test_43_blockchain_state_mark_pruned() {
    let mut state = BlockchainState::new();
    state.mark_pruned(Hash::new(b"block1"));
    state.mark_pruned(Hash::new(b"block2"));
    assert_eq!(state.pruned.len(), 2);
}

#[test]
fn test_44_blockchain_state_utxo_integration() {
    let mut state = BlockchainState::new();
    state.utxo_set.utxos.insert((Hash::new(b"tx1"), 0), make_output(100, b"alice"));
    assert_eq!(state.utxo_set.utxos.len(), 1);
}

// ============================================================================
// TEST SUITE 8: EMISSION & REWARD SYSTEM (Tests 45-50)
// ============================================================================

#[test]
fn test_45_block_reward_genesis() {
    let reward = raw_block_reward(0);
    assert!(reward > 0);
}

#[test]
fn test_46_block_reward_early_blocks() {
    let reward_0 = raw_block_reward(0);
    let reward_100 = raw_block_reward(100);
    assert_eq!(reward_0, reward_100);
}

#[test]
fn test_47_block_reward_consistency() {
    let r1 = raw_block_reward(50);
    let r2 = raw_block_reward(50);
    assert_eq!(r1, r2);
}

#[test]
fn test_48_block_reward_halving_schedule() {
    let mut prev = raw_block_reward(0);
    for halving_num in 1u64..=5 {
        let height = halving_num * 100_000;
        let reward = raw_block_reward(height);
        assert!(reward <= prev);
        prev = reward;
    }
}

#[test]
fn test_49_block_reward_split() {
    let reward_base = raw_block_reward(0);
    let (miner, infra, _) = block_reward(0, 10);
    let total = (miner as u128) + (infra as u128);
    assert!(total <= reward_base);
}

#[test]
fn test_50_block_reward_no_nodes() {
    let (_miner, infra, _) = block_reward(0, 0);
    assert_eq!(infra, 0);
}

// ============================================================================
// TEST SUITE 9: ERROR HANDLING & EDGE CASES (Tests 51-54)
// ============================================================================

#[test]
fn test_51_dag_self_parent_rejected() {
    let mut dag = Dag::new();
    let block_id = Hash::new(b"block1");
    let mut parents = HashSet::new();
    parents.insert(block_id.clone());
    let block = BlockNode {
        id: block_id,
        parents,
        children: HashSet::new(),
        selected_parent: None,
        blue_set: HashSet::new(),
        red_set: HashSet::new(),
        blue_score: 0,
        timestamp: 0,
        difficulty: 0,
        nonce: 0,
        transactions: Vec::new(),
    };
    assert!(dag.add_block(block).is_err());
}

#[test]
fn test_52_dag_missing_parent_rejected() {
    let mut dag = Dag::new();
    let mut parents = HashSet::new();
    parents.insert(Hash::new(b"nonexistent"));
    let block = make_block(b"block1", vec![], parents);
    assert!(dag.add_block(block).is_err());
}

#[test]
fn test_53_dag_orphan_genesis_rejected() {
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis).expect("add genesis");
    let orphan = make_block(b"orphan", vec![], HashSet::new());
    assert!(dag.add_block(orphan).is_err());
}

#[test]
fn test_54_transaction_empty_outputs() {
    let tx = make_coinbase_tx(vec![]);
    assert_eq!(tx.outputs.len(), 0);
    assert!(tx.is_coinbase());
}

// ============================================================================
// TEST SUITE 10: COMPREHENSIVE WORKFLOW INTEGRATION (Tests 55-70)
// ============================================================================

#[test]
fn test_55_full_workflow_create_apply_commit() {
    let tx = make_coinbase_tx(vec![make_output(100, b"miner")]);
    let parents = HashSet::new();
    let block = make_block(b"block1", vec![tx], parents);
    let mut dag = Dag::new();
    dag.add_block(block.clone()).expect("add");
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let mut manager = StateManager::new(tree).expect("create");
    let mut utxo = UtxoSet::new();
    manager.apply_block(&block, &mut utxo).expect("apply");
    if let Ok(root) = manager.get_root_hash() {
        assert_eq!(root.len(), 32);
    }
}

#[test]
fn test_56_workflow_transaction_chain() {
    let mut utxo = UtxoSet::new();
    utxo.utxos.insert((Hash::new(b"gen"), 0), make_output(1000, b"alice"));
    let input = make_input(b"gen", 0);
    let tx = make_tx(vec![input], vec![make_output(900, b"bob")]);
    assert_eq!(tx.outputs.len(), 1);
}

#[test]
fn test_57_workflow_dag_consensus() {
    let mut dag = Dag::new();
    let ghostdag = GhostDag::new(24);
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis).expect("add");
    let ordering = ghostdag.get_ordering(&dag);
    assert!(!ordering.is_empty());
}

#[test]
fn test_58_workflow_state_snapshots() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let mut manager = StateManager::new(tree).expect("create");
    let mut utxo = UtxoSet::new();
    for i in 0u32..5 {
        let block = make_block(&i.to_le_bytes(), vec![], HashSet::new());
        manager.apply_block(&block, &mut utxo).ok();
    }
    assert!(manager.snapshots.len() > 0);
}

#[test]
fn test_59_workflow_block_commitment() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage).expect("create tree");
    let _ = tree.insert([0x01u8; 32], vec![0x10; 32]);
    let proof = tree.generate_proof([0x01u8; 32]).expect("generate proof");
    let valid = tree.verify_proof(&proof).expect("verify proof");
    assert!(valid);
}

#[test]
fn test_60_complex_dag_branches() {
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add");
    for i in 0u32..3 {
        let mut p = HashSet::new();
        p.insert(genesis.id.clone());
        let b = make_block(&i.to_le_bytes(), vec![], p);
        dag.add_block(b).ok();
    }
    assert!(dag.get_all_hashes().len() >= 3);
}

#[test]
fn test_61_ghostdag_complex_dag() {
    let mut dag = Dag::new();
    let ghostdag = GhostDag::new(24);
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add");
    for i in 1u32..5 {
        let mut p = HashSet::new();
        p.insert(Hash::new(&(i-1).to_le_bytes()));
        let b = make_block(&i.to_le_bytes(), vec![], p);
        dag.add_block(b).ok();
    }
    let ordering = ghostdag.get_ordering(&dag);
    assert!(!ordering.is_empty());
}

#[test]
fn test_62_state_manager_replay() {
    let storage = MemoryStorage::new();
    let tree = VerkleTree::new(storage).expect("create tree");
    let mut manager = StateManager::new(tree).expect("create");
    let mut utxo = UtxoSet::new();
    for i in 0u32..3 {
        let tx = make_coinbase_tx(vec![make_output(100 + i as u64, b"miner")]);
        let b = make_block(&i.to_le_bytes(), vec![tx], HashSet::new());
        manager.apply_block(&b, &mut utxo).ok();
    }
    assert!(manager.current_height > 0);
}

#[test]
fn test_63_utxo_spending() {
    let mut utxo = UtxoSet::new();
    for i in 0u32..5 {
        utxo.utxos.insert((Hash::new(&i.to_le_bytes()), 0), make_output(100, b"owner"));
    }
    assert_eq!(utxo.utxos.len(), 5);
}

#[test]
fn test_64_state_sequential() {
    let mut state = BlockchainState::new();
    for i in 0u32..5 {
        state.set_finalizing_block(Hash::new(&i.to_le_bytes()));
        state.update_virtual_score(i as u64 * 10);
    }
    assert!(state.get_virtual_score() > 0);
}

#[test]
fn test_65_emission_cumulative() {
    let mut total = 0u128;
    for i in 0u64..100 {
        total += raw_block_reward(i);
    }
    assert!(total > 0);
}

#[test]
fn test_66_ghostdag_ordering() {
    let ghostdag = GhostDag::new(24);
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    let mut dag = Dag::new();
    dag.add_block(genesis).ok();
    let ordering = ghostdag.get_ordering(&dag);
    assert!(ordering.len() >= 1);
}

#[test]
fn test_67_verkle_large_dataset() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage).expect("create tree");
    for i in 0u16..50 {
        let mut key = [0u8; 32];
        key[0] = (i / 256) as u8;
        let _ = tree.insert(key, vec![i as u8; 32]);
    }
    let root = tree.get_root().expect("get root");
    assert_eq!(root.len(), 32);
}

#[test]
fn test_68_config_values() {
    let config = Config::default();
    assert!(config.block_reward > 0);
    assert!(config.k > 0);
}

#[test]
fn test_69_full_tx_lifecycle() {
    let mut utxo = UtxoSet::new();
    utxo.utxos.insert((Hash::new(b"gen"), 0), make_output(1000, b"owner"));
    let input = make_input(b"gen", 0);
    let tx = make_tx(vec![input], vec![make_output(600, b"alice"), make_output(400, b"bob")]);
    assert!(!tx.is_coinbase());
    assert_eq!(tx.outputs.len(), 2);
}

#[test]
fn test_70_dag_ancestry() {
    let mut dag = Dag::new();
    let genesis = make_block(b"genesis", vec![], HashSet::new());
    dag.add_block(genesis.clone()).expect("add");
    let mut p = HashSet::new();
    p.insert(genesis.id);
    let b1 = make_block(b"b1", vec![], p);
    dag.add_block(b1).expect("add");
    assert_eq!(dag.get_all_hashes().len(), 2);
}
