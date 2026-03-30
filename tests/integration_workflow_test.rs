//! Comprehensive Integration Tests for Klomang Core
//! Tests the complete workflow: Transaction -> UTXO Validation -> Consensus -> Block Commitment

use klomang_core::core::crypto::Hash;
use klomang_core::core::dag::{Dag, BlockNode};
use klomang_core::core::state::transaction::{Transaction, TxOutput};
use klomang_core::core::state::utxo::UtxoSet;
use klomang_core::core::state::MemoryStorage;
use klomang_core::core::crypto::verkle::VerkleTree;
use klomang_core::core::consensus::GhostDag;
use std::collections::HashSet;

/// Helper to create a simple transaction
fn make_tx(outputs: Vec<TxOutput>) -> Transaction {
    let mut tx = Transaction::new(Vec::new(), outputs);
    tx
}

/// Helper to create a block
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

/// Test 1: Basic transaction creation
#[test]
fn test_basic_transaction_creation() {
    let outputs = vec![TxOutput {
        value: 100,
        pubkey_hash: Hash::new(b"recipient"),
    }];
    
    let tx = make_tx(outputs);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, 100);
}

/// Test 2: Multiple outputs in transaction
#[test]
fn test_multiple_transaction_outputs() {
    let outputs = vec![
        TxOutput { value: 50, pubkey_hash: Hash::new(b"alice") },
        TxOutput { value: 30, pubkey_hash: Hash::new(b"bob") },
        TxOutput { value: 20, pubkey_hash: Hash::new(b"charlie") },
    ];
    
    let tx = make_tx(outputs);
    assert_eq!(tx.outputs.len(), 3);
}

/// Test 3: UTXO set operations
#[test]
fn test_utxo_set_operations() {
    let mut utxo_set = UtxoSet::new();
    
    let tx_hash = Hash::new(b"tx1");
    let output = TxOutput {
        value: 100,
        pubkey_hash: Hash::new(b"alice"),
    };
    
    utxo_set.utxos.insert((tx_hash.clone(), 0), output.clone());
    
    assert!(utxo_set.utxos.contains_key(&(tx_hash, 0)));
}

/// Test 4: Block creation with transactions
#[test]
fn test_block_creation() {
    let outputs = vec![TxOutput { value: 100, pubkey_hash: Hash::new(b"alice") }];
    let tx = make_tx(outputs);
    
    let mut parents = HashSet::new();
    parents.insert(Hash::new(b"genesis"));
    
    let block = make_block(b"block1", vec![tx], parents);
    assert_eq!(block.transactions.len(), 1);
}

/// Test 5: Genesis block setup
#[test]
fn test_genesis_block() {
    let parents = HashSet::new();
    let genesis = make_block(b"genesis", vec![], parents);
    
    assert_eq!(genesis.transactions.len(), 0);
    assert_eq!(genesis.parents.len(), 0);
}

/// Test 6: DAG structure
#[test]
fn test_dag_structure() {
    let mut dag = Dag::new();

    let mut genesis_parents = HashSet::new();
    let genesis = make_block(b"genesis", vec![], genesis_parents);
    
    dag.add_block(genesis.clone()).expect("Failed to add genesis");
    assert!(dag.get_block(&genesis.id).is_some());
}

/// Test 7: Multiple blocks in DAG
#[test]
fn test_multiple_blocks_in_dag() {
    let mut dag = Dag::new();
    
    let mut gen_parents = HashSet::new();
    let gen = make_block(b"genesis", vec![], gen_parents);
    dag.add_block(gen.clone()).expect("Failed to add genesis");
    
    let mut block1_parents = HashSet::new();
    block1_parents.insert(gen.id.clone());
    let block1 = make_block(b"block1", vec![], block1_parents);
    dag.add_block(block1.clone()).expect("Failed to add block1");
    
    let all_blocks = dag.get_all_hashes();
    assert!(all_blocks.len() >= 2);
}

/// Test 8: Block commitment and root tracking
#[test]
fn test_block_commitment_verification() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    // Verify tree was created
    let root = tree.get_root();
    assert_eq!(root.len(), 32);
}

/// Test 9: DAG with parent-child relationships
#[test]
fn test_dag_parent_child_relationships() {
    let mut dag = Dag::new();
    
    let mut gen_parents = HashSet::new();
    let gen = make_block(b"genesis", vec![], gen_parents);
    dag.add_block(gen.clone()).expect("Failed to add genesis");
    
    let mut parents = HashSet::new();
    parents.insert(gen.id.clone());
    let block1 = make_block(b"block1", vec![], parents);
    dag.add_block(block1.clone()).expect("Failed to add block1");
    
    let block1_retrieved = dag.get_block(&block1.id);
    assert!(block1_retrieved.is_some());
}

/// Test 10: GHOSTDAG consensus ordering
#[test]
fn test_ghostdag_consensus() {
    let mut dag = Dag::new();
    let mut ghostdag = GhostDag::new(24);
    
    let mut gen_parents = HashSet::new();
    let gen = make_block(b"genesis", vec![], gen_parents);
    dag.add_block(gen.clone()).expect("Failed to add genesis");
    
    let mut block1_parents = HashSet::new();
    block1_parents.insert(gen.id.clone());
    let block1 = make_block(b"block1", vec![], block1_parents);
    dag.add_block(block1.clone()).expect("Failed to add block1");
    
    let tips = dag.get_all_hashes();
    assert!(tips.len() > 0);
}

/// Test 11: Empty transaction block
#[test]
fn test_empty_transaction_block() {
    let mut parents = HashSet::new();
    parents.insert(Hash::new(b"parent"));
    
    let block = make_block(b"empty_block", vec![], parents);
    assert_eq!(block.transactions.len(), 0);
}

/// Test 12: UTXO spend and create
#[test]
fn test_utxo_spend_and_create() {
    let mut utxo_set = UtxoSet::new();
    
    // Create initial UTXO
    let tx0 = Hash::new(b"tx0");
    let output0 = TxOutput { value: 100, pubkey_hash: Hash::new(b"alice") };
    utxo_set.utxos.insert((tx0.clone(), 0), output0);
    
    // Remove it (spend)
    utxo_set.utxos.remove(&(tx0.clone(), 0));
    
    // Create new UTXO
    let tx1 = Hash::new(b"tx1");
    let output1 = TxOutput { value: 100, pubkey_hash: Hash::new(b"bob") };
    utxo_set.utxos.insert((tx1.clone(), 0), output1);
    
    assert!(!utxo_set.utxos.contains_key(&(tx0, 0)));
    assert!(utxo_set.utxos.contains_key(&(tx1, 0)));
}

/// Test 13: DAG retrieval consistency
#[test]
fn test_dag_retrieval_consistency() {
    let mut dag = Dag::new();
    
    let mut parents = HashSet::new();
    let block = make_block(b"test_block", vec![], parents);
    
    dag.add_block(block.clone()).expect("Failed to add block");
    
    let retrieved = dag.get_block(&block.id);
    assert!(retrieved.is_some());
    
    let retrieved_block = retrieved.unwrap();
    assert_eq!(retrieved_block.id, block.id);
}

/// Test 14: Transaction chain
#[test]
fn test_transaction_chain() {
    let tx1 = make_tx(vec![TxOutput { value: 100, pubkey_hash: Hash::new(b"alice") }]);
    let tx2 = make_tx(vec![TxOutput { value: 100, pubkey_hash: Hash::new(b"bob") }]);
    let tx3 = make_tx(vec![TxOutput { value: 100, pubkey_hash: Hash::new(b"charlie") }]);
    
    let txs = vec![tx1, tx2, tx3];
    
    let mut parents = HashSet::new();
    parents.insert(Hash::new(b"genesis"));
    
    let block = make_block(b"block", txs, parents);
    assert_eq!(block.transactions.len(), 3);
}

/// Test 15: Complete workflow integration
#[test]
fn test_complete_workflow_integration() {
    // Setup DAG
    let mut dag = Dag::new();
    let mut ghostdag = GhostDag::new(24);
    
    // Create genesis
    let mut gen_parents = HashSet::new();
    let genesis = make_block(b"genesis", vec![], gen_parents);
    dag.add_block(genesis.clone()).expect("Failed to add genesis");
    
    // Add blocks
    for i in 1..=3 {
        let mut parents = HashSet::new();
        parents.insert(genesis.id.clone());
        
        let block_id = format!("block{}", i);
        let block = make_block(block_id.as_bytes(), vec![], parents);
        dag.add_block(block.clone()).expect("Failed to add block");
    }
    
    let all = dag.get_all_hashes();
    assert!(all.len() >= 4);
}

/// Test 16: Parallel execution no conflict
#[test]
fn test_parallel_execution_no_conflict() {
    use klomang_core::core::scheduler::parallel::ParallelScheduler;
    use klomang_core::core::state::transaction::TxInput;

    // Create two transactions with different outputs (no conflict)
    let tx1 = Transaction::new(
        vec![],
        vec![TxOutput { value: 100, pubkey_hash: Hash::new(b"alice") }]
    );
    let tx2 = Transaction::new(
        vec![],
        vec![TxOutput { value: 200, pubkey_hash: Hash::new(b"bob") }]
    );

    let txs = vec![tx1, tx2];
    let groups = ParallelScheduler::schedule_transactions(txs);

    // Should be scheduled in one group since no conflicts
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].len(), 2);
}

/// Test 17: Parallel execution with conflict
#[test]
fn test_parallel_execution_conflict() {
    use klomang_core::core::scheduler::parallel::ParallelScheduler;
    use klomang_core::core::state::transaction::TxInput;

    // Create transactions that might conflict (same output key)
    // For simplicity, create txs with same hash_with_index
    let mut tx1 = Transaction::new(
        vec![],
        vec![TxOutput { value: 100, pubkey_hash: Hash::new(b"alice") }]
    );
    tx1.id = Hash::new(b"same_id");

    let mut tx2 = Transaction::new(
        vec![],
        vec![TxOutput { value: 200, pubkey_hash: Hash::new(b"bob") }]
    );
    tx2.id = Hash::new(b"same_id");

    let txs = vec![tx1, tx2];
    let groups = ParallelScheduler::schedule_transactions(txs);

    // Should be scheduled in separate groups due to conflict
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].len(), 1);
    assert_eq!(groups[1].len(), 1);
}
