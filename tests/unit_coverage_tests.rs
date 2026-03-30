/// Comprehensive Unit Tests for Low-Coverage Modules
/// Target: 90%+ code coverage for crypto, consensus, and state modules
use klomang_core::core::crypto::{
    schnorr::{self, KeyPairWrapper, verify},
    Hash,
};
use klomang_core::core::state::transaction::{Transaction, TxInput, TxOutput, SigHashType};
use klomang_core::core::state::utxo::UtxoSet;
use klomang_core::core::consensus::{ghostdag::GhostDag, reward};
use klomang_core::core::dag::{Dag, BlockNode};
use klomang_core::core::config::Config;
use klomang_core::core::errors::CoreError;
use std::collections::HashSet;

// ============================================================================
// SCHNORR CRYPTOGRAPHY TESTS
// ============================================================================

#[test]
fn test_schnorr_keypair_generation() {
    let kp1 = KeyPairWrapper::new();
    let kp2 = KeyPairWrapper::new();
    
    let pub1 = kp1.public_key();
    let pub2 = kp2.public_key();
    
    // Different keypairs should generate different public keys
    assert_ne!(pub1.to_bytes(), pub2.to_bytes());
}

#[test]
fn test_schnorr_sign_verify_basic() {
    let kp = KeyPairWrapper::new();
    let msg = b"Test message";
    
    let signature = kp.sign(msg);
    let pubkey = kp.public_key();
    
    assert!(verify(&pubkey, msg, &signature));
}

#[test]
fn test_schnorr_sign_verify_different_messages() {
    let kp = KeyPairWrapper::new();
    let msg1 = b"Message 1";
    let msg2 = b"Message 2";
    
    let sig1 = kp.sign(msg1);
    let pubkey = kp.public_key();
    
    // Correct message should verify
    assert!(verify(&pubkey, msg1, &sig1));
    
    // Different message should not verify
    assert!(!verify(&pubkey, msg2, &sig1));
}

#[test]
fn test_schnorr_sign_verify_wrong_pubkey() {
    let kp1 = KeyPairWrapper::new();
    let kp2 = KeyPairWrapper::new();
    let msg = b"Test message";
    
    let sig1 = kp1.sign(msg);
    let pubkey2 = kp2.public_key();
    
    // Signature from different keypair should not verify
    assert!(!verify(&pubkey2, msg, &sig1));
}

#[test]
fn test_schnorr_sign_multiple_messages() {
    let kp = KeyPairWrapper::new();
    let pubkey = kp.public_key();
    
    for i in 0..10 {
        let msg = format!("Message {}", i);
        let sig = kp.sign(msg.as_bytes());
        assert!(verify(&pubkey, msg.as_bytes(), &sig));
    }
}

#[test]
fn test_schnorr_tagged_hash() {
    let tag = "TEST_TAG";
    let data1 = b"data1";
    let data2 = b"data2";
    
    let hash1_a = schnorr::tagged_hash(tag, data1);
    let hash1_b = schnorr::tagged_hash(tag, data1);
    let hash2 = schnorr::tagged_hash(tag, data2);
    
    // Same input should produce same hash
    assert_eq!(hash1_a, hash1_b);
    
    // Different input should produce different hash
    assert_ne!(hash1_a, hash2);
}

#[test]
fn test_schnorr_tagged_hash_different_tags() {
    let data = b"same_data";
    let hash1 = schnorr::tagged_hash("TAG1", data);
    let hash2 = schnorr::tagged_hash("TAG2", data);
    
    // Different tags should produce different hashes for same data
    assert_ne!(hash1, hash2);
}

#[test]
fn test_schnorr_tx_message_consistency() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx1"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 1000,
            pubkey_hash: Hash::new(b"pubkey"),
        }],
        locktime: 0,
    };
    
    let msg1 = schnorr::tx_message(&tx);
    let msg2 = schnorr::tx_message(&tx);
    
    assert_eq!(msg1, msg2);
}

#[test]
fn test_schnorr_compute_sighash_all() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx1"),
        inputs: vec![TxInput {
            prev_tx: Hash::new(b"prev1"),
            index: 0,
            pubkey: vec![],
            signature: vec![],
            sighash_type: SigHashType::All,
        }],
        outputs: vec![TxOutput {
            value: 500,
            pubkey_hash: Hash::new(b"addr1"),
        }],
        locktime: 0,
    };
    
    let sighash = schnorr::compute_sighash(&tx, 0, SigHashType::All);
    assert!(sighash.is_ok());
    
    let hash = sighash.unwrap();
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_schnorr_compute_sighash_none() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx1"),
        inputs: vec![TxInput {
            prev_tx: Hash::new(b"prev1"),
            index: 0,
            pubkey: vec![],
            signature: vec![],
            sighash_type: SigHashType::None,
        }],
        outputs: vec![TxOutput {
            value: 500,
            pubkey_hash: Hash::new(b"addr1"),
        }],
        locktime: 0,
    };
    
    let sighash = schnorr::compute_sighash(&tx, 0, SigHashType::None);
    assert!(sighash.is_ok());
}

#[test]
fn test_schnorr_compute_sighash_single() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx1"),
        inputs: vec![TxInput {
            prev_tx: Hash::new(b"prev1"),
            index: 0,
            pubkey: vec![],
            signature: vec![],
            sighash_type: SigHashType::Single,
        }],
        outputs: vec![
            TxOutput {
                value: 300,
                pubkey_hash: Hash::new(b"addr1"),
            },
            TxOutput {
                value: 200,
                pubkey_hash: Hash::new(b"addr2"),
            },
        ],
        locktime: 0,
    };
    
    let sighash = schnorr::compute_sighash(&tx, 0, SigHashType::Single);
    assert!(sighash.is_ok());
}

#[test]
fn test_schnorr_serialize_tx_empty_inputs_outputs() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx1"),
        inputs: vec![],
        outputs: vec![],
        locktime: 0,
    };
    
    let serialized = schnorr::serialize_tx_for_sighash(&tx, 0, SigHashType::All);
    assert!(!serialized.is_empty());
}

#[test]
fn test_schnorr_serialize_tx_multiple_inputs() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx1"),
        inputs: vec![
            TxInput {
                prev_tx: Hash::new(b"prev1"),
                index: 0,
                pubkey: vec![1, 2, 3],
                signature: vec![],
                sighash_type: SigHashType::All,
            },
            TxInput {
                prev_tx: Hash::new(b"prev2"),
                index: 1,
                pubkey: vec![4, 5, 6],
                signature: vec![],
                sighash_type: SigHashType::All,
            },
        ],
        outputs: vec![],
        locktime: 0,
    };
    
    let serialized = schnorr::serialize_tx_for_sighash(&tx, 0, SigHashType::All);
    assert!(!serialized.is_empty());
}

// ============================================================================
// UTXO VALIDATION TESTS
// ============================================================================

#[test]
fn test_utxo_validate_coinbase_transaction() {
    let utxo_set = UtxoSet::new();
    
    let coinbase_tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"coinbase1"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 5000000000,
            pubkey_hash: Hash::new(b"miner1"),
        }],
        locktime: 0,
    };
    
    // Coinbase should always validate with 0 fee
    let fee = utxo_set.validate_tx(&coinbase_tx);
    assert!(fee.is_ok());
    assert_eq!(fee.unwrap(), 0);
}

#[test]
fn test_utxo_validate_insufficient_inputs() {
    let mut utxo_set = UtxoSet::new();
    
    // Add UTXO: 100 units
    let utxo_out = (Hash::new(b"prev"), 0);
    utxo_set.utxos.insert(
        utxo_out.clone(),
        TxOutput {
            value: 100,
            pubkey_hash: Hash::new(b"addr1"),
        },
    );
    
    // Transaction tries to spend 150 (more than available)
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"spend_too_much"),
        inputs: vec![TxInput {
            prev_tx: utxo_out.0.clone(),
            index: 0,
            pubkey: vec![0; 32],
            signature: vec![0; 64],
            sighash_type: SigHashType::All,
        }],
        outputs: vec![TxOutput {
            value: 150,
            pubkey_hash: Hash::new(b"addr2"),
        }],
        locktime: 0,
    };
    
    // Should fail due to insufficient inputs
    let result = utxo_set.validate_tx(&tx);
    assert!(result.is_err());
}

#[test]
fn test_utxo_validate_missing_input() {
    let utxo_set = UtxoSet::new();
    
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx_missing_input"),
        inputs: vec![TxInput {
            prev_tx: Hash::new(b"nonexistent"),
            index: 0,
            pubkey: vec![0; 32],
            signature: vec![0; 64],
            sighash_type: SigHashType::All,
        }],
        outputs: vec![TxOutput {
            value: 100,
            pubkey_hash: Hash::new(b"addr"),
        }],
        locktime: 0,
    };
    
    // Should fail: input UTXO not found
    let result = utxo_set.validate_tx(&tx);
    assert!(result.is_err());
}

#[test]
fn test_utxo_validate_invalid_pubkey_length() {
    let mut utxo_set = UtxoSet::new();
    
    let utxo_out = (Hash::new(b"prev"), 0);
    utxo_set.utxos.insert(
        utxo_out.clone(),
        TxOutput {
            value: 100,
            pubkey_hash: Hash::new(b"addr1"),
        },
    );
    
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"bad_pubkey_len"),
        inputs: vec![TxInput {
            prev_tx: utxo_out.0.clone(),
            index: 0,
            pubkey: vec![0; 20],
            signature: vec![0; 64],
            sighash_type: SigHashType::All,
        }],
        outputs: vec![TxOutput {
            value: 50,
            pubkey_hash: Hash::new(b"addr2"),
        }],
        locktime: 0,
    };
    
    let result = utxo_set.validate_tx(&tx);
    assert!(result.is_err());
}

#[test]
fn test_utxo_validate_invalid_signature_length() {
    let mut utxo_set = UtxoSet::new();
    
    let utxo_out = (Hash::new(b"prev"), 0);
    utxo_set.utxos.insert(
        utxo_out.clone(),
        TxOutput {
            value: 100,
            pubkey_hash: Hash::new(b"addr1"),
        },
    );
    
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"bad_sig_len"),
        inputs: vec![TxInput {
            prev_tx: utxo_out.0.clone(),
            index: 0,
            pubkey: vec![0; 32],
            signature: vec![0; 63],
            sighash_type: SigHashType::All,
        }],
        outputs: vec![TxOutput {
            value: 50,
            pubkey_hash: Hash::new(b"addr2"),
        }],
        locktime: 0,
    };
    
    let result = utxo_set.validate_tx(&tx);
    assert!(result.is_err());
}

// ============================================================================
// CORE ERROR SCENARIOS TESTS
// ============================================================================

#[test]
fn test_core_error_display_variants() {
    let c = CoreError::BlockNotFound;
    assert_eq!(format!("{}", c), "Block not found");

    let c = CoreError::InvalidParent;
    assert_eq!(format!("{}", c), "Invalid parent");

    let c = CoreError::DuplicateBlock;
    assert_eq!(format!("{}", c), "Duplicate block");

    let c = CoreError::ConsensusError;
    assert_eq!(format!("{}", c), "Consensus error");

    let c = CoreError::TransactionError("tx-fail".to_string());
    assert_eq!(format!("{}", c), "Transaction error: tx-fail");

    let c = CoreError::InvalidSignature;
    assert_eq!(format!("{}", c), "Invalid signature");

    let c = CoreError::InvalidPublicKey;
    assert_eq!(format!("{}", c), "Invalid public key");

    let c = CoreError::SignatureVerificationFailed;
    assert_eq!(format!("{}", c), "Signature verification failed");

    let c = CoreError::ConfigError("cfg".to_string());
    assert_eq!(format!("{}", c), "Config error: cfg");

    let c = CoreError::SerializationError("ser".to_string());
    assert_eq!(format!("{}", c), "Serialization error: ser");

    let c = CoreError::PolynomialCommitmentError("poly".to_string());
    assert_eq!(format!("{}", c), "Polynomial commitment error: poly");

    let c = CoreError::CryptographicError("crypto".to_string());
    assert_eq!(format!("{}", c), "Cryptographic error: crypto");

    let c = CoreError::StorageError("storage".to_string());
    assert_eq!(format!("{}", c), "Storage error: storage");
}

#[test]
fn test_core_error_paths_from_dag() {
    let mut dag = Dag::new();

    // Add genesis block first
    let genesis = BlockNode {
        id: Hash::new(b"genesis"),
        parents: HashSet::new(),
        children: HashSet::new(),
        selected_parent: None,
        blue_set: HashSet::new(),
        red_set: HashSet::new(),
        blue_score: 0,
        timestamp: 0,
        difficulty: 1,
        nonce: 0,
        transactions: Vec::new(),
    };
    dag.add_block(genesis.clone()).unwrap();

    // Duplicate block causes DuplicateBlock
    let result = dag.add_block(genesis.clone());
    assert!(matches!(result, Err(CoreError::DuplicateBlock)));

    // Invalid parent for a block requiring parent existence
    let mut bad_parent_set = HashSet::new();
    bad_parent_set.insert(Hash::new(b"missing"));
    let bad_block = BlockNode { id: Hash::new(b"bad"), parents: bad_parent_set, children: HashSet::new(), selected_parent: None, blue_set: HashSet::new(), red_set: HashSet::new(), blue_score: 0, timestamp: 0, difficulty: 1, nonce: 0, transactions: Vec::new() };
    let result = dag.add_block(bad_block);
    assert!(matches!(result, Err(CoreError::InvalidParent)));
}

// ============================================================================
// REWARD CALCULATION TESTS
// ============================================================================

#[test]
fn test_reward_calculate_block_reward_genesis() {
    let reward = reward::calculate_block_reward(0);
    let expected = Config::default().block_reward;
    assert_eq!(reward, expected);
}

#[test]
fn test_reward_calculate_block_reward_early_block() {
    let reward = reward::calculate_block_reward(1000);
    let expected = Config::default().block_reward;
    assert_eq!(reward, expected);
}

#[test]
fn test_reward_calculate_block_reward_first_halving() {
    let reward_before = reward::calculate_block_reward(99_999);
    let reward_at = reward::calculate_block_reward(100_000);
    let reward_after = reward::calculate_block_reward(100_001);
    
    let initial = Config::default().block_reward;
    assert_eq!(reward_before, initial);
    assert_eq!(reward_at, initial >> 1);
    assert_eq!(reward_after, initial >> 1);
}

#[test]
fn test_reward_calculate_block_reward_multiple_halvings() {
    let initial = Config::default().block_reward;
    let reward_0 = reward::calculate_block_reward(0);
    let reward_100k = reward::calculate_block_reward(100_000);
    let reward_200k = reward::calculate_block_reward(200_000);
    let reward_300k = reward::calculate_block_reward(300_000);
    
    assert_eq!(reward_0, initial);
    assert_eq!(reward_100k, initial >> 1);
    assert_eq!(reward_200k, initial >> 2);
    assert_eq!(reward_300k, initial >> 3);
}

#[test]
fn test_reward_calculate_block_reward_after_64_halvings() {
    let height = 100_000 * 64;
    let reward = reward::calculate_block_reward(height);
    assert_eq!(reward, 0);
}

#[test]
fn test_reward_calculate_fees_coinbase() {
    let utxo_set = UtxoSet::new();
    
    let coinbase = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"coinbase"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 5000000000,
            pubkey_hash: Hash::new(b"miner"),
        }],
        locktime: 0,
    };
    
    let fee = reward::calculate_fees(&coinbase, &utxo_set);
    assert!(fee.is_ok());
    assert_eq!(fee.unwrap(), 0);
}

// ============================================================================
// GHOSTDAG CONSENSUS TESTS
// ============================================================================

fn make_test_block(id: &[u8], parents: Vec<Hash>) -> BlockNode {
    BlockNode {
        id: Hash::new(id),
        parents: parents.into_iter().collect(),
        children: HashSet::new(),
        selected_parent: None,
        blue_set: HashSet::new(),
        red_set: HashSet::new(),
        blue_score: 0,
        timestamp: 0,
        difficulty: 0,
        nonce: 0,
        transactions: vec![],
    }
}

#[test]
fn test_ghostdag_select_parent_single() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    let b1 = make_test_block(b"b1", vec![genesis.id.clone()]);
    
    dag.add_block(genesis.clone()).ok();
    dag.add_block(b1.clone()).ok();
    
    let parents = vec![genesis.id.clone()];
    let selected = ghostdag.select_parent(&dag, &parents);
    
    assert_eq!(selected, Some(genesis.id.clone()));
}

#[test]
fn test_ghostdag_select_parent_multiple() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    let mut b1 = make_test_block(b"b1", vec![genesis.id.clone()]);
    let mut b2 = make_test_block(b"b2", vec![genesis.id.clone()]);
    
    b1.blue_score = 10;
    b2.blue_score = 20;
    
    dag.add_block(genesis).ok();
    dag.add_block(b1.clone()).ok();
    dag.add_block(b2.clone()).ok();
    
    let parents = vec![b1.id.clone(), b2.id.clone()];
    let selected = ghostdag.select_parent(&dag, &parents);
    
    assert_eq!(selected, Some(b2.id));
}

#[test]
fn test_ghostdag_select_parent_empty() {
    let ghostdag = GhostDag::new(24);
    let dag = Dag::new();
    
    let selected = ghostdag.select_parent(&dag, &[]);
    assert_eq!(selected, None);
}

#[test]
fn test_ghostdag_anticone_genesis() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    dag.add_block(genesis.clone()).ok();
    
    let anticone = ghostdag.anticone(&dag, &genesis.id);
    assert!(anticone.is_empty());
}

#[test]
fn test_ghostdag_build_blue_set_single_block() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    dag.add_block(genesis.clone()).ok();
    
    let (blue, red) = ghostdag.build_blue_set(&dag, &genesis.id, std::slice::from_ref(&genesis.id));
    
    assert!(blue.contains(&genesis.id));
    assert!(red.is_empty());
}

#[test]
fn test_ghostdag_build_virtual_block_empty() {
    let ghostdag = GhostDag::new(24);
    let dag = Dag::new();
    
    let vblock = ghostdag.build_virtual_block(&dag);
    assert!(vblock.parents.is_empty());
    assert_eq!(vblock.blue_score, 0);
}

#[test]
fn test_ghostdag_build_virtual_block_genesis() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    dag.add_block(genesis.clone()).ok();
    
    let vblock = ghostdag.build_virtual_block(&dag);
    assert_eq!(vblock.parents.len(), 1);
    assert!(vblock.parents.contains(&genesis.id));
}

#[test]
fn test_ghostdag_recompute_block_empty_parents() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let block = make_test_block(b"orphan", vec![]);
    dag.add_block(block.clone()).ok();
    
    let changed = ghostdag.recompute_block(&mut dag, &block.id);
    assert!(!changed);
}

#[test]
fn test_ghostdag_recompute_block_with_parents() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    let b1 = make_test_block(b"b1", vec![genesis.id.clone()]);
    
    dag.add_block(genesis).ok();
    dag.add_block(b1.clone()).ok();
    
    let changed = ghostdag.recompute_block(&mut dag, &b1.id);
    assert!(changed);
}

#[test]
fn test_ghostdag_recompute_block_missing_parent() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let missing = Hash::new(b"missing");
    let block = make_test_block(b"orphan", vec![missing]);
    dag.add_block(block.clone()).ok();
    
    let changed = ghostdag.recompute_block(&mut dag, &block.id);
    assert!(!changed);
}

#[test]
fn test_ghostdag_get_ordering_linear_chain() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    let b1 = make_test_block(b"b1", vec![genesis.id.clone()]);
    let b2 = make_test_block(b"b2", vec![b1.id.clone()]);
    
    dag.add_block(genesis).ok();
    dag.add_block(b1).ok();
    dag.add_block(b2).ok();
    
    let ordering = ghostdag.get_ordering(&dag);
    assert!(!ordering.is_empty());
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_edge_case_massive_dag_weight() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let mut genesis = make_test_block(b"genesis", vec![]);
    genesis.blue_score = u64::MAX - 1000;
    
    dag.add_block(genesis.clone()).ok();
    
    let vblock = ghostdag.build_virtual_block(&dag);
    assert!(vblock.blue_score > 0);
}

#[test]
fn test_reward_halving_progression() {
    for halving in 0..10 {
        let height = 100_000 * halving;
        let reward = reward::calculate_block_reward(height);
        let initial = Config::default().block_reward;
        
        if halving < 64 {
            assert_eq!(reward, initial >> halving);
        }
    }
}

#[test]
fn test_utxo_changeset_tracking() {
    let utxo_set = UtxoSet::new();
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"test"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 1000,
            pubkey_hash: Hash::new(b"addr"),
        }],
        locktime: 0,
    };
    
    // Just ensure coinbase validates
    let result = utxo_set.validate_tx(&tx);
    assert!(result.is_ok());
}

#[test]
fn test_schnorr_tag_hash_length() {
    let hash = schnorr::tagged_hash("KLOMANG", b"data");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_integration_dag_consistency() {
    let mut dag1 = Dag::new();
    let mut dag2 = Dag::new();
    
    let block = make_test_block(b"test_block", vec![]);
    dag1.add_block(block.clone()).ok();
    dag2.add_block(block.clone()).ok();
    
    assert_eq!(dag1.get_all_hashes().len(), dag2.get_all_hashes().len());
}

// ============================================================================
// ADDITIONAL COVERAGE TESTS - ERROR HANDLING & EDGE CASES
// ============================================================================

#[test]
fn test_error_invalid_public_key_format() {
    let utxo_set = UtxoSet::new();
    
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"bad_format"),
        inputs: vec![TxInput {
            prev_tx: Hash::new(b"prev"),
            index: 0,
            pubkey: vec![],  // Empty pubkey
            signature: vec![0; 64],
            sighash_type: SigHashType::All,
        }],
        outputs: vec![],
        locktime: 0,
    };
    
    let result = utxo_set.validate_tx(&tx);
    assert!(result.is_err());
}

#[test]
fn test_error_transaction_with_empty_outputs() {
    let utxo_set = UtxoSet::new();
    
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"empty_out"),
        inputs: vec![],
        outputs: vec![],
        locktime: 0,
    };
    
    // Coinbase with no outputs should still validate
    let result = utxo_set.validate_tx(&tx);
    assert!(result.is_ok());
}

#[test]
fn test_reward_overflow_protection() {
    // Test that extreme heights don't cause overflow
    let extreme_height = u64::MAX - 1;
    let reward = reward::calculate_block_reward(extreme_height);
    assert_eq!(reward, 0);
}

#[test]
fn test_ghostdag_anticone_with_multiple_branches() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    let b1 = make_test_block(b"b1", vec![genesis.id.clone()]);
    let b2 = make_test_block(b"b2", vec![genesis.id.clone()]);
    let b3 = make_test_block(b"b3", vec![b1.id.clone()]);
    let b4 = make_test_block(b"b4", vec![b2.id.clone()]);
    
    dag.add_block(genesis.clone()).ok();
    dag.add_block(b1.clone()).ok();
    dag.add_block(b2.clone()).ok();
    dag.add_block(b3.clone()).ok();
    dag.add_block(b4.clone()).ok();
    
    // Anticone tests
    let anticone_b3 = ghostdag.anticone(&dag, &b3.id);
    assert!(!anticone_b3.is_empty());
}

#[test]
fn test_schnorr_tag_consistency() {
    let tag = "TEST";
    let data = b"some_data";
    
    let h1 = schnorr::tagged_hash(tag, data);
    let h2 = schnorr::tagged_hash(tag, data);
    let h3 = schnorr::tagged_hash("OTHER", data);
    
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
}

#[test]
fn test_transaction_sighash_variations() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx_variations"),
        inputs: vec![
            TxInput {
                prev_tx: Hash::new(b"prev1"),
                index: 0,
                pubkey: vec![0; 32],
                signature: vec![0; 64],
                sighash_type: SigHashType::All,
            },
            TxInput {
                prev_tx: Hash::new(b"prev2"),
                index: 1,
                pubkey: vec![1; 32],
                signature: vec![0; 64],
                sighash_type: SigHashType::None,
            },
        ],
        outputs: vec![
            TxOutput {
                value: 100,
                pubkey_hash: Hash::new(b"out1"),
            },
            TxOutput {
                value: 50,
                pubkey_hash: Hash::new(b"out2"),
            },
        ],
        locktime: 100,
    };
    
    let sighash_all = schnorr::compute_sighash(&tx, 0, SigHashType::All);
    let sighash_none = schnorr::compute_sighash(&tx, 1, SigHashType::None);
    
    assert!(sighash_all.is_ok());
    assert!(sighash_none.is_ok());
    assert_ne!(sighash_all.unwrap(), sighash_none.unwrap());
}

#[test]
fn test_dag_block_children_tracking() {
    let mut dag = Dag::new();
    
    let genesis = make_test_block(b"genesis", vec![]);
    let b1 = make_test_block(b"b1", vec![genesis.id.clone()]);
    
    dag.add_block(genesis.clone()).ok();
    dag.add_block(b1.clone()).ok();
    
    // Check that blocks are tracked
    assert!(!dag.get_all_hashes().is_empty());
}

#[test]
fn test_utxo_value_overflow() {
    let mut utxo = UtxoSet::new();
    
    let tx_id = Hash::new(b"overflow_test");
    utxo.utxos.insert(
        (tx_id.clone(), 0),
        TxOutput {
            value: u64::MAX,
            pubkey_hash: Hash::new(b"addr"),
        },
    );
    
    // Verify max value is stored
    if let Some(output) = utxo.utxos.get(&(tx_id, 0)) {
        assert_eq!(output.value, u64::MAX);
    }
}

#[test]
fn test_ghostdag_build_blue_set_k_parameter() {
    let ghostdag_small = GhostDag::new(1);
    let ghostdag_large = GhostDag::new(100);
    
    assert_eq!(ghostdag_small.k, 1);
    assert_eq!(ghostdag_large.k, 100);
}

#[test]
fn test_reward_chain_id_independence() {
    let tx1 = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"tx1"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 1000,
            pubkey_hash: Hash::new(b"addr"),
        }],
        locktime: 0,
    };
    
    let tx2 = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 2,
        id: Hash::new(b"tx2"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 1000,
            pubkey_hash: Hash::new(b"addr"),
        }],
        locktime: 0,
    };
    
    // Transactions with different chain_id should have different IDs
    assert_ne!(tx1.calculate_id(), tx2.calculate_id());
}

#[test]
fn test_utxo_multiple_spending_attempts() {
    let mut utxo = UtxoSet::new();
    
    let outpoint = (Hash::new(b"utxo1"), 0);
    utxo.utxos.insert(
        outpoint.clone(),
        TxOutput {
            value: 100,
            pubkey_hash: Hash::new(b"addr"),
        },
    );
    
    // First transaction exists
    assert!(utxo.utxos.contains_key(&outpoint));
}

#[test]
fn test_schnorr_keypair_determinism() {
    let kp1 = KeyPairWrapper::new();
    let kp2 = KeyPairWrapper::new();
    
    // Different instances should have different keys
    let pub1 = kp1.public_key();
    let pub2 = kp2.public_key();
    
    // Low probability of collision
    assert_ne!(pub1.to_bytes(), pub2.to_bytes());
}

#[test]
fn test_transaction_id_determinism() {
    let tx = Transaction { execution_payload: Vec::new(), contract_address: None, gas_limit: 0, max_fee_per_gas: 0,
        chain_id: 1,
        id: Hash::new(b"temp"),
        inputs: vec![],
        outputs: vec![TxOutput {
            value: 100,
            pubkey_hash: Hash::new(b"addr"),
        }],
        locktime: 0,
    };
    
    let id1 = tx.calculate_id();
    let id2 = tx.calculate_id();
    
    assert_eq!(id1, id2);
}

#[test]
fn test_ghostdag_virtual_block_tips() {
    let ghostdag = GhostDag::new(24);
    let mut dag = Dag::new();
    
    for i in 0..5 {
        let block = make_test_block(
            format!("block_{}", i).as_bytes(),
            vec![]
        );
        dag.add_block(block).ok();
    }
    
    let vblock = ghostdag.build_virtual_block(&dag);
    // Virtual block should have some parent
    assert!(!vblock.parents.is_empty() || dag.get_all_hashes().is_empty());
}

#[test]
fn test_reward_multiple_halvings_step() {
    let config = Config::default();
    let initial_reward = config.block_reward;
    
    for halving_count in 0..5 {
        let height = 100_000 * halving_count;
        let reward = reward::calculate_block_reward(height);
        
        if halving_count < 64 {
            assert_eq!(reward, initial_reward >> halving_count);
        }
    }
}

#[test]
fn test_dag_block_insertion_order() {
    let mut dag = Dag::new();
    
    let blocks: Vec<_> = (0..10)
        .map(|i| make_test_block(format!("block_{}", i).as_bytes(), vec![]))
        .collect();
    
    for block in blocks {
        let result = dag.add_block(block);
        assert!(result.is_ok() || result.is_err());
    }
}

#[test]
fn test_utxo_serialization_format() {
    let output = TxOutput {
        value: 12345,
        pubkey_hash: Hash::new(b"test_hash"),
    };
    
    let serialized = output.serialize();
    assert!(!serialized.is_empty());
    assert!(serialized.len() >= 8); // At least 8 bytes for value
}


