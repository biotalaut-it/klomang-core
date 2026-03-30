//! Cryptographic Operations Integration Tests
//! Tests Verkle Tree, Polynomial Commitments, Hash functions, and Signatures

use klomang_core::core::crypto::{Hash, KeyPairWrapper};
use klomang_core::core::crypto::verkle::VerkleTree;
use klomang_core::core::state::MemoryStorage;
use klomang_core::core::crypto::verkle::verkle_tree::ProofType;

/// Test 1: Verkle tree insertion and retrieval
#[test]
fn test_verkle_tree_insert_retrieve() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let key = [1u8; 32];
    let value = b"test_value_12345".to_vec();
    
    tree.insert(key, value.clone());
    
    let retrieved = tree.get(key).unwrap();
    assert_eq!(retrieved, Some(value));
}

/// Test 2: Verkle tree multiple insertions
#[test]
fn test_verkle_tree_multiple_insertions() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    // Insert multiple key-value pairs
    for i in 0..10 {
        let mut key = [0u8; 32];
        key[0] = i as u8;
        let value = format!("value_{}", i).as_bytes().to_vec();
        tree.insert(key, value.clone());
        
        let retrieved = tree.get(key).unwrap();
        assert_eq!(retrieved, Some(value));
    }
}

/// Test 3: Verkle tree root hash stability
#[test]
fn test_verkle_tree_root_hash_stability() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let key = [42u8; 32];
    let value = b"stable_value".to_vec();
    
    tree.insert(key, value.clone());
    let root1 = tree.get_root();
    
    // Inserting same key/value again should not change root
    tree.insert(key, value);
    let root2 = tree.get_root();
    
    assert_eq!(root1, root2);
}

/// Test 4: Verkle tree membership proof
#[test]
fn test_verkle_tree_membership_proof() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let key = [100u8; 32];
    let value = b"membership_test".to_vec();
    
    tree.insert(key, value.clone());
    
    let proof = tree.generate_proof(key);
    
    // Verify membership proof
    assert_eq!(proof.proof_type, ProofType::Membership);
    assert_eq!(proof.leaf_value, Some(value));
    
    let is_valid = tree.verify_proof(&proof);
    assert!(is_valid);
}

/// Test 5: Verkle tree non-membership proof
#[test]
fn test_verkle_tree_non_membership_proof() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let inserted_key = [50u8; 32];
    let inserted_value = b"inserted".to_vec();
    tree.insert(inserted_key, inserted_value);
    
    let missing_key = [75u8; 32];
    
    let proof = tree.generate_proof(missing_key);
    
    // Verify non-membership proof
    assert_eq!(proof.proof_type, ProofType::NonMembership);
    assert_eq!(proof.leaf_value, None);
    
    let is_valid = tree.verify_proof(&proof);
    assert!(is_valid);
}

/// Test 6: Verkle tree proof with modified root should fail
#[test]
fn test_verkle_tree_invalid_proof_modified_root() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let key = [10u8; 32];
    tree.insert(key, b"value".to_vec());
    
    let mut proof = tree.generate_proof(key);
    
    // Corrupt the proof's root
    proof.root[0] ^= 0xFF;
    
    let is_valid = tree.verify_proof(&proof);
    assert!(!is_valid);
}

/// Test 7: Hash function determinism
#[test]
fn test_hash_function_determinism() {
    let data = b"deterministic_test_data";
    
    let hash1 = Hash::new(data);
    let hash2 = Hash::new(data);
    
    assert_eq!(hash1, hash2);
}

/// Test 8: Hash function collision resistance
#[test]
fn test_hash_function_different_inputs() {
    let hash1 = Hash::new(b"input1");
    let hash2 = Hash::new(b"input2");
    
    assert_ne!(hash1, hash2);
}

/// Test 9: Key pair generation and verification
#[test]
fn test_key_pair_generation() {
    let keypair = KeyPairWrapper::new();
    
    // Public key should be derived from private key
    let pubkey = keypair.public_key();
    let pubkey_bytes = pubkey.to_bytes();
    assert!(!pubkey_bytes.is_empty());
    assert!(pubkey_bytes.len() == 33 || pubkey_bytes.len() == 65); // compressed/uncompressed formats
}

/// Test 10: Verkle tree storage persistence
#[test]
fn test_verkle_tree_storage_clone() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let key = [200u8; 32];
    let value = b"persistence_test".to_vec();
    tree.insert(key, value.clone());
    
    // Clone the storage
    let cloned_storage = tree.storage_clone();

    // Create new tree from cloned storage
    let mut tree2 = VerkleTree::new(cloned_storage);
    
    // Should be able to retrieve the value from new tree
    let retrieved = tree2.get(key).unwrap();
    assert_eq!(retrieved, Some(value));
}

/// Test 11: Empty Verkle tree operations
#[test]
fn test_verkle_tree_empty_operations() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let key = [0u8; 32];
    assert_eq!(tree.get(key).unwrap(), None);
    
    // Get root from empty tree
    let root = tree.get_root();
    assert_eq!(root.len(), 32);
}

/// Test 12: Large data values in Verkle tree
#[test]
fn test_verkle_tree_large_values() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let key = [123u8; 32];
    let large_value = vec![42u8; 1000]; // 1KB value
    
    tree.insert(key, large_value.clone());
    
    let retrieved = tree.get(key).unwrap();
    assert_eq!(retrieved, Some(large_value));
}

/// Test 13: Verkle tree with many keys
#[test]
fn test_verkle_tree_many_keys() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    // Insert 256 different keys
    for i in 0..256 {
        let mut key = [i as u8; 32];
        let value = format!("value_{}", i).as_bytes().to_vec();
        tree.insert(key, value.clone());
    }
    
    // Retrieve all keys to verify
    for i in 0..256 {
        let mut key = [i as u8; 32];
        let value = format!("value_{}", i).as_bytes().to_vec();
        assert_eq!(tree.get(key).unwrap(), Some(value));
    }
}

/// Test 14: Hash equality
#[test]
fn test_hash_equality() {
    let hash1 = Hash::new(b"test");
    let hash2 = Hash::new(b"test");
    let hash3 = Hash::new(b"different");
    
    assert_eq!(hash1, hash2);
    assert_ne!(hash1, hash3);
}

/// Test 15: Verkle tree proof path correctness
#[test]
fn test_verkle_proof_path_correctness() {
    let storage = MemoryStorage::new();
    let mut tree = VerkleTree::new(storage);
    
    let key = [77u8; 32];
    tree.insert(key, b"path_test".to_vec());
    
    let proof = tree.generate_proof(key);
    
    // Path length should match key size (32 bytes)
    assert_eq!(proof.path.len(), 32);
    
    // All path elements should match the key
    for (i, &path_byte) in proof.path.iter().enumerate() {
        assert_eq!(path_byte, key[i]);
    }
}
