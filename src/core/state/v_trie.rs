use crate::core::crypto::verkle::polynomial_commitment::Commitment;
use crate::core::crypto::verkle::PolynomialCommitment;
use crate::core::errors::CoreError;
use crate::core::state::storage::Storage;
use ark_ec::Group;
use std::collections::HashSet;
use ark_ed_on_bls12_381_bandersnatch::EdwardsProjective;
use ark_ff::{Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::CanonicalSerialize;
use blake3;

type ScalarField = <EdwardsProjective as Group>::ScalarField;
type RootHashes = Vec<[u8; 32]>;
type ScalarValues = Vec<ScalarField>;
type EmptySubtreeConstantsResult = Result<(RootHashes, ScalarValues), CoreError>;

const VERKLE_RADIX: usize = 256;
const KEY_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofType {
    Membership,
    NonMembership,
}

#[derive(Debug, Clone)]
pub struct VerkleProof {
    pub proof_type: ProofType,
    pub path: Vec<u8>,
    pub siblings: Vec<[u8; 32]>,
    pub leaf_value: Option<Vec<u8>>,
    pub root: [u8; 32],
}

/// In-memory storage-backed 256-ary Verkle tree.
#[derive(Debug)]
pub struct VerkleTree<S: Storage> {
    storage: S,
    pc: PolynomialCommitment,
    empty_subtree_roots: Vec<[u8; 32]>,
    empty_subtree_scalars: Vec<<EdwardsProjective as Group>::ScalarField>,
    pruned_keys: HashSet<Vec<u8>>,
}

impl<S: Storage> VerkleTree<S> {
    pub fn new(storage: S) -> Result<Self, CoreError> {
        let pc = PolynomialCommitment::new(VERKLE_RADIX);
        let (empty_subtree_roots, empty_subtree_scalars) =
            Self::compute_empty_subtree_constants(&pc)?;

        let mut tree = Self {
            storage,
            pc,
            empty_subtree_roots,
            empty_subtree_scalars,
            pruned_keys: HashSet::new(),
        };
        tree.ensure_node(&[]);
        Ok(tree)
    }

    pub fn insert(&mut self, key: [u8; KEY_SIZE], value: Vec<u8>) {
        let mut path = Vec::new();
        self.ensure_node(&path);

        for &byte in key.iter().take(KEY_SIZE) {
            path.push(byte);
            self.ensure_node(&path);
        }

        self.set_node_value(&path, Some(value));
    }

    pub fn get(&self, key: [u8; KEY_SIZE]) -> Result<Option<Vec<u8>>, CoreError> {
        let path_vec = key.to_vec();
        if self.pruned_keys.contains(&path_vec) {
            return Err(CoreError::PrunedData("Key has been pruned".to_string()));
        }

        let mut path = Vec::new();
        for &byte in key.iter().take(KEY_SIZE) {
            path.push(byte);
        }

        Ok(self.get_node_value(&path))
    }

    pub fn prune_key(&mut self, key: [u8; KEY_SIZE]) -> Result<(), CoreError> {
        let mut path = Vec::new();
        for &byte in key.iter().take(KEY_SIZE) {
            path.push(byte);
        }

        let storage_key = Self::key_for_path(&path);
        if self.storage.get(&storage_key).is_none() {
            return Err(CoreError::PrunedData("Key does not exist or already absent".to_string()));
        }

        self.storage.delete(&storage_key);
        self.pruned_keys.insert(path.clone());
        Ok(())
    }

    pub fn get_root(&self) -> Result<[u8; 32], CoreError> {
        self.compute_node_root_hash(&[], 0)
    }

    pub fn storage_clone(&self) -> S
    where
        S: Clone,
    {
        self.storage.clone()
    }

    pub fn generate_proof(&self, key: [u8; KEY_SIZE]) -> Result<VerkleProof, CoreError> {
        let mut siblings = Vec::with_capacity(KEY_SIZE * VERKLE_RADIX);
        let mut path = Vec::new();
        let mut path_exists = true;

        for (depth, &byte) in key.iter().enumerate().take(KEY_SIZE) {
            let empty_child_root = self.empty_subtree_root_hash(depth + 1);
            for child_index in 0..VERKLE_RADIX {
                let child_root = if path_exists && self.node_exists(&path) {
                    let mut child_path = path.clone();
                    child_path.push(child_index as u8);
                    if self.node_exists(&child_path) {
                        self.compute_node_root_hash(&child_path, depth + 1)?
                    } else {
                        empty_child_root
                    }
                } else {
                    empty_child_root
                };
                siblings.push(child_root);
            }

            if path_exists {
                path.push(byte);
                if !self.node_exists(&path) {
                    path_exists = false;
                }
            }
        }

        let leaf_value = if path_exists {
            self.get_node_value(&path)
        } else {
            None
        };

        let proof_type = if leaf_value.is_some() {
            ProofType::Membership
        } else {
            ProofType::NonMembership
        };

        Ok(VerkleProof {
            proof_type,
            path: key.to_vec(),
            siblings,
            leaf_value,
            root: self.get_root()?,
        })
    }

    pub fn verify_proof(&self, proof: &VerkleProof) -> Result<bool, CoreError> {
        if proof.path.len() != KEY_SIZE {
            return Ok(false);
        }

        if proof.siblings.len() != KEY_SIZE * VERKLE_RADIX {
            return Ok(false);
        }

        match proof.proof_type {
            ProofType::Membership => {
                if proof.leaf_value.is_none() {
                    return Ok(false);
                }
            }
            ProofType::NonMembership => {
                if proof.leaf_value.is_some() {
                    return Ok(false);
                }
            }
        }

        let mut current_scalar = match (&proof.proof_type, &proof.leaf_value) {
            (ProofType::Membership, Some(value)) => {
                let leaf_scalar = Self::value_to_scalar(value);
                let leaf_poly = DensePolynomial::from_coefficients_vec(vec![leaf_scalar]);
                let leaf_commitment = self.pc.commit(&leaf_poly)
                    .map_err(|e| CoreError::PolynomialCommitmentError(format!("Failed to commit leaf: {}", e)))?;
                let leaf_root_hash = Self::commitment_root_hash(&leaf_commitment)?;
                <EdwardsProjective as Group>::ScalarField::from_le_bytes_mod_order(&leaf_root_hash)
            }
            (ProofType::NonMembership, _) => {
                let empty_leaf_root = self.empty_subtree_root_hash(KEY_SIZE);
                <EdwardsProjective as Group>::ScalarField::from_le_bytes_mod_order(&empty_leaf_root)
            }
            _ => return Ok(false),
        };

        let mut computed_root: [u8; 32] = [0u8; 32];

        for depth in (0..KEY_SIZE).rev() {
            let base = depth * VERKLE_RADIX;
            let mut coeffs = Vec::with_capacity(VERKLE_RADIX);

            for child_index in 0..VERKLE_RADIX {
                if child_index == proof.path[depth] as usize {
                    coeffs.push(current_scalar);
                } else {
                    let sibling_hash = proof.siblings[base + child_index];
                    coeffs.push(<EdwardsProjective as Group>::ScalarField::from_le_bytes_mod_order(&sibling_hash));
                }
            }

            let polynomial = DensePolynomial::from_coefficients_vec(coeffs);
            let reconstructed_commitment = self.pc.commit(&polynomial)
                .map_err(|e| CoreError::PolynomialCommitmentError(format!("Failed to reconstruct commitment: {}", e)))?;
            let reconstructed_root = Self::commitment_root_hash(&reconstructed_commitment)?;

            computed_root = reconstructed_root;
            current_scalar = <EdwardsProjective as Group>::ScalarField::from_le_bytes_mod_order(&reconstructed_root);
        }

        if computed_root != proof.root {
            return Ok(false);
        }

        Ok(true)
    }

    fn key_for_path(path: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + path.len());
        key.push(path.len() as u8);
        key.extend_from_slice(path);
        key
    }

    fn serialize_node(value: Option<&[u8]>) -> Vec<u8> {
        let mut data = Vec::new();
        match value {
            Some(inner) => {
                data.push(1);
                data.extend_from_slice(&(inner.len() as u32).to_be_bytes());
                data.extend_from_slice(inner);
            }
            None => {
                data.push(0);
            }
        }
        data
    }

    fn deserialize_node(encoded: &[u8]) -> Option<Option<Vec<u8>>> {
        if encoded.is_empty() {
            return None;
        }

        match encoded[0] {
            0 => Some(None),
            1 => {
                if encoded.len() < 5 {
                    return None;
                }
                let size = u32::from_be_bytes(encoded[1..5].try_into().ok()?) as usize;
                if encoded.len() != 5 + size {
                    return None;
                }
                Some(Some(encoded[5..].to_vec()))
            }
            _ => None,
        }
    }

    fn ensure_node(&mut self, path: &[u8]) {
        let key = Self::key_for_path(path);
        if self.storage.get(&key).is_none() {
            self.storage.put(key, Self::serialize_node(None));
        }
    }

    fn node_exists(&self, path: &[u8]) -> bool {
        let key = Self::key_for_path(path);
        self.storage.get(&key).is_some()
    }

    fn get_node_value(&self, path: &[u8]) -> Option<Vec<u8>> {
        let key = Self::key_for_path(path);
        self.storage
            .get(&key)
            .and_then(|encoded| Self::deserialize_node(&encoded))
            .flatten()
    }

    fn set_node_value(&mut self, path: &[u8], value: Option<Vec<u8>>) {
        let key = Self::key_for_path(path);
        self.storage.put(key, Self::serialize_node(value.as_deref()));
    }

    fn compute_node_commitment(&self, path: &[u8], depth: usize) -> Result<Commitment, CoreError> {
        if depth == KEY_SIZE {
            let leaf_scalar = self
                .get_node_value(path)
                .as_deref()
                .map(Self::value_to_scalar)
                .unwrap_or(<EdwardsProjective as Group>::ScalarField::ZERO);

            let poly = DensePolynomial::from_coefficients_vec(vec![leaf_scalar]);
            return self.pc.commit(&poly)
                .map_err(|e| CoreError::PolynomialCommitmentError(format!("Failed to commit leaf: {}", e)));
        }

        let empty_scalar = self.empty_subtree_scalar(depth + 1);
        let mut coeffs = Vec::with_capacity(VERKLE_RADIX);

        for child_index in 0..VERKLE_RADIX {
            let mut child_path = path.to_vec();
            child_path.push(child_index as u8);
            let child_scalar = if self.node_exists(&child_path) {
                let child_root = self.compute_node_root_hash(&child_path, depth + 1)?;
                <EdwardsProjective as Group>::ScalarField::from_le_bytes_mod_order(&child_root)
            } else {
                empty_scalar
            };
            coeffs.push(child_scalar);
        }

        let poly = DensePolynomial::from_coefficients_vec(coeffs);
        self.pc.commit(&poly)
            .map_err(|e| CoreError::PolynomialCommitmentError(format!("Failed to commit node polynomial: {}", e)))
    }

    fn compute_empty_subtree_constants(
        pc: &PolynomialCommitment,
    ) -> EmptySubtreeConstantsResult {
        let mut roots = vec![[0u8; 32]; KEY_SIZE + 1];
        let mut scalars = vec![<EdwardsProjective as Group>::ScalarField::ZERO; KEY_SIZE + 1];

        let empty_commitment = pc.commit(&DensePolynomial::from_coefficients_vec(vec![]))
            .map_err(|e| CoreError::PolynomialCommitmentError(format!("Failed to commit empty polynomial: {}", e)))?;
        roots[KEY_SIZE] = Self::commitment_root_hash(&empty_commitment)?;
        scalars[KEY_SIZE] = <EdwardsProjective as Group>::ScalarField::from_le_bytes_mod_order(&roots[KEY_SIZE]);

        for depth in (0..KEY_SIZE).rev() {
            let child_scalar = scalars[depth + 1];
            let coeffs = vec![child_scalar; VERKLE_RADIX];
            let polynomial = DensePolynomial::from_coefficients_vec(coeffs);
            let commitment = pc.commit(&polynomial)
                .map_err(|e| CoreError::PolynomialCommitmentError(format!("Failed to commit subtree polynomial: {}", e)))?;
            roots[depth] = Self::commitment_root_hash(&commitment)?;
            scalars[depth] = <EdwardsProjective as Group>::ScalarField::from_le_bytes_mod_order(&roots[depth]);
        }

        Ok((roots, scalars))
    }

    fn empty_subtree_root_hash(&self, depth: usize) -> [u8; 32] {
        self.empty_subtree_roots[depth]
    }

    fn empty_subtree_scalar(&self, depth: usize) -> <EdwardsProjective as Group>::ScalarField {
        self.empty_subtree_scalars[depth]
    }

    fn compute_node_root_hash(&self, path: &[u8], depth: usize) -> Result<[u8; 32], CoreError> {
        let commitment = self.compute_node_commitment(path, depth)?;
        Self::commitment_root_hash(&commitment)
    }

    fn commitment_root_hash(commitment: &Commitment) -> Result<[u8; 32], CoreError> {
        let mut bytes = Vec::new();
        commitment
            .0
            .serialize_uncompressed(&mut bytes)
            .map_err(|e| CoreError::SerializationError(format!("Failed to serialize commitment: {}", e)))?;

        let hash = blake3::hash(&bytes);
        Ok(*hash.as_bytes())
    }

    fn value_to_scalar(value: &[u8]) -> <EdwardsProjective as Group>::ScalarField {
        let hash = blake3::hash(value);
        <EdwardsProjective as Group>::ScalarField::from_le_bytes_mod_order(hash.as_bytes())
    }
}

impl<S: Storage + Clone> Clone for VerkleTree<S> {
    fn clone(&self) -> Self {
        let mut cloned = VerkleTree::new(self.storage_clone()).expect("failed to clone VerkleTree");
        cloned.pruned_keys = self.pruned_keys.clone();
        cloned.empty_subtree_roots = self.empty_subtree_roots.clone();
        cloned.empty_subtree_scalars = self.empty_subtree_scalars.clone();
        cloned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::state::MemoryStorage;

    #[test]
    fn test_vtrie_insert_and_root_stability() {
        let storage = MemoryStorage::new();
        let mut tree = VerkleTree::new(storage).expect("failed to create VerkleTree");

        let key = [1u8; KEY_SIZE];
        let value = b"hello".to_vec();

        tree.insert(key, value.clone());
        let root1 = tree.get_root().expect("failed to get root");
        assert_ne!(root1, [0u8; 32]);

        tree.insert(key, value);
        let root2 = tree.get_root().expect("failed to get root");
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_vtrie_generate_and_verify_proof() {
        let storage = MemoryStorage::new();
        let mut tree = VerkleTree::new(storage).expect("failed to create VerkleTree");

        let key = [10u8; KEY_SIZE];
        let value = b"verkle".to_vec();

        tree.insert(key, value.clone());

        let proof = tree.generate_proof(key).expect("failed to generate proof");

        assert_eq!(proof.leaf_value, Some(value));
        assert_eq!(proof.proof_type, ProofType::Membership);
        let is_valid = tree.verify_proof(&proof).expect("failed to verify proof");
        assert!(is_valid);
    }

    #[test]
    fn test_vtrie_non_membership_proof() {
        let storage = MemoryStorage::new();
        let mut tree = VerkleTree::new(storage).expect("failed to create VerkleTree");

        let inserted_key = [10u8; KEY_SIZE];
        let inserted_value = b"verkle".to_vec();
        tree.insert(inserted_key, inserted_value);

        let missing_key = [11u8; KEY_SIZE];
        let proof = tree.generate_proof(missing_key).expect("failed to generate proof");

        assert_eq!(proof.leaf_value, None);
        assert_eq!(proof.proof_type, ProofType::NonMembership);
        let is_valid = tree.verify_proof(&proof).expect("failed to verify proof");
        assert!(is_valid);
    }

    #[test]
    fn test_vtrie_invalid_proof_modified_root_hash() {
        let storage = MemoryStorage::new();
        let mut tree = VerkleTree::new(storage).expect("failed to create VerkleTree");

        let key = [20u8; KEY_SIZE];
        tree.insert(key, b"value".to_vec());

        let mut proof = tree.generate_proof(key).expect("failed to generate proof");
        proof.root[0] ^= 0xFF;

        let is_valid = tree.verify_proof(&proof).expect("failed to verify proof");
        assert!(!is_valid);
    }

    #[test]
    fn test_vtrie_invalid_proof_modified_path() {
        let storage = MemoryStorage::new();
        let mut tree = VerkleTree::new(storage).expect("failed to create VerkleTree");

        let key = [30u8; KEY_SIZE];
        tree.insert(key, b"value".to_vec());

        let mut proof = tree.generate_proof(key).expect("failed to generate proof");
        proof.path[0] = proof.path[0].wrapping_add(1);

        let is_valid = tree.verify_proof(&proof).expect("failed to verify proof");
        assert!(!is_valid);
    }

    #[test]
    fn test_vtrie_invalid_siblings_length() {
        let storage = MemoryStorage::new();
        let mut tree = VerkleTree::new(storage).expect("failed to create VerkleTree");

        let key = [40u8; KEY_SIZE];
        tree.insert(key, b"value".to_vec());

        let mut proof = tree.generate_proof(key).expect("failed to generate proof");
        proof.siblings.pop();

        let is_valid = tree.verify_proof(&proof).expect("failed to verify proof");
        assert!(!is_valid);
    }
}
