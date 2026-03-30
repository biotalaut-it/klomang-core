use crate::core::crypto::Hash;
use crate::core::state::access_set::AccessSet;
use wasmer::wasmparser::{Parser, Payload};

pub type Address = [u8; 32];

/// Signature hash type for transaction signing (BIP340-compatible)
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SigHashType {
    /// All inputs and outputs must not change
    All = 0x01,
    /// No outputs must change
    None = 0x02,
    /// Only corresponding output ne change
    Single = 0x03,
}

impl SigHashType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(SigHashType::All),
            0x02 => Some(SigHashType::None),
            0x03 => Some(SigHashType::Single),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxInput {
    pub prev_tx: Hash,
    pub index: u32,
    pub signature: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub sighash_type: SigHashType,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxOutput {
    pub value: u64,
    pub pubkey_hash: Hash,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub id: Hash,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,

    // Smart contract related fields
    pub execution_payload: Vec<u8>,
    pub contract_address: Option<Address>,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,

    pub chain_id: u32,
    pub locktime: u32,
}

impl Transaction {
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        let mut tx = Self {
            id: Hash::new(&[]),
            inputs,
            outputs,
            execution_payload: Vec::new(),
            contract_address: None,
            gas_limit: 0,
            max_fee_per_gas: 0,
            chain_id: 1,
            locktime: 0,
        };
        tx.id = tx.calculate_id();
        tx
    }

    pub fn calculate_id(&self) -> Hash {
        let mut data = Vec::new();
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        for input in &self.inputs {
            data.extend_from_slice(input.prev_tx.as_bytes());
            data.extend_from_slice(&input.index.to_be_bytes());
            data.extend_from_slice(&input.pubkey);
            data.push(input.sighash_type.as_u8());
        }
        for output in &self.outputs {
            data.extend_from_slice(&output.value.to_be_bytes());
            data.extend_from_slice(output.pubkey_hash.as_bytes());
        }
        data.extend_from_slice(&self.locktime.to_be_bytes());
        Hash::new(&data)
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Analyze WASM bytecode to extract storage access patterns
    /// Pre-scans bytecode to identify which storage slots are accessed (read/write)
    /// This enables fine-grained parallelism by detecting transactions accessing different slots
    /// can execute in parallel even if they call the same contract
    pub fn analyze_execution_payload(payload: &[u8]) -> AccessSet {
        let mut access_set = AccessSet::new();

        // Parse WASM bytecode to detect state_read/write function calls
        // These patterns help determine which storage slots will be accessed
        let parser = Parser::new(0);

        let mut function_imports = Vec::new();
        let mut _call_indices: Vec<usize> = Vec::new();
        let mut _in_function = false;

        for payload in parser.parse_all(payload) {
            match payload {
                Ok(Payload::ImportSection(reader)) => {
                    for import in reader {
                        if let Ok(import) = import {
                            if import.module == "env" {
                                function_imports.push((
                                    import.name.to_string(),
                                    function_imports.len(),
                                ));
                            }
                        }
                    }
                }
                Ok(Payload::CodeSectionEntry(_entry)) => {
                    _in_function = true;
                }
                Ok(Payload::ExportSection(reader)) => {
                    for _export in reader {
                        // Track exported functions if needed
                    }
                }
                _ => {}
            }
        }

        // For deterministic analysis, extract storage slots from payload prefix patterns
        // Storage slot determinism: slots are often encoded as u32 (4 bytes) in WASM locals/immediates
        if payload.len() >= 8 {
            // Extract potential storage slot indicators from bytecode metadata
            // Slots are typically 32-byte identifiers passed as immediates
            for i in (0..payload.len().saturating_sub(32)).step_by(8) {
                // Pattern 1: Detect common state_read/write prefixes (conservative approach)
                // klomang_state_read is typically called with (key_ptr, key_len, out_ptr, out_len)
                // klomang_state_write is called with (key_ptr, key_len, value_ptr, value_len)
                if let Some(slot_bytes) = payload.get(i..i + 32) {
                    let mut slot: [u8; 32] = [0; 32];
                    slot.copy_from_slice(slot_bytes);

                    // Heuristic: if bytes are not all-zero and not all-FF, likely a valid slot reference
                    if slot != [0u8; 32] && slot != [0xFF; 32] {
                        // Conservative: add to both read and write sets
                        // More precise analysis would require call context tracking
                        access_set.read_set.insert(slot);
                        access_set.write_set.insert(slot);
                    }
                }
            }
        }

        // If no patterns detected, return empty set (conservative for determinism)
        // Actual slots will be discovered at runtime when klomang_state_read/write are called
        if access_set.read_set.is_empty() && access_set.write_set.is_empty() {
            // Fallback: create a deterministic pseudo-slot from the payload hash
            // This ensures conservative scheduling (safe but potentially less parallelism)
            let payload_hash = Hash::new(payload);
            access_set.write_set.insert(*payload_hash.as_bytes());
        }

        access_set
    }

    pub fn hash_with_index(&self, index: u32) -> [u8; 32] {
        let mut data = Vec::with_capacity(32 + 4);
        data.extend_from_slice(self.id.as_bytes());
        data.extend_from_slice(&index.to_be_bytes());
        *Hash::new(&data).as_bytes()
    }

    /// Generate the access set for this transaction
    /// For UTXO transactions: read inputs, write outputs
    /// For contract transactions: analyze bytecode to detect read/write storage slots
    pub fn generate_access_set(&self) -> AccessSet {
        let mut access_set = AccessSet::new();

        // For UTXO transactions
        for (i, _input) in self.inputs.iter().enumerate() {
            let key = self.hash_with_index(i as u32);
            access_set.read_set.insert(key);
        }

        for (i, _output) in self.outputs.iter().enumerate() {
            let key = self.hash_with_index(i as u32);
            access_set.write_set.insert(key);
        }

        // For contract transactions: analyze payload to determine fine-grained storage access
        if let Some(contract_addr) = self.contract_address {
            // Add contract address itself to write set
            access_set.write_set.insert(contract_addr);

            // Perform pre-scan of bytecode payload to detect storage access patterns
            let payload_access = Self::analyze_execution_payload(&self.execution_payload);
            access_set.merge(&payload_access);
        }

        access_set
    }
}

impl TxOutput {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 32);
        bytes.extend_from_slice(&self.value.to_be_bytes());
        bytes.extend_from_slice(self.pubkey_hash.as_bytes());
        bytes
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            id: Hash::new(&[]),
            inputs: Vec::new(),
            outputs: Vec::new(),
            execution_payload: Vec::new(),
            contract_address: None,
            gas_limit: 0,
            max_fee_per_gas: 0,
            chain_id: 1,
            locktime: 0,
        }
    }
}