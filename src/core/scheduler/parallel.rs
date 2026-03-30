use std::collections::{VecDeque};
use rayon::prelude::*;
use crate::core::state::transaction::Transaction;
use crate::core::state::access_set::AccessSet;
use crate::core::crypto::Hash;

/// Represents a transaction with its access set for scheduling
#[derive(Clone)]
pub struct ScheduledTransaction {
    pub tx: Transaction,
    pub access_set: AccessSet,
    pub index: usize, // For deterministic ordering
}

/// Parallel scheduler for transaction execution
pub struct ParallelScheduler;

impl ParallelScheduler {
    /// Schedule transactions into parallelizable groups
    /// Returns a vector of groups, where each group can be executed in parallel
    pub fn schedule_transactions(txs: Vec<Transaction>) -> Vec<Vec<ScheduledTransaction>> {
        let mut scheduled: Vec<ScheduledTransaction> = txs
            .into_iter()
            .enumerate()
            .map(|(i, tx)| ScheduledTransaction {
                access_set: tx.generate_access_set(),
                tx,
                index: i,
            })
            .collect();

        // Sort by index for deterministic ordering
        scheduled.sort_by_key(|s| s.index);

        let mut groups = Vec::new();
        let mut remaining: VecDeque<ScheduledTransaction> = scheduled.into_iter().collect();

        while !remaining.is_empty() {
            let mut current_group = Vec::new();
            let mut to_remove = Vec::new();

            // Find non-conflicting transactions
            for i in 0..remaining.len() {
                let candidate = &remaining[i];
                let conflicts = current_group.iter().any(|existing: &ScheduledTransaction| {
                    existing.access_set.has_conflict(&candidate.access_set)
                });

                if !conflicts {
                    current_group.push(candidate.clone());
                    to_remove.push(i);
                }
            }

            // Remove selected transactions from remaining
            for &idx in to_remove.iter().rev() {
                remaining.remove(idx);
            }

            if current_group.is_empty() {
                // If no non-conflicting found, take the first one
                current_group.push(remaining.pop_front().unwrap());
            }

            groups.push(current_group);
        }

        groups
    }

    /// Execute scheduled groups in parallel
    /// This is a placeholder - actual execution would integrate with StateManager
    pub fn execute_groups<F>(groups: Vec<Vec<ScheduledTransaction>>, executor: F) -> Result<(), String>
    where
        F: Fn(&Transaction) -> Result<(), String> + Send + Sync,
    {
        for group in groups {
            // Execute group in parallel
            let results: Vec<Result<(), String>> = group
                .par_iter()
                .map(|scheduled| executor(&scheduled.tx))
                .collect();

            // Check for errors
            for result in results {
                result?;
            }
        }

        Ok(())
    }
}

/// Canonical ordering based on DAG timestamp and hash
pub fn canonical_order_key(tx: &Transaction, timestamp: u64) -> (u64, Hash) {
    (timestamp, tx.id.clone())
}