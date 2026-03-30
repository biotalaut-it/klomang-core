use std::collections::{HashSet, HashMap};
use crate::core::crypto::Hash;
use crate::core::dag::Dag;

#[derive(Debug, Clone)]
pub struct VirtualBlock {
    pub parents: HashSet<Hash>,
    pub selected_parent: Option<Hash>,
    pub blue_set: HashSet<Hash>,
    pub red_set: HashSet<Hash>,
    pub blue_score: u64,
}

#[derive(Debug, Clone)]
pub struct GhostDag {
    pub k: usize,
}

impl GhostDag {
    pub fn new(k: usize) -> Self {
        Self { k }
    }

    pub fn select_parent(&self, dag: &Dag, parents: &[Hash]) -> Option<Hash> {
        if parents.is_empty() {
            return None;
        }
        
        // Max 2 parents: select only two with highest blue_score
        let mut parent_scores: Vec<_> = parents
            .iter()
            .filter_map(|h| dag.get_block(h).map(|b| (h.clone(), b.blue_score)))
            .collect();
        
        // Sort by blue_score descending, then by hash ascending (deterministic)
        parent_scores.sort_by(|(h1, s1), (h2, s2)| s2.cmp(s1).then(h1.cmp(h2)));
        
        // Return highest score parent
        parent_scores.first().map(|(h, _)| h.clone())
    }

    pub fn anticone(&self, dag: &Dag, block: &Hash) -> Vec<Hash> {
        dag.get_anticone(block)
    }

    pub fn build_blue_set(
        &self,
        dag: &Dag,
        selected_parent: &Hash,
        _parents: &[Hash],
    ) -> (HashSet<Hash>, HashSet<Hash>) {
        let mut blue_set = HashSet::new();
        let mut red_set = HashSet::new();

        if let Some(parent_block) = dag.get_block(selected_parent) {
            blue_set.extend(parent_block.blue_set.iter().cloned());
            blue_set.insert(selected_parent.clone());
        }

        // Get anticone and convert to HashSet for k-cluster check
        let candidates = self.anticone(dag, selected_parent);
        // Already sorted from anticone, so iteration is deterministic
        
        for candidate in candidates {
            let candidate_anticone: HashSet<Hash> = self.anticone(dag, &candidate).into_iter().collect();
            let conflicts = candidate_anticone.intersection(&blue_set).count();
            if conflicts <= self.k {
                blue_set.insert(candidate);
            } else {
                red_set.insert(candidate);
            }
        }

        (blue_set, red_set)
    }

    pub fn recompute_block(&self, dag: &mut Dag, hash: &Hash) -> bool {
        let block = match dag.get_block(hash) {
            Some(b) => b.clone(),
            None => return false,
        };

        if block.parents.is_empty() {
            return false;
        }

        for parent in &block.parents {
            if dag.get_block(parent).is_none() {
                return false;
            }
        }

        // Convert HashSet to Vec for deterministic processing
        let parents_vec: Vec<Hash> = {
            let mut v: Vec<_> = block.parents.iter().cloned().collect();
            v.sort();
            v
        };

        let selected_parent = match self.select_parent(dag, &parents_vec) {
            Some(p) => p,
            None => return false,
        };

        let (blue_set, red_set) = self.build_blue_set(dag, &selected_parent, &parents_vec);
        let parent_score = dag
            .get_block(&selected_parent)
            .map(|b| b.blue_score)
            .unwrap_or(0);
        let blue_score = parent_score + (blue_set.len() as u64);

        if let Some(stored) = dag.get_block_mut(hash) {
            if stored.selected_parent == Some(selected_parent.clone())
                && stored.blue_set == blue_set
                && stored.red_set == red_set
                && stored.blue_score == blue_score
            {
                return false;
            }

            stored.selected_parent = Some(selected_parent);
            stored.blue_set = blue_set;
            stored.red_set = red_set;
            stored.blue_score = blue_score;
            return true;
        }

        false
    }

    pub fn build_virtual_block(&self, dag: &Dag) -> VirtualBlock {
        let tips = dag.get_tips();

        if dag.get_all_hashes().is_empty() {
            return VirtualBlock {
                parents: HashSet::new(),
                selected_parent: None,
                blue_set: HashSet::new(),
                red_set: HashSet::new(),
                blue_score: 0,
            };
        }

        if dag.get_all_hashes().len() == 1 {
            // Safe to unwrap because we just checked len() == 1
            if let Some(only_block_hash) = dag.get_all_hashes().first() {
                let only_block_hash = only_block_hash.clone();
                if let Some(b) = dag.get_block(&only_block_hash) {
                    return VirtualBlock {
                        parents: tips.into_iter().collect(),
                        selected_parent: b.selected_parent.clone(),
                        blue_set: b.blue_set.clone(),
                        red_set: b.red_set.clone(),
                        blue_score: b.blue_score,
                    };
                }
            }
        }

        let selected_parent = self.select_parent(dag, &tips);
        if let Some(selected_parent) = selected_parent {
            let (blue_set, red_set) = self.build_blue_set(dag, &selected_parent, &tips);
            let parent_score = dag.get_block(&selected_parent).map(|b| b.blue_score).unwrap_or(0);
            let blue_score = parent_score + (blue_set.len() as u64);

            VirtualBlock {
                parents: tips.into_iter().collect(),
                selected_parent: Some(selected_parent),
                blue_set,
                red_set,
                blue_score,
            }
        } else {
            VirtualBlock {
                parents: tips.into_iter().collect(),
                selected_parent: None,
                blue_set: HashSet::new(),
                red_set: HashSet::new(),
                blue_score: 0,
            }
        }
    }

    pub fn get_virtual_selected_chain(&self, dag: &Dag) -> Vec<Hash> {
        let v = self.build_virtual_block(dag);
        let mut chain = Vec::new();
        let mut current = v.selected_parent;

        while let Some(parent_hash) = current {
            chain.push(parent_hash.clone());
            current = dag.get_block(&parent_hash).and_then(|b| b.selected_parent.clone());
        }

        chain.reverse();
        chain
    }

    pub fn get_virtual_ordering(&self, dag: &Dag) -> Vec<Hash> {
        let mut ordering: Vec<_> = dag.get_all_hashes().into_iter().collect();
        ordering.sort_by(|a, b| {
            let a_score = dag.get_block(a).map_or(0, |block| block.blue_score);
            let b_score = dag.get_block(b).map_or(0, |block| block.blue_score);
            a_score.cmp(&b_score).then(a.cmp(b))
        });
        ordering
    }

    pub fn topological_sort(&self, dag: &Dag, nodes: &[Hash]) -> Vec<Hash> {
        let node_set: HashSet<Hash> = nodes.iter().cloned().collect();
        let mut indegree: HashMap<Hash, usize> = HashMap::new();

        for hash in nodes {
            let degree = dag
                .get_block(hash)
                .map(|block| {
                    block
                        .parents
                        .iter()
                        .filter(|p| node_set.contains(p))
                        .count()
                })
                .unwrap_or(0);
            indegree.insert(hash.clone(), degree);
        }

        let mut queue: Vec<Hash> = indegree
            .iter()
            .filter_map(|(h, d)| if *d == 0 { Some(h.clone()) } else { None })
            .collect();
        queue.sort();

        let mut sorted = Vec::new();

        while let Some(current) = queue.pop() {
            sorted.push(current.clone());
            if let Some(block) = dag.get_block(&current) {
                let mut children: Vec<_> = block
                    .children
                    .iter()
                    .filter(|c| node_set.contains(c))
                    .cloned()
                    .collect();
                children.sort();
                for child in children {
                    if let Some(deg) = indegree.get_mut(&child) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push(child.clone());
                        }
                    }
                }
            }
        }

        sorted
    }

    pub fn process_block(&self, dag: &mut Dag, block_hash: &Hash) {
        let block = match dag.get_block(block_hash) {
            Some(b) => b.clone(),
            None => return,
        };

        if block.parents.is_empty() {
            if let Some(stored) = dag.get_block_mut(block_hash) {
                stored.selected_parent = None;
                stored.blue_set = HashSet::new();
                stored.red_set = HashSet::new();
                stored.blue_score = 1;
            }
        } else {
            self.recompute_block(dag, block_hash);
        }

        // Affected area should include all descendants of all parents, and the block itself
        let mut affected_set = HashSet::new();
        for parent in &block.parents {
            affected_set.insert(parent.clone());
            for child in dag.get_descendants(parent) {
                affected_set.insert(child);
            }
        }

        let affected: Vec<Hash> = affected_set.into_iter().collect();
        let sorted_descendants = self.topological_sort(dag, &affected);

        for descendant in sorted_descendants {
            self.recompute_block(dag, &descendant);
        }
    }

    pub fn get_blue_set(&self, dag: &Dag, hash: &Hash) -> HashSet<Hash> {
        dag.get_block(hash)
            .map(|block| block.blue_set.clone())
            .unwrap_or_default()
    }

    pub fn get_red_set(&self, dag: &Dag, hash: &Hash) -> HashSet<Hash> {
        dag.get_block(hash)
            .map(|block| block.red_set.clone())
            .unwrap_or_default()
    }

    pub fn get_virtual_block(&self, dag: &Dag) -> Option<Hash> {
        dag.get_all_hashes()
            .into_iter()
            .filter_map(|hash| {
                dag.get_block(&hash).map(|block| (hash, block.blue_score))
            })
            .max_by(|(h1, s1), (h2, s2)| s1.cmp(s2).then(h2.cmp(h1)))
            .map(|(hash, _)| hash)
    }

    /// Check if a block/transaction is final (irreversible)
    /// A block is considered final if its blue score is below the virtual blue score by a certain threshold
    pub fn check_finality(&self, dag: &Dag, block_hash: &Hash, finality_threshold: u64) -> bool {
        let virtual_block = self.build_virtual_block(dag);
        let block_blue_score = dag.get_block(block_hash)
            .map(|b| b.blue_score)
            .unwrap_or(0);

        virtual_block.blue_score.saturating_sub(block_blue_score) >= finality_threshold
    }
}

impl Default for GhostDag {
    fn default() -> Self {
        Self::new(1)
    }
}
