use crate::core::crypto::Hash;
use crate::core::dag::dag::Dag;
use std::collections::HashSet;

pub fn get_anticone(dag: &Dag, id: &Hash) -> Vec<Hash> {
    let ancestors: HashSet<Hash> = dag.get_ancestors(id).into_iter().collect();
    let descendants: HashSet<Hash> = dag.get_descendants(id).into_iter().collect();
    
    // Deterministic iteration: sort before filtering
    let all_hashes = dag.get_all_hashes();
    let mut anticone = Vec::new();
    
    for hash in all_hashes {
        if hash != *id && !ancestors.contains(&hash) && !descendants.contains(&hash) {
            anticone.push(hash);
        }
    }
    
    anticone  // Already sorted from get_all_hashes()
}