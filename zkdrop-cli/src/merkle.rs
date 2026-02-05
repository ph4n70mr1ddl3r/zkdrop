//! Merkle tree utilities for the airdrop eligibility list
//! 
//! Implements the tree construction rules from the design document:
//! - Binary tree with Poseidon hashing
//! - Odd-level duplication rule
//! - Canonical ordering preserved

use crate::poseidon::poseidon_hash_arity2;
use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};

/// Merkle tree structure
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Leaves (addresses as field elements)
    pub leaves: Vec<Fr254>,
    /// Tree levels (level 0 = leaves, level N = root)
    pub levels: Vec<Vec<Fr254>>,
    /// Root hash
    pub root: Fr254,
}

/// Serializable Merkle tree for JSON export
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleTreeJson {
    pub format: String,
    pub hash: String,
    pub field: String,
    pub poseidon: String,
    pub leaf_encoding: String,
    pub root: String,
    pub addresses: Vec<String>,
}

/// Merkle proof path element
#[derive(Clone, Debug)]
pub struct PathElement {
    /// Sibling hash
    pub sibling: Fr254,
    /// Direction: 0 = current is left, 1 = current is right
    pub direction: u8,
}

/// Serializable path element
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathElementJson {
    pub sibling: String,
    pub direction: u8,
}

/// Merkle proof for a leaf
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Root hash
    pub root: Fr254,
    /// Leaf value (address as field element)
    pub leaf: Fr254,
    /// Leaf index
    pub index: usize,
    /// Path from leaf to root
    pub path: Vec<PathElement>,
}

/// Serializable Merkle proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProofJson {
    pub format: String,
    pub root: String,
    pub leaf: String,
    pub index: usize,
    pub path: Vec<PathElementJson>,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of leaves
    /// 
    /// Tree construction follows the design spec:
    /// - Level-by-level construction
    /// - Odd count levels: duplicate last node
    /// - No pre-padding to power of two
    pub fn new(leaves: Vec<Fr254>) -> Result<Self, &'static str> {
        if leaves.is_empty() {
            return Err("Merkle tree must have at least one leaf");
        }

        let mut levels: Vec<Vec<Fr254>> = Vec::new();
        levels.push(leaves.clone());

        // Build tree level by level
        while levels.last().unwrap().len() > 1 {
            let current_level = levels.last().unwrap();
            let mut next_level = Vec::new();

            let mut i = 0;
            while i < current_level.len() {
                let left = current_level[i];
                
                // If odd count, duplicate the last node
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    current_level[i] // Duplicate last node
                };

                let parent = poseidon_hash_arity2(left, right);
                next_level.push(parent);

                i += 2;
            }

            levels.push(next_level);
        }

        let root = levels.last().unwrap()[0];

        Ok(MerkleTree {
            leaves,
            levels,
            root,
        })
    }

    /// Get the tree height (number of hash levels from leaf to root)
    pub fn height(&self) -> usize {
        self.levels.len() - 1
    }

    /// Generate a Merkle proof for a leaf at the given index
    pub fn generate_proof(&self, index: usize) -> Result<MerkleProof, &'static str> {
        if index >= self.leaves.len() {
            return Err("Index out of bounds");
        }

        let mut path = Vec::new();
        let mut current_index = index;

        for level in 0..self.height() {
            let level_nodes = &self.levels[level];
            let is_right = current_index % 2 == 1;
            
            // Get sibling index
            let sibling_index = if is_right {
                current_index - 1
            } else {
                // Handle odd-length levels where last node is duplicated
                if current_index + 1 < level_nodes.len() {
                    current_index + 1
                } else {
                    current_index // Sibling is the node itself (duplicated)
                }
            };

            let sibling = level_nodes[sibling_index];
            let direction = if is_right { 1 } else { 0 };

            path.push(PathElement { sibling, direction });

            // Move to parent index
            current_index /= 2;
        }

        Ok(MerkleProof {
            root: self.root,
            leaf: self.leaves[index],
            index,
            path,
        })
    }

    /// Verify a Merkle proof
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;

        for path_elem in &proof.path {
            current = if path_elem.direction == 0 {
                // Current is left, sibling is right
                poseidon_hash_arity2(current, path_elem.sibling)
            } else {
                // Current is right, sibling is left
                poseidon_hash_arity2(path_elem.sibling, current)
            };
        }

        current == proof.root
    }

    /// Convert to JSON format (zkdrop/merkle-tree-v1)
    pub fn to_json(&self, addresses: Vec<String>) -> MerkleTreeJson {
        let root_bytes = self.root.into_bigint().to_bytes_be();
        let root_hex = format!("0x{}", hex::encode(root_bytes));
        
        MerkleTreeJson {
            format: "zkdrop/merkle-tree-v1".to_string(),
            hash: "poseidon".to_string(),
            field: "bn254".to_string(),
            poseidon: "bn254-arity2-rf8-rp57-v1".to_string(),
            leaf_encoding: "eth_address_be_32".to_string(),
            root: root_hex,
            addresses,
        }
    }
}

impl MerkleProof {
    /// Convert to JSON format (zkdrop/merkle-path-v1)
    pub fn to_json(&self) -> MerkleProofJson {
        let root_bytes = self.root.into_bigint().to_bytes_be();
        let root_hex = format!("0x{}", hex::encode(root_bytes));
        
        let leaf_bytes = self.leaf.into_bigint().to_bytes_be();
        // Only take the last 20 bytes for the address
        let leaf_hex = if leaf_bytes.len() >= 20 {
            format!("0x{}", hex::encode(&leaf_bytes[12..32]))
        } else {
            format!("0x{}", hex::encode(leaf_bytes))
        };
        
        let path_json: Vec<PathElementJson> = self.path.iter().map(|p| {
            let sibling_bytes = p.sibling.into_bigint().to_bytes_be();
            PathElementJson {
                sibling: format!("0x{}", hex::encode(sibling_bytes)),
                direction: p.direction,
            }
        }).collect();
        
        MerkleProofJson {
            format: "zkdrop/merkle-path-v1".to_string(),
            root: root_hex,
            leaf: leaf_hex,
            index: self.index,
            path: path_json,
        }
    }
}

/// Compute tree height needed for N addresses
pub fn tree_height_for_address_count(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (n - 1).next_power_of_two().trailing_zeros() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_leaves(count: usize) -> Vec<Fr254> {
        (0..count).map(|i| Fr254::from(i as u64 + 1)).collect()
    }

    #[test]
    fn test_single_leaf_tree() {
        let leaves = create_test_leaves(1);
        let tree = MerkleTree::new(leaves).unwrap();
        
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.root, Fr254::from(1u64));
    }

    #[test]
    fn test_power_of_two_tree() {
        let leaves = create_test_leaves(4);
        let tree = MerkleTree::new(leaves).unwrap();
        
        assert_eq!(tree.height(), 2);
        
        // Verify all proofs
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(MerkleTree::verify_proof(&proof));
        }
    }

    #[test]
    fn test_odd_leaf_count() {
        let leaves = create_test_leaves(5);
        let tree = MerkleTree::new(leaves).unwrap();
        
        // Height should be 3 (2^2 = 4 < 5, so need 2^3 = 8 space)
        assert_eq!(tree.height(), 3);
        
        // Verify all proofs
        for i in 0..5 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(MerkleTree::verify_proof(&proof));
        }
    }

    #[test]
    fn test_65m_address_height() {
        let height = tree_height_for_address_count(65_000_000);
        // 2^26 = 67,108,864 > 65M
        assert_eq!(height, 26);
    }

    #[test]
    fn test_json_serialization() {
        let leaves = create_test_leaves(8);
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let proof = tree.generate_proof(3).unwrap();
        
        // Convert to JSON
        let addresses: Vec<String> = leaves.iter().enumerate().map(|(i, _)| {
            format!("0x{:040x}", i + 1)
        }).collect();
        
        let tree_json = tree.to_json(addresses);
        let proof_json = proof.to_json();
        
        // Serialize to JSON string
        let tree_str = serde_json::to_string_pretty(&tree_json).unwrap();
        let proof_str = serde_json::to_string_pretty(&proof_json).unwrap();
        
        // Verify format strings
        assert_eq!(tree_json.format, "zkdrop/merkle-tree-v1");
        assert_eq!(proof_json.format, "zkdrop/merkle-path-v1");
        
        // Check JSON output has expected fields
        assert!(tree_str.contains("merkle-tree-v1"));
        assert!(proof_str.contains("merkle-path-v1"));
    }

    #[test]
    fn test_direction_bits_match_index() {
        // For index 5 (binary 101), directions should be [1, 0, 1]
        let leaves = create_test_leaves(8);
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(5).unwrap();
        
        assert_eq!(proof.path[0].direction, 1); // LSB
        assert_eq!(proof.path[1].direction, 0);
        assert_eq!(proof.path[2].direction, 1); // MSB
    }
}
