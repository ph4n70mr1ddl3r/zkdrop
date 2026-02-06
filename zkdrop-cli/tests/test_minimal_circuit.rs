//! Minimal circuit test to debug constraint satisfaction

use ark_bn254::Fr as Fr254;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, eq::EqGadget};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use zkdrop_cli::{
    merkle::MerkleTree,
    poseidon::{poseidon_hash_arity2_circuit, address_to_field_element, compute_leaf},
};

/// Minimal circuit: just verify a Merkle path
#[derive(Clone)]
struct MinimalMerkleCircuit {
    tree_height: usize,
    leaf: Option<Fr254>,
    merkle_path: Vec<Fr254>,
    path_indices: Vec<bool>,
    merkle_root: Option<Fr254>,
}

impl MinimalMerkleCircuit {
    fn new(tree_height: usize) -> Self {
        Self {
            tree_height,
            leaf: None,
            merkle_path: Vec::new(),
            path_indices: Vec::new(),
            merkle_root: None,
        }
    }

    fn with_witness(
        mut self,
        leaf: Fr254,
        merkle_path: Vec<Fr254>,
        path_indices: Vec<bool>,
        merkle_root: Fr254,
    ) -> Self {
        self.leaf = Some(leaf);
        self.merkle_path = merkle_path;
        self.path_indices = path_indices;
        self.merkle_root = Some(merkle_root);
        self
    }
}

impl ConstraintSynthesizer<Fr254> for MinimalMerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr254>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let merkle_root_var = FpVar::new_input(cs.clone(), || {
            self.merkle_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Allocate leaf as witness
        let leaf_var = FpVar::new_witness(cs.clone(), || {
            self.leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Allocate merkle path siblings
        let mut path_vars = Vec::new();
        for i in 0..self.tree_height {
            let sibling = FpVar::new_witness(cs.clone(), || {
                Ok(self.merkle_path[i])
            })?;
            path_vars.push(sibling);
        }
        
        // Hash leaf with 0 to get tree leaf
        let zero_var = FpVar::Constant(Fr254::from(0u64));
        let mut current_var = poseidon_hash_arity2_circuit(&leaf_var, &zero_var)?;
        
        // Verify Merkle path
        for i in 0..self.tree_height {
            let is_right = self.path_indices.get(i).copied().unwrap_or(false);
            let (left, right) = if is_right {
                (&path_vars[i], &current_var)
            } else {
                (&current_var, &path_vars[i])
            };
            current_var = poseidon_hash_arity2_circuit(left, right)?;
        }
        
        // Enforce computed root matches public input
        current_var.enforce_equal(&merkle_root_var)?;
        
        Ok(())
    }
}

#[test]
fn test_minimal_merkle_circuit() {
    println!("\n=== Minimal Merkle Circuit Test ===\n");
    
    let mut rng = ChaCha8Rng::from_seed([42u8; 32]);
    let tree_height = 4usize;
    let num_leaves = 1 << tree_height;
    
    // Build tree with simple addresses
    let addresses: Vec<[u8; 20]> = (0..num_leaves).map(|i| {
        let mut addr = [0u8; 20];
        addr[19] = i as u8;
        addr
    }).collect();
    
    let leaves: Vec<Fr254> = addresses.iter()
        .map(|addr| compute_leaf(address_to_field_element(*addr)))
        .collect();
    
    let tree = MerkleTree::new(leaves.clone()).expect("Failed to build tree");
    println!("Tree root: {:?}", tree.root);
    
    // Get proof for leaf 0
    let proof = tree.generate_proof(0).expect("Valid index");
    println!("Proof leaf: {:?}", proof.leaf);
    
    // Verify natively
    assert!(MerkleTree::verify_proof(&proof), "Native verification should pass");
    println!("✓ Native verification passed");
    
    // Build circuit
    let merkle_path: Vec<Fr254> = proof.path.iter().map(|p| p.sibling).collect();
    let path_indices: Vec<bool> = proof.path.iter().map(|p| p.direction == 1).collect();
    
    // Use the raw address as the leaf input to the circuit
    let address_fe = address_to_field_element(addresses[0]);
    
    let circuit = MinimalMerkleCircuit::new(tree_height)
        .with_witness(address_fe, merkle_path, path_indices, tree.root);
    
    // Generate constraints
    let cs = ConstraintSystemRef::new(ark_relations::r1cs::ConstraintSystem::new());
    circuit.generate_constraints(cs.clone()).expect("Synthesis should succeed");
    
    let num_constraints = cs.num_constraints();
    println!("Constraints: {}", num_constraints);
    
    // Check satisfaction
    match cs.is_satisfied() {
        Ok(true) => println!("✓ All constraints satisfied"),
        Ok(false) => {
            if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                println!("✗ First unsatisfied constraint: {}", unsat);
            }
            panic!("Constraints not satisfied");
        }
        Err(e) => panic!("Error checking satisfaction: {:?}", e),
    }
    
    println!("\n=== Test Passed ===\n");
}
