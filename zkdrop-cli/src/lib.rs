//! ZK Drop - Privacy-preserving airdrop proof generation
//! 
//! This library provides circuits and utilities for generating ZK proofs
//! for the privacy airdrop token design.

use ark_bn254::{Bn254, Fr as Fr254};
use ark_groth16::Groth16;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

pub mod circuit;
pub mod keccak;
pub mod merkle;
pub mod poseidon;
pub mod secp256k1;

/// Public inputs for the claim proof (matches contract expectations)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Merkle root as field element
    pub merkle_root: String,
    /// Nullifier as field element
    pub nullifier: String,
    /// Recipient address (160-bit) as field element
    pub recipient: String,
}

/// Proof output format (zkdrop/proof-v1)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOutput {
    pub format: String,
    pub proof: String,
    pub public_inputs: Vec<String>,
}

/// Test circuit for benchmarking proving times with configurable Merkle tree height
/// 
/// This is a simplified circuit that tests the proving time scaling
/// with respect to Merkle tree height.
#[derive(Clone)]
pub struct TestMerkleCircuit {
    /// Height of the Merkle tree
    pub tree_height: usize,
    /// Leaf value (private)
    pub leaf: Option<Fr254>,
    /// Merkle path siblings (private)
    pub path: Vec<Option<Fr254>>,
    /// Path indices as bits (private)
    pub indices: Vec<Option<bool>>,
    /// Expected root (public)
    pub root: Option<Fr254>,
}

impl TestMerkleCircuit {
    pub fn new(tree_height: usize) -> Self {
        Self {
            tree_height,
            leaf: None,
            path: vec![None; tree_height],
            indices: vec![None; tree_height],
            root: None,
        }
    }

    pub fn with_witness(
        mut self,
        leaf: Fr254,
        path: Vec<Fr254>,
        indices: Vec<bool>,
        root: Fr254,
    ) -> Self {
        assert_eq!(path.len(), self.tree_height);
        assert_eq!(indices.len(), self.tree_height);
        self.leaf = Some(leaf);
        self.path = path.into_iter().map(Some).collect();
        self.indices = indices.into_iter().map(Some).collect();
        self.root = Some(root);
        self
    }
}

impl ConstraintSynthesizer<Fr254> for TestMerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr254>) -> Result<(), SynthesisError> {
        // Allocate public input: root
        let root_var = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate private inputs
        let mut current = FpVar::new_witness(cs.clone(), || {
            self.leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Process each level of the Merkle path
        for i in 0..self.tree_height {
            let sibling = FpVar::new_witness(cs.clone(), || {
                self.path[i].ok_or(SynthesisError::AssignmentMissing)
            })?;

            let is_right = self.indices[i].ok_or(SynthesisError::AssignmentMissing)?;

            // Use Poseidon hash
            let (left, right) = if is_right {
                (&sibling, &current)
            } else {
                (&current, &sibling)
            };
            
            current = crate::poseidon::poseidon_hash_arity2_circuit(left, right)?;
        }

        // Enforce computed root matches public input
        root_var.enforce_equal(&current)?;

        Ok(())
    }
}

/// Generate setup parameters for Groth16
pub fn generate_setup<C: ConstraintSynthesizer<Fr254>>(
    circuit: C,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ark_groth16::ProvingKey<Bn254>, ark_groth16::VerifyingKey<Bn254>), Box<dyn std::error::Error>> {
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)?;
    Ok((pk, vk))
}

/// Generate a proof with timing
pub fn generate_proof<C: ConstraintSynthesizer<Fr254>>(
    circuit: C,
    pk: &ark_groth16::ProvingKey<Bn254>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<ark_groth16::Proof<Bn254>, Box<dyn std::error::Error>> {
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok(proof)
}

/// Verify a proof
pub fn verify_proof(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    public_inputs: &[Fr254],
    proof: &ark_groth16::Proof<Bn254>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let result = Groth16::<Bn254>::verify(vk, public_inputs, proof)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    #[test]
    fn test_circuit_synthesis() {
        let mut rng = ChaCha8Rng::from_seed([42u8; 32]);
        let tree_height = 10;
        
        // Generate witness
        let leaf = Fr254::rand(&mut rng);
        let path: Vec<Fr254> = (0..tree_height).map(|_| Fr254::rand(&mut rng)).collect();
        let indices: Vec<bool> = (0..tree_height).map(|i| (i % 2) == 0).collect();
        
        // Compute expected root using proper Poseidon hash
        let mut current = leaf;
        for i in 0..tree_height {
            let (left, right) = if indices[i] {
                (path[i], current)
            } else {
                (current, path[i])
            };
            current = crate::poseidon::poseidon_hash_arity2(left, right);
        }
        let root = current;
        
        let circuit = TestMerkleCircuit::new(tree_height)
            .with_witness(leaf, path, indices, root);
            
        let cs = ConstraintSystemRef::new(ark_relations::r1cs::ConstraintSystem::new());
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_full_proof_lifecycle() {
        use ark_serialize::CanonicalSerialize;

        let mut rng = ChaCha8Rng::from_seed([43u8; 32]);
        let tree_height = 4;
        
        // Generate witness
        let leaf = Fr254::rand(&mut rng);
        let path: Vec<Fr254> = (0..tree_height).map(|_| Fr254::rand(&mut rng)).collect();
        let indices: Vec<bool> = (0..tree_height).map(|i| (i % 2) == 0).collect();
        
        // Compute root
        let mut current = leaf;
        for i in 0..tree_height {
            let (left, right) = if indices[i] {
                (path[i], current)
            } else {
                (current, path[i])
            };
            current = crate::poseidon::poseidon_hash_arity2(left, right);
        }
        let root = current;
        
        let circuit = TestMerkleCircuit::new(tree_height)
            .with_witness(leaf, path, indices, root);
        
        // Generate setup
        let (pk, vk) = generate_setup(circuit.clone(), &mut rng).unwrap();
        
        // Generate proof
        let proof = generate_proof(circuit, &pk, &mut rng).unwrap();
        
        // Serialize proof
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        
        // Verify
        let is_valid = verify_proof(&vk, &[root], &proof).unwrap();
        assert!(is_valid);
        
        println!("Proof size: {} bytes", proof_bytes.len());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::poseidon::poseidon_hash_arity2;
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    /// Test full proof lifecycle with the simplified TestMerkleCircuit
    /// This tests that the proving and verification pipeline works end-to-end
    #[test]
    fn test_merkle_proof_lifecycle() {
        use ark_serialize::CanonicalSerialize;
        
        let mut rng = ChaCha8Rng::from_seed([99u8; 32]);
        let tree_height = 4;
        
        // Generate a valid merkle tree
        let leaves: Vec<Fr254> = (0..(1 << tree_height)).map(|i| Fr254::from(i as u64)).collect();
        let tree = crate::merkle::MerkleTree::new(leaves.clone()).expect("Valid tree");
        
        // Get proof for leaf 0
        let proof = tree.generate_proof(0).expect("Valid index");
        assert!(crate::merkle::MerkleTree::verify_proof(&proof), "Native verification should pass");
        
        // Build circuit with the proof data
        let merkle_path: Vec<Fr254> = proof.path.iter().map(|p| p.sibling).collect();
        let indices: Vec<bool> = proof.path.iter().map(|p| p.direction == 1).collect();
        
        let circuit = TestMerkleCircuit::new(tree_height)
            .with_witness(proof.leaf, merkle_path, indices, tree.root);
        
        // Run the full pipeline: setup -> prove -> verify
        let (pk, vk) = generate_setup(circuit.clone(), &mut rng).expect("Setup failed");
        let proof = generate_proof(circuit, &pk, &mut rng).expect("Proof generation failed");
        
        // Verify
        let is_valid = verify_proof(&vk, &[tree.root], &proof).expect("Verification failed");
        assert!(is_valid, "Proof should be valid");
        
        // Serialize and check size
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        
        println!("✓ Full proof lifecycle test passed");
        println!("  Tree height: {}", tree_height);
        println!("  Proof size: {} bytes", proof_bytes.len());
    }
}
