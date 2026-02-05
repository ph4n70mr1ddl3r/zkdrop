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
pub mod merkle;
pub mod poseidon;

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

/// Full circuit placeholder (for architecture testing)
/// 
/// This represents the complete circuit structure that would include:
/// - secp256k1 public key derivation from private key
/// - Keccak256 hash of pubkey to get Ethereum address  
/// - Merkle inclusion proof
/// - Nullifier computation
pub struct FullAirdropCircuit {
    pub tree_height: usize,
    // Private inputs
    pub private_key: Option<Fr254>,
    pub merkle_path: Vec<Option<Fr254>>,
    pub path_indices: Vec<Option<bool>>,
    // Public inputs
    pub merkle_root: Option<Fr254>,
    pub nullifier: Option<Fr254>,
    pub recipient: Option<Fr254>,
}

impl FullAirdropCircuit {
    pub fn new(tree_height: usize) -> Self {
        Self {
            tree_height,
            private_key: None,
            merkle_path: vec![None; tree_height],
            path_indices: vec![None; tree_height],
            merkle_root: None,
            nullifier: None,
            recipient: None,
        }
    }
}

impl ConstraintSynthesizer<Fr254> for FullAirdropCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr254>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let _merkle_root = FpVar::new_input(cs.clone(), || {
            self.merkle_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _nullifier = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let _recipient = FpVar::new_input(cs.clone(), || {
            self.recipient.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate private key
        let _sk = FpVar::new_witness(cs.clone(), || {
            self.private_key.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Placeholder constraints to simulate circuit complexity
        // In the real circuit, this would be:
        // 1. secp256k1 pubkey derivation (~100k constraints)
        // 2. Keccak256 of pubkey (~25k constraints)
        // 3. Merkle path verification (~2k constraints per level)
        // 4. Nullifier computation (~1k constraints)

        // Simulate complexity with repeated operations
        let complexity_multiplier = self.tree_height * 1000 + 125000; // Base + per-level
        let mut acc = FpVar::new_witness(cs.clone(), || Ok(Fr254::from(1u64)))?;
        
        for i in 0..complexity_multiplier.min(10000) {
            let temp = FpVar::new_witness(cs.clone(), || Ok(Fr254::from(i as u64)))?;
            acc = acc.clone() * temp + acc.clone();
        }

        // Dummy constraint to use the result
        let one = FpVar::new_witness(cs, || Ok(Fr254::from(1u64)))?;
        let _ = acc.enforce_equal(&one);

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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_circuit_synthesis() {
        let mut rng = test_rng();
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
}
