//! Integration tests for proving time measurements
//! 
//! These tests measure actual proving times and can be used to:
//! 1. Validate circuit performance before deployment
//! 2. Generate reports for different circuit sizes
//! 3. Compare different optimization strategies
//!
//! Run with: cargo test proving_time -- --nocapture

use ark_bn254::{Bn254, Fr as Fr254};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_serialize::CanonicalSerialize;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::time::{Duration, Instant};
use zkdrop_cli::{
    circuit::{estimate_constraint_count, AirdropClaimCircuit, AirdropPrivateInputs, AirdropPublicInputs},
    generate_proof, generate_setup,
    merkle::tree_height_for_address_count,
};

/// Test configuration for proving time measurements
#[derive(Debug, Clone)]
struct ProvingTimeResult {
    pub tree_height: usize,
    pub max_addresses: usize,
    pub estimated_constraints: usize,
    pub setup_time: Duration,
    pub proving_time: Duration,
    pub verification_time: Duration,
    pub proof_size_bytes: usize,
}

impl ProvingTimeResult {
    fn format(&self) -> String {
        format!(
            "Height {:2} | {:>12} addrs | {:>9} constraints | Setup: {:>6}ms | Prove: {:>8}ms | Verify: {:>4}ms | Proof: {}B",
            self.tree_height,
            self.max_addresses,
            self.estimated_constraints,
            self.setup_time.as_millis(),
            self.proving_time.as_millis(),
            self.verification_time.as_millis(),
            self.proof_size_bytes
        )
    }
}

/// Build a simple test tree using the same hash as the circuit
/// Returns (leaves, levels, root)
fn build_simple_test_tree(num_leaves: usize) -> (Vec<Fr254>, Vec<Vec<Fr254>>, Fr254) {
    let leaves: Vec<Fr254> = (0..num_leaves)
        .map(|i| Fr254::from(i as u64 + 1))
        .collect();
    
    let mut levels: Vec<Vec<Fr254>> = vec![leaves.clone()];
    
    // Build tree level by level using proper Poseidon hash
    while levels.last().unwrap().len() > 1 {
        let current_level = levels.last().unwrap();
        let mut next_level = Vec::new();

        let mut i = 0;
        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                current_level[i]
            };

            // Use proper Poseidon hash
            let parent = zkdrop_cli::poseidon::poseidon_hash_arity2(left, right);
            next_level.push(parent);

            i += 2;
        }

        levels.push(next_level);
    }
    
    let root = levels.last().unwrap()[0];
    (leaves, levels, root)
}

/// Compute Merkle root manually using the proper Poseidon hash
fn compute_root_manual(leaf: Fr254, path: &[Fr254], indices: &[bool]) -> Fr254 {
    let mut current = leaf;
    for (i, sibling) in path.iter().enumerate() {
        let (left, right) = if indices[i] {
            (*sibling, current)  // sibling is left, current is right
        } else {
            (current, *sibling)  // current is left, sibling is right
        };
        
        // Use proper Poseidon hash
        current = zkdrop_cli::poseidon::poseidon_hash_arity2(left, right);
    }
    current
}

/// Generate Merkle proof for a leaf at given index
fn generate_proof_manual(
    leaves: &[Fr254], 
    levels: &[Vec<Fr254>], 
    index: usize
) -> (Fr254, Vec<Fr254>, Vec<bool>) {
    let leaf = leaves[index];
    let tree_height = levels.len() - 1;
    
    let mut path = Vec::new();
    let mut path_indices = Vec::new();
    let mut current_index = index;
    
    for level in 0..tree_height {
        let level_nodes = &levels[level];
        let is_right = current_index % 2 == 1;
        
        let sibling_index = if is_right {
            current_index - 1
        } else {
            if current_index + 1 < level_nodes.len() {
                current_index + 1
            } else {
                current_index
            }
        };
        
        path.push(level_nodes[sibling_index]);
        path_indices.push(is_right);
        current_index /= 2;
    }
    
    (leaf, path, path_indices)
}

/// Measure proving time for a specific tree height
fn measure_proving_time(tree_height: usize) -> ProvingTimeResult {
    let mut rng = ChaCha8Rng::from_entropy();
    let chain_id = 8453u64; // Base mainnet
    
    // Build simple tree with consistent hashing
    // Use actual tree height for number of leaves to ensure correct path length
    let num_leaves = 1usize << tree_height;
    let (leaves, levels, root) = build_simple_test_tree(num_leaves);
    
    // Get proof for a leaf
    let proof_index = 0;
    let (leaf, path, path_indices) = generate_proof_manual(&leaves, &levels, proof_index);
    
    // Verify our path is correct
    let computed_root = compute_root_manual(leaf, &path, &path_indices);
    assert_eq!(computed_root, root, "Merkle path should verify to root");
    
    // Prepare inputs
    let merkle_root = root;
    let private_key = Fr254::from(42u64);
    let pk_x = leaf; // Use leaf as pk_x for simplicity
    let pk_y = Fr254::rand(&mut rng);
    
    // Compute nullifier: H(chainId, merkleRoot, pkx_fe, pky_fe)
    let chain_id_fe = Fr254::from(chain_id);
    let nullifier = zkdrop_cli::poseidon::poseidon_hash_arity4([
        chain_id_fe,
        merkle_root,
        pk_x,
        pk_y,
    ]);
    let recipient = Fr254::from(0x11111111111111111111111111111111u128);
    
    let public_inputs = AirdropPublicInputs {
        merkle_root,
        nullifier,
        recipient,
    };
    
    let private_inputs = AirdropPrivateInputs {
        private_key,
        merkle_path: path.clone(),
        path_indices: path_indices.clone(),
        pk_x,
        pk_y,
    };
    
    // Create circuit
    let circuit = AirdropClaimCircuit::new(tree_height, chain_id)
        .with_witness(public_inputs.clone(), private_inputs);
    
    // Measure setup time
    let setup_start = Instant::now();
    let (pk, vk) = generate_setup(circuit.clone(), &mut rng)
        .expect("Setup should succeed");
    let setup_time = setup_start.elapsed();
    
    // Measure proving time (average of 3 runs for accuracy)
    let mut proving_times = Vec::new();
    let mut proof_size_bytes = 0;
    let mut verification_time = Duration::default();
    
    for run_idx in 0..3 {
        let prove_start = Instant::now();
        
        // Recreate circuit for each run
        let circuit_run = AirdropClaimCircuit::new(tree_height, chain_id)
            .with_witness(public_inputs.clone(), AirdropPrivateInputs {
                private_key: Fr254::from(42u64),
                merkle_path: path.clone(),
                path_indices: path_indices.clone(),
                pk_x,
                pk_y,
            });
            
        let proof = generate_proof(circuit_run, &pk, &mut rng)
            .expect("Proof generation should succeed");
        proving_times.push(prove_start.elapsed());
        
        // Keep first proof for size measurement and verification
        if run_idx == 0 {
            // Measure proof size
            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes).expect("Serialization should succeed");
            proof_size_bytes = proof_bytes.len();
            
            // Measure verification time
            let public_inputs_vec = vec![merkle_root, nullifier, recipient];
            let verify_start = Instant::now();
            Groth16::<Bn254>::verify(&vk, &public_inputs_vec, &proof)
                .expect("Verification should succeed");
            verification_time = verify_start.elapsed();
        }
    }
    
    let avg_proving_time = proving_times.iter().sum::<Duration>() / proving_times.len() as u32;
    
    ProvingTimeResult {
        tree_height,
        max_addresses: num_leaves,
        estimated_constraints: estimate_constraint_count(tree_height),
        setup_time,
        proving_time: avg_proving_time,
        verification_time,
        proof_size_bytes,
    }
}

/// Test proving times for various tree heights
/// 
/// This test generates a report showing how proving time scales with tree size.
/// Use it to estimate proving time for the full 65M address deployment.
#[test]
fn test_proving_time_scaling() {
    println!("\n╔════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                           PROVING TIME SCALING TEST                                                     ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
    
    let test_heights = vec![4, 8, 12, 16];
    let mut results = Vec::new();
    
    for height in test_heights {
        println!("Testing tree height {}...", height);
        let result = measure_proving_time(height);
        results.push(result);
    }
    
    println!("\n═══════════════════════════════════════════════════════════════════════════════════════════════════════════");
    println!("                                            RESULTS                                                        ");
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
    for result in &results {
        println!("{}", result.format());
    }
    
    // Extrapolate to target (65M addresses, height 26)
    println!("\n═══════════════════════════════════════════════════════════════════════════════════════════════════════════");
    println!("                                    EXTRAPOLATION TO TARGET (65M addresses)                                 ");
    println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
    
    if let (Some(r1), Some(r2)) = (results.get(2), results.get(3)) {
        // Linear extrapolation from heights 12 and 16
        let target_height = 26usize;
        let height_diff = r2.tree_height - r1.tree_height;
        let time_per_height = (r2.proving_time.as_millis() as f64 - r1.proving_time.as_millis() as f64) 
            / height_diff as f64;
        
        let estimated_proving_ms = r2.proving_time.as_millis() as f64 
            + time_per_height * (target_height - r2.tree_height) as f64;
        
        println!("Based on heights {} to {}:", r1.tree_height, r2.tree_height);
        println!("  Time increase per tree level: {:.2} ms", time_per_height);
        println!("  Estimated proving time at height {}: {:.0} ms ({:.1} seconds)",
            target_height, estimated_proving_ms, estimated_proving_ms / 1000.0);
        
        let estimated_constraints = estimate_constraint_count(target_height);
        println!("  Estimated constraint count: {}", estimated_constraints);
        
        // Recommendations
        println!("\n═══════════════════════════════════════════════════════════════════════════════════════════════════════════");
        println!("                                              RECOMMENDATIONS                                               ");
        println!("═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
        
        if estimated_proving_ms > 300_000.0 {
            println!("⚠️  WARNING: Estimated proving time > 5 minutes!");
            println!("   Consider:");
            println!("   - Circuit optimizations (custom Poseidon gates in arkworks)");
            println!("   - Parallel witness generation");
            println!("   - GPU acceleration (using libraries like bellperson or rapidsnark)");
        } else if estimated_proving_ms > 60_000.0 {
            println!("⚠️  Estimated proving time > 1 minute.");
            println!("   This is acceptable but users should be informed.");
        } else {
            println!("✓ Estimated proving time is acceptable (< 1 minute)");
        }
        
        println!("\nNote: This is based on a simplified circuit. Full circuit with secp256k1 + Keccak256");
        println!("      will have ~125k additional constraints, potentially increasing proving time by 2-5x.");
    }
    
    println!("\n═══════════════════════════════════════════════════════════════════════════════════════════════════════════\n");
}

/// Quick smoke test that proof generation works
#[test]
fn test_proof_generation_smoke() {
    let mut rng = ChaCha8Rng::from_entropy();
    let tree_height = 8usize;
    let chain_id = 8453u64;
    
    // Build simple tree with consistent hashing
    let num_leaves = 1usize << tree_height;
    let (leaves, levels, root) = build_simple_test_tree(num_leaves);
    
    // Generate proof for leaf 0
    let leaf_index = 0usize;
    let (leaf, path, path_indices) = generate_proof_manual(&leaves, &levels, leaf_index);
    
    // Verify our path computes the correct root
    let computed_root = compute_root_manual(leaf, &path, &path_indices);
    assert_eq!(computed_root, root, "Merkle path should verify to root");
    
    let pk_x = leaf; // Use leaf as pk_x for simplicity
    let pk_y = Fr254::rand(&mut rng);
    
    // Compute nullifier: H(chainId, merkleRoot, pkx_fe, pky_fe)
    let nullifier = zkdrop_cli::poseidon::poseidon_hash_arity4([
        Fr254::from(chain_id),
        root,
        pk_x,
        pk_y,
    ]);
    
    let public_inputs = AirdropPublicInputs {
        merkle_root: root,
        nullifier,
        recipient: Fr254::from(0x11111111111111111111111111111111u128),
    };
    
    let private_inputs = AirdropPrivateInputs {
        private_key: Fr254::from(42u64),
        merkle_path: path,
        path_indices,
        pk_x,
        pk_y,
    };
    
    let circuit = AirdropClaimCircuit::new(tree_height, chain_id)
        .with_witness(public_inputs.clone(), private_inputs);
    
    // Generate setup
    let (pk, vk) = generate_setup(circuit.clone(), &mut rng).expect("Setup should succeed");
    
    // Generate proof
    let proof = generate_proof(circuit, &pk, &mut rng).expect("Proof should succeed");
    
    // Verify
    let public_inputs_vec = vec![public_inputs.merkle_root, public_inputs.nullifier, public_inputs.recipient];
    let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs_vec, &proof).expect("Verification should succeed");
    
    assert!(is_valid, "Proof should be valid");
}

/// Test that the merkle tree height calculation is correct for 65M addresses
#[test]
fn test_65m_address_height() {
    let height = tree_height_for_address_count(65_000_000);
    
    // 2^26 = 67,108,864 > 65M
    assert_eq!(height, 26);
    
    // Verify constraint estimate
    let constraints = estimate_constraint_count(height);
    println!("Height 26 estimated constraints: {}", constraints);
    
    // Should be in the 100k+ range
    assert!(constraints > 100_000);
}
