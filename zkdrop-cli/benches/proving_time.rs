//! Proving Time Benchmarks
//! 
//! This benchmark measures the time required to:
//! 1. Generate setup parameters (trusted setup)
//! 2. Create proofs for different circuit sizes
//! 3. Verify proofs
//!
//! Run with: cargo bench --bench proving_time

use ark_bn254::{Bn254, Fr as Fr254};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;
use zkdrop_cli::{TestMerkleCircuit, generate_setup, generate_proof};

/// Build tree and generate witness for a given height
fn prepare_witness(height: usize) -> (Fr254, Vec<Fr254>, Vec<bool>, Fr254) {
    let mut rng = ChaCha8Rng::from_entropy();
    let leaf = Fr254::rand(&mut rng);
    let path: Vec<Fr254> = (0..height).map(|_| Fr254::rand(&mut rng)).collect();
    let indices: Vec<bool> = (0..height).map(|i| (i % 2) == 0).collect();
    
    // Compute root using proper Poseidon hash
    let mut current = leaf;
    for i in 0..height {
        let (left, right) = if indices[i] {
            (path[i], current)
        } else {
            (current, path[i])
        };
        current = zkdrop_cli::poseidon::poseidon_hash_arity2(left, right);
    }
    let root = current;
    
    (leaf, path, indices, root)
}

/// Benchmark the complete workflow for a circuit of given tree height
fn bench_circuit_height(c: &mut Criterion, height: usize) {
    let mut group = c.benchmark_group(format!("proving_height_{}", height));
    
    // Use fewer samples for expensive operations (min 10 for criterion)
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));
    
    let mut rng = ChaCha8Rng::from_entropy();
    let (leaf, path, indices, root) = prepare_witness(height);

    // Setup generation - use circuit with witness for setup
    let setup_circuit = TestMerkleCircuit::new(height)
        .with_witness(leaf, path.clone(), indices.clone(), root);
    let (pk, vk) = generate_setup(setup_circuit, &mut rng).unwrap();

    // Benchmark proof generation with proper witness
    group.bench_function(BenchmarkId::new("proof_generation", height), |b| {
        b.iter(|| {
            let circuit = TestMerkleCircuit::new(height)
                .with_witness(leaf, path.clone(), indices.clone(), root);
            let proof = generate_proof(circuit, &pk, &mut rng).unwrap();
            black_box(proof);
        });
    });

    // Benchmark verification
    let proof_circuit = TestMerkleCircuit::new(height)
        .with_witness(leaf, path.clone(), indices.clone(), root);
    let proof = generate_proof(proof_circuit, &pk, &mut rng).unwrap();
    
    group.bench_function(BenchmarkId::new("verification", height), |b| {
        b.iter(|| {
            let public_inputs = vec![root];
            let result = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
            black_box(result);
        });
    });
    
    group.finish();
}

/// Benchmark proving times across different tree heights
fn bench_proving_times(c: &mut Criterion) {
    println!("\n=== Proving Time Benchmarks ===\n");
    
    // Test heights: 4, 8, 12, 16
    // Height 20+ is too slow for benchmark, see integration tests instead
    let heights = vec![4, 8, 12, 16];
    
    for height in &heights {
        let max_addresses = 1usize << height;
        println!("Testing tree height {} (max {} addresses)", height, max_addresses);
        
        bench_circuit_height(c, *height);
    }
}

criterion_group!(benches, bench_proving_times);
criterion_main!(benches);
