//! Merkle Tree Height Scaling Benchmark
//! 
//! This benchmark specifically tests how proving time scales with:
//! - Number of addresses (tree height)
//! - Circuit complexity
//!
//! It generates a report showing estimated proving times for the full 65M address set.

use ark_bn254::{Bn254, Fr as Fr254};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::{Duration, Instant};
use zkdrop_cli::{TestMerkleCircuit, generate_setup, generate_proof};

/// Structure to hold benchmark results for reporting
#[derive(Debug, Clone)]
struct ProvingMetrics {
    tree_height: usize,
    max_addresses: usize,
    setup_time_ms: u64,
    proving_time_ms: u64,
    verification_time_ms: u64,
    constraint_count: usize,
}

impl ProvingMetrics {
    fn format_report(&self) -> String {
        format!(
            "Height {:2} ({:>12} addresses): Setup={:>6}ms, Prove={:>8}ms, Verify={:>4}ms, Constraints={}",
            self.tree_height,
            format!("{}", self.max_addresses),
            self.setup_time_ms,
            self.proving_time_ms,
            self.verification_time_ms,
            self.constraint_count
        )
    }
}

/// Prepare witness for benchmarking
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

/// Run a single benchmark iteration and collect metrics
fn run_benchmark(height: usize) -> ProvingMetrics {
    let mut rng = ChaCha8Rng::from_entropy();
    let (leaf, path, indices, root) = prepare_witness(height);

    // Measure setup time - use circuit with witness for setup
    let setup_start = Instant::now();
    let setup_circuit = TestMerkleCircuit::new(height)
        .with_witness(leaf, path.clone(), indices.clone(), root);
    let (pk, vk) = generate_setup(setup_circuit, &mut rng).unwrap();
    let setup_time_ms = setup_start.elapsed().as_millis() as u64;

    // Get constraint count from a fresh circuit with witness
    let cs = ark_relations::r1cs::ConstraintSystem::new_ref();
    let count_circuit = TestMerkleCircuit::new(height)
        .with_witness(leaf, path.clone(), indices.clone(), root);
    count_circuit.generate_constraints(cs.clone()).unwrap();
    let constraint_count = cs.num_constraints();

    // Measure proving time (average of 3 runs for accuracy)
    let mut proving_times = Vec::new();
    for _ in 0..3 {
        let prove_start = Instant::now();
        let circuit = TestMerkleCircuit::new(height)
            .with_witness(leaf, path.clone(), indices.clone(), root);
        let proof = generate_proof(circuit, &pk, &mut rng).unwrap();
        black_box(proof);
        proving_times.push(prove_start.elapsed().as_millis() as u64);
    }
    let proving_time_ms = proving_times.iter().sum::<u64>() / proving_times.len() as u64;

    // Measure verification time (average of 10 runs)
    let proof_circuit = TestMerkleCircuit::new(height)
        .with_witness(leaf, path.clone(), indices.clone(), root);
    let proof = generate_proof(proof_circuit, &pk, &mut rng).unwrap();
    
    let mut verification_times = Vec::new();
    for _ in 0..10 {
        let verify_start = Instant::now();
        let public_inputs = vec![root];
        let result = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
        black_box(result);
        verification_times.push(verify_start.elapsed().as_millis() as u64);
    }
    let verification_time_ms = verification_times.iter().sum::<u64>() / verification_times.len() as u64;

    ProvingMetrics {
        tree_height: height,
        max_addresses: 1usize << height,
        setup_time_ms,
        proving_time_ms,
        verification_time_ms,
        constraint_count,
    }
}

/// Generate extrapolation estimate for 65M addresses
fn extrapolate_to_target(metrics: &[ProvingMetrics]) -> String {
    let target_height = 26;
    let target_addresses = 65_000_000usize;
    
    // Find two closest data points for linear extrapolation
    let below = metrics.iter().find(|m| m.tree_height <= target_height);
    let above = metrics.iter().find(|m| m.tree_height >= target_height);
    
    let estimate = if let (Some(b), Some(a)) = (below, above) {
        if b.tree_height == a.tree_height {
            b.proving_time_ms
        } else {
            // Linear interpolation
            let t = (target_height - b.tree_height) as f64 / (a.tree_height - b.tree_height) as f64;
            let time = b.proving_time_ms as f64 + t * (a.proving_time_ms as f64 - b.proving_time_ms as f64);
            time as u64
        }
    } else if let Some(b) = below {
        // Extrapolate from last known point assuming linear scaling per level
        let levels_diff = target_height - b.tree_height;
        let time_per_level = if b.tree_height > 10 {
            b.proving_time_ms / b.tree_height as u64
        } else {
            100 // conservative estimate
        };
        b.proving_time_ms + (levels_diff as u64 * time_per_level)
    } else {
        0
    };

    format!(
        "\n=== Extrapolation to Target (65M addresses, height 26) ===\n\
         Estimated proving time: {} ms ({} seconds)\n\
         Note: This is for simplified circuit. Full circuit (secp256k1+keccak) will be significantly slower.",
        estimate,
        estimate / 1000
    )
}

/// Main benchmark function
fn bench_merkle_scaling(c: &mut Criterion) {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║     Merkle Tree Height Scaling Benchmark                        ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let mut all_metrics = Vec::new();
    
    // Test incremental heights
    let test_heights = vec![4, 8, 12, 16, 20, 24];
    
    for height in test_heights {
        let mut group = c.benchmark_group("merkle_scaling");
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(30));
        
        let metrics = run_benchmark(height);
        println!("{}", metrics.format_report());
        all_metrics.push(metrics.clone());
        
        // Also add to criterion report
        let (leaf, path, indices, root) = prepare_witness(height);
        let setup_circuit = TestMerkleCircuit::new(height)
            .with_witness(leaf, path.clone(), indices.clone(), root);
        let (pk, _vk) = generate_setup(setup_circuit, &mut ChaCha8Rng::from_entropy()).unwrap();
        
        group.bench_function(BenchmarkId::new("height", height), |b| {
            let mut rng = ChaCha8Rng::from_entropy();
            b.iter(|| {
                let circuit = TestMerkleCircuit::new(height)
                    .with_witness(leaf, path.clone(), indices.clone(), root);
                let proof = generate_proof(circuit, &pk, &mut rng).unwrap();
                black_box(proof);
            });
        });
        
        group.finish();
    }

    // Print summary and extrapolation
    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("                         SUMMARY REPORT                             ");
    println!("═══════════════════════════════════════════════════════════════════");
    
    for m in &all_metrics {
        println!("{}", m.format_report());
    }
    
    println!("{}", extrapolate_to_target(&all_metrics));
    
    println!("\n═══════════════════════════════════════════════════════════════════");
    println!("                         RECOMMENDATIONS                            ");
    println!("═══════════════════════════════════════════════════════════════════");
    println!("1. Target proving time should be < 5 minutes for acceptable UX");
    println!("2. If proving takes > 10 minutes, consider:");
    println!("   - Circuit optimizations (custom Poseidon gates)");
    println!("   - Batch proof generation");
    println!("   - Distributed proving infrastructure");
    println!("3. Full circuit will add ~100k+ constraints for secp256k1 + Keccak");
    println!("═══════════════════════════════════════════════════════════════════\n");
}

criterion_group!(benches, bench_merkle_scaling);
criterion_main!(benches);
