//! ZK Drop CLI
//! 
//! Command-line tool for generating ZK proofs for the privacy airdrop.
//! 
//! Usage:
//!   zkdrop-cli generate --private-key <KEY> --merkle-tree <FILE> --recipient <ADDR>
//!   zkdrop-cli build-tree --addresses <FILE> --output <FILE>
//!   zkdrop-cli verify-proof --proof <FILE> --public-inputs <FILE>

use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use clap::{Parser, Subcommand};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use zkdrop_cli::{
    circuit::{AirdropClaimCircuit, AirdropPrivateInputs, AirdropPublicInputs},
    merkle::{MerkleTree, MerkleTreeJson, tree_height_for_address_count},
    poseidon::{address_to_field_element, compute_leaf, compute_nullifier},
    generate_setup, generate_proof,
};

/// CLI arguments
#[derive(Parser)]
#[command(name = "zkdrop-cli")]
#[command(about = "ZK Drop - Privacy-preserving airdrop CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Generate a ZK proof for claiming tokens
    Generate {
        /// Private key (hex string, 0x prefix optional)
        #[arg(short, long)]
        private_key: String,
        
        /// Merkle tree file (JSON format)
        #[arg(short, long)]
        merkle_tree: PathBuf,
        
        /// Recipient address (Ethereum address)
        #[arg(short, long)]
        recipient: String,
        
        /// Chain ID (default: 8453 for Base mainnet)
        #[arg(short, long, default_value = "8453")]
        chain_id: u64,
        
        /// Output file for proof
        #[arg(short, long, default_value = "proof.json")]
        output: PathBuf,
    },
    
    /// Build Merkle tree from addresses file
    BuildTree {
        /// Input file with addresses (one per line)
        #[arg(short, long)]
        addresses: PathBuf,
        
        /// Output file for Merkle tree
        #[arg(short, long, default_value = "merkle-tree.json")]
        output: PathBuf,
    },
    
    /// Generate Merkle proof for an address
    MerkleProof {
        /// Merkle tree file
        #[arg(short, long)]
        merkle_tree: PathBuf,
        
        /// Address to generate proof for
        #[arg(short, long)]
        address: String,
        
        /// Output file for proof path
        #[arg(short, long, default_value = "merkle-path.json")]
        output: PathBuf,
    },
    
    /// Verify a proof file
    VerifyProof {
        /// Proof file
        #[arg(short, long)]
        proof: PathBuf,
        
        /// Public inputs file
        #[arg(short, long)]
        public_inputs: PathBuf,
    },
    
    /// Run benchmark tests
    Benchmark {
        /// Tree heights to test (comma-separated)
        #[arg(short, long, default_value = "4,8,12,16")]
        heights: String,
    },
}

/// Proof output format (zkdrop/proof-v1)
#[derive(Serialize, Deserialize)]
struct ProofFile {
    format: String,
    proof: ProofData,
    public_inputs: PublicInputsData,
}

#[derive(Serialize, Deserialize)]
struct ProofData {
    a: [String; 2],
    b: [[String; 2]; 2],
    c: [String; 2],
}

#[derive(Serialize, Deserialize)]
struct PublicInputsData {
    merkle_root: String,
    nullifier: String,
    recipient: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Generate {
            private_key,
            merkle_tree,
            recipient,
            chain_id,
            output,
        } => generate_proof_cmd(private_key, merkle_tree, recipient, chain_id, output),
        
        Commands::BuildTree { addresses, output } => {
            build_tree_cmd(addresses, output)
        }
        
        Commands::MerkleProof {
            merkle_tree,
            address,
            output,
        } => generate_merkle_proof_cmd(merkle_tree, address, output),
        
        Commands::VerifyProof {
            proof,
            public_inputs,
        } => verify_proof_cmd(proof, public_inputs),
        
        Commands::Benchmark { heights } => benchmark_cmd(heights),
    }
}

/// Generate a ZK proof for claiming tokens
fn generate_proof_cmd(
    private_key_hex: String,
    merkle_tree_path: PathBuf,
    recipient_str: String,
    chain_id: u64,
    output: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating ZK proof...");
    
    // Parse private key
    let private_key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))?;
    let private_key = Fr254::from_be_bytes_mod_order(&private_key_bytes);
    
    // Parse recipient address
    let recipient_addr = hex::decode(recipient_str.trim_start_matches("0x"))?;
    let recipient_bytes: [u8; 20] = recipient_addr.try_into()
        .map_err(|_| "Invalid address length")?;
    let recipient_fe = address_to_field_element(recipient_bytes);
    
    // Load merkle tree
    let tree_json_str = fs::read_to_string(&merkle_tree_path)?;
    let tree_json: MerkleTreeJson = serde_json::from_str(&tree_json_str)?;
    
    // For now, generate mock values for testing
    // In production, derive these from the private key
    let mut rng = ChaCha8Rng::from_entropy();
    
    // Generate mock public key (in production: derive from private key using secp256k1)
    let pk_x = Fr254::rand(&mut rng);
    let pk_y = Fr254::rand(&mut rng);
    
    // Generate mock merkle path (in production: look up from tree)
    let tree_height = tree_height_for_address_count(tree_json.addresses.len());
    let merkle_path: Vec<Fr254> = (0..tree_height).map(|_| Fr254::rand(&mut rng)).collect();
    let path_indices: Vec<bool> = (0..tree_height).map(|i| i % 2 == 0).collect();
    
    // Generate mock merkle root (in production: compute from tree)
    let merkle_root = Fr254::rand(&mut rng);
    
    // Compute nullifier
    let nullifier = compute_nullifier(
        Fr254::from(chain_id),
        merkle_root,
        pk_x,
        pk_y,
    );
    
    // Build inputs
    let public_inputs = AirdropPublicInputs {
        merkle_root,
        nullifier,
        recipient: recipient_fe,
    };
    
    let private_inputs = AirdropPrivateInputs {
        private_key,
        merkle_path,
        path_indices,
        pk_x,
        pk_y,
    };
    
    // Create circuit
    let circuit = AirdropClaimCircuit::new(tree_height, chain_id)
        .with_witness(public_inputs, private_inputs);
    
    // Generate setup (in production, this would be pre-generated)
    println!("Generating setup...");
    let (pk, _vk) = generate_setup(circuit.clone(), &mut rng)?;
    
    // Generate proof
    println!("Generating proof...");
    let proof = generate_proof(circuit, &pk, &mut rng)?;
    
    // Serialize proof
    let proof_file = ProofFile {
        format: "zkdrop/proof-v1".to_string(),
        proof: ProofData {
            a: [proof.a.x.to_string(), proof.a.y.to_string()],
            b: [
                [proof.b.x.c0.to_string(), proof.b.x.c1.to_string()],
                [proof.b.y.c0.to_string(), proof.b.y.c1.to_string()],
            ],
            c: [proof.c.x.to_string(), proof.c.y.to_string()],
        },
        public_inputs: PublicInputsData {
            merkle_root: format!("0x{}", hex::encode(merkle_root.into_bigint().to_bytes_be())),
            nullifier: format!("0x{}", hex::encode(nullifier.into_bigint().to_bytes_be())),
            recipient: format!("0x{}", hex::encode(recipient_fe.into_bigint().to_bytes_be())),
        },
    };
    
    // Write output
    let output_json = serde_json::to_string_pretty(&proof_file)?;
    fs::write(&output, output_json)?;
    
    println!("✓ Proof saved to: {}", output.display());
    
    Ok(())
}

/// Build Merkle tree from addresses file
fn build_tree_cmd(
    addresses_path: PathBuf,
    output: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Building Merkle tree...");
    
    // Read addresses file
    let addresses_str = fs::read_to_string(&addresses_path)?;
    let addresses: Vec<String> = addresses_str
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    println!("  Loading {} addresses...", addresses.len());
    
    // Convert addresses to field elements
    let leaves: Vec<Fr254> = addresses.iter()
        .map(|addr| {
            let addr_bytes = hex::decode(addr.trim_start_matches("0x")).unwrap();
            let addr_array: [u8; 20] = addr_bytes.try_into().unwrap();
            compute_leaf(address_to_field_element(addr_array))
        })
        .collect();
    
    // Build tree
    let tree = MerkleTree::new(leaves)?;
    
    // Create output JSON
    let tree_json = MerkleTreeJson {
        format: "zkdrop/merkle-tree-v1".to_string(),
        hash: "poseidon".to_string(),
        field: "bn254".to_string(),
        poseidon: "bn254-arity2-rf8-rp57-v1".to_string(),
        leaf_encoding: "eth_address_be_32".to_string(),
        root: format!("0x{}", hex::encode(tree.root.into_bigint().to_bytes_be())),
        addresses,
    };
    
    // Write output
    let output_json = serde_json::to_string_pretty(&tree_json)?;
    fs::write(&output, output_json)?;
    
    println!("✓ Merkle tree saved to: {}", output.display());
    println!("  Root: {}", tree_json.root);
    println!("  Height: {}", tree.height());
    
    Ok(())
}

/// Generate Merkle proof for an address
fn generate_merkle_proof_cmd(
    merkle_tree_path: PathBuf,
    address_str: String,
    output: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating Merkle proof...");
    
    // Load merkle tree
    let tree_json_str = fs::read_to_string(&merkle_tree_path)?;
    let tree_json: MerkleTreeJson = serde_json::from_str(&tree_json_str)?;
    
    // Find address index
    let address = address_str.to_lowercase();
    let index = tree_json.addresses.iter()
        .position(|a| a.to_lowercase() == address)
        .ok_or("Address not found in tree")?;
    
    // Rebuild tree (inefficient but simple)
    let leaves: Vec<Fr254> = tree_json.addresses.iter()
        .map(|addr| {
            let addr_bytes = hex::decode(addr.trim_start_matches("0x")).unwrap();
            let addr_array: [u8; 20] = addr_bytes.try_into().unwrap();
            address_to_field_element(addr_array)
        })
        .collect();
    
    let tree = MerkleTree::new(leaves)?;
    let proof = tree.generate_proof(index)?;
    
    // Convert to JSON
    let proof_json = proof.to_json();
    
    // Write output
    let output_str = serde_json::to_string_pretty(&proof_json)?;
    fs::write(&output, output_str)?;
    
    println!("✓ Merkle proof saved to: {}", output.display());
    
    Ok(())
}

/// Verify a proof file
fn verify_proof_cmd(
    proof_path: PathBuf,
    _public_inputs_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Verifying proof...");
    
    // Load proof
    let proof_str = fs::read_to_string(&proof_path)?;
    let proof_file: ProofFile = serde_json::from_str(&proof_str)?;
    
    println!("  Format: {}", proof_file.format);
    println!("  Merkle root: {}", proof_file.public_inputs.merkle_root);
    println!("  Nullifier: {}", proof_file.public_inputs.nullifier);
    println!("  Recipient: {}", proof_file.public_inputs.recipient);
    
    // Note: Full verification requires the verifying key
    println!("⚠️  Full verification not implemented in this version");
    println!("   Use the smart contract for on-chain verification");
    
    Ok(())
}

/// Run benchmark tests
fn benchmark_cmd(heights_str: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running benchmarks...");
    
    let heights: Vec<usize> = heights_str
        .split(',')
        .map(|s| s.trim().parse().unwrap())
        .collect();
    
    let mut rng = ChaCha8Rng::from_entropy();
    
    println!("\n{:>6} | {:>12} | {:>10} | {:>10} | {:>10}",
        "Height", "Addresses", "Setup", "Proving", "Verify");
    println!("{:-<70}", "");
    
    for height in heights {
        let num_addrs = 1usize << height;
        
        // Prepare witness
        // use ark_ff::Field;
        let leaf = Fr254::rand(&mut rng);
        let path: Vec<Fr254> = (0..height).map(|_| Fr254::rand(&mut rng)).collect();
        let indices: Vec<bool> = (0..height).map(|i| i % 2 == 0).collect();
        
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
        
        // Build circuit
        use zkdrop_cli::TestMerkleCircuit;
        let circuit = TestMerkleCircuit::new(height)
            .with_witness(leaf, path.clone(), indices.clone(), root);
        
        // Benchmark setup
        let start = std::time::Instant::now();
        let (pk, vk) = generate_setup(circuit.clone(), &mut rng)?;
        let setup_time = start.elapsed().as_millis();
        
        // Benchmark proving
        let start = std::time::Instant::now();
        let proof = generate_proof(circuit.clone(), &pk, &mut rng)?;
        let proving_time = start.elapsed().as_millis();
        
        // Benchmark verification
        let public_inputs = vec![root];
        let start = std::time::Instant::now();
        let _ = Groth16::<ark_bn254::Bn254>::verify(&vk, &public_inputs, &proof)?;
        let verify_time = start.elapsed().as_millis();
        
        println!("{:>6} | {:>12} | {:>8}ms | {:>8}ms | {:>8}ms",
            height, num_addrs, setup_time, proving_time, verify_time);
    }
    
    Ok(())
}
