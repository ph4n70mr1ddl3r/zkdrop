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
    merkle::{MerkleTree, MerkleTreeJson},
    poseidon::{address_to_field_element, compute_leaf, compute_nullifier},
    secp256k1::{parse_private_key_hex, parse_address_hex, derive_all_from_private_key},
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
        
        /// Verifying key file
        #[arg(short, long)]
        verifying_key: Option<PathBuf>,
    },
    
    /// Run benchmark tests
    Benchmark {
        /// Tree heights to test (comma-separated)
        #[arg(short, long, default_value = "4,8,12,16")]
        heights: String,
    },
    
    /// Derive public key and address from private key
    Derive {
        /// Private key (hex string, 0x prefix optional)
        #[arg(short, long)]
        private_key: String,
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
            verifying_key,
        } => verify_proof_cmd(proof, public_inputs, verifying_key),
        
        Commands::Benchmark { heights } => benchmark_cmd(heights),
        
        Commands::Derive { private_key } => derive_cmd(private_key),
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
    let private_key_bytes = parse_private_key_hex(&private_key_hex)
        .map_err(|e| format!("Invalid private key: {}", e))?;
    
    // Derive public key and address from private key
    let derived = derive_all_from_private_key(&private_key_bytes)
        .map_err(|e| format!("Failed to derive public key: {}", e))?;
    
    println!("  Derived address: 0x{}", hex::encode(derived.address));
    
    // Parse recipient address
    let recipient_addr = parse_address_hex(&recipient_str)
        .map_err(|e| format!("Invalid recipient address: {}", e))?;
    let recipient_fe = address_to_field_element(recipient_addr);
    
    // Load merkle tree
    let tree_json_str = fs::read_to_string(&merkle_tree_path)
        .map_err(|e| format!("Failed to read merkle tree file: {}", e))?;
    let tree_json: MerkleTreeJson = serde_json::from_str(&tree_json_str)
        .map_err(|e| format!("Invalid merkle tree JSON: {}", e))?;
    
    // Find the user's address in the tree
    let user_address_hex = format!("0x{}", hex::encode(derived.address));
    let address_index = tree_json.addresses.iter()
        .position(|a| a.to_lowercase() == user_address_hex.to_lowercase())
        .ok_or("Your derived address was not found in the merkle tree. Are you eligible?")?;
    
    println!("  Found address at index {} in merkle tree", address_index);
    
    // Rebuild tree to generate merkle path
    let leaves: Vec<Fr254> = tree_json.addresses.iter()
        .map(|addr| {
            let addr_bytes = parse_address_hex(addr)
                .expect("Address in tree file should be valid");
            compute_leaf(address_to_field_element(addr_bytes))
        })
        .collect();
    
    let tree = MerkleTree::new(leaves)
        .map_err(|e| format!("Failed to build merkle tree: {}", e))?;
    
    // Generate merkle proof
    let merkle_proof = tree.generate_proof(address_index)
        .map_err(|e| format!("Failed to generate merkle proof: {}", e))?;
    
    // Convert merkle proof to circuit format
    let merkle_path: Vec<Fr254> = merkle_proof.path.iter()
        .map(|p| p.sibling)
        .collect();
    let path_indices: Vec<bool> = merkle_proof.path.iter()
        .map(|p| p.direction == 1)
        .collect();
    
    let merkle_root = tree.root;
    let tree_height = tree.height();
    
    // Compute nullifier
    let nullifier = compute_nullifier(
        Fr254::from(chain_id),
        merkle_root,
        derived.pkx_fe,
        derived.pky_fe,
    );
    
    println!("  Merkle root: 0x{}", hex::encode(merkle_root.into_bigint().to_bytes_be()));
    println!("  Nullifier: 0x{}", hex::encode(nullifier.into_bigint().to_bytes_be()));
    
    // Build inputs
    let public_inputs = AirdropPublicInputs {
        merkle_root,
        nullifier,
        recipient: recipient_fe,
    };
    
    let private_key_fe = Fr254::from_be_bytes_mod_order(&private_key_bytes);
    
    let private_inputs = AirdropPrivateInputs {
        private_key: private_key_fe,
        merkle_path,
        path_indices,
        pk_x: derived.pkx_fe,
        pk_y: derived.pky_fe,
    };
    
    // Create circuit
    let circuit = AirdropClaimCircuit::new(tree_height, chain_id)
        .with_witness(public_inputs.clone(), private_inputs);
    
    // Generate setup
    println!("Generating setup...");
    let mut rng = ChaCha8Rng::from_entropy();
    let (pk, _vk) = generate_setup(circuit.clone(), &mut rng)
        .map_err(|e| format!("Setup generation failed: {}", e))?;
    
    // Generate proof
    println!("Generating proof...");
    let proof = generate_proof(circuit, &pk, &mut rng)
        .map_err(|e| format!("Proof generation failed: {}", e))?;
    
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
    let addresses_str = fs::read_to_string(&addresses_path)
        .map_err(|e| format!("Failed to read addresses file: {}", e))?;
    
    let addresses: Vec<String> = addresses_str
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    
    if addresses.is_empty() {
        return Err("No addresses found in input file".into());
    }
    
    println!("  Loading {} addresses...", addresses.len());
    
    // Validate and convert addresses to field elements
    let mut leaves = Vec::with_capacity(addresses.len());
    for (idx, addr) in addresses.iter().enumerate() {
        let addr_bytes = parse_address_hex(addr)
            .map_err(|e| format!("Invalid address at line {}: {}", idx + 1, e))?;
        leaves.push(compute_leaf(address_to_field_element(addr_bytes)));
    }
    
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
    
    // Parse target address
    let target_addr = parse_address_hex(&address_str)
        .map_err(|e| format!("Invalid address: {}", e))?;
    let target_addr_hex = format!("0x{}", hex::encode(target_addr));
    
    // Load merkle tree
    let tree_json_str = fs::read_to_string(&merkle_tree_path)
        .map_err(|e| format!("Failed to read merkle tree file: {}", e))?;
    let tree_json: MerkleTreeJson = serde_json::from_str(&tree_json_str)
        .map_err(|e| format!("Invalid merkle tree JSON: {}", e))?;
    
    // Find address index (case-insensitive comparison)
    let address = address_str.to_lowercase();
    let index = tree_json.addresses.iter()
        .position(|a| a.to_lowercase() == address)
        .ok_or(format!("Address {} not found in tree", target_addr_hex))?;
    
    // Rebuild tree (inefficient but simple)
    let leaves: Vec<Fr254> = tree_json.addresses.iter()
        .map(|addr| {
            let addr_bytes = parse_address_hex(addr)
                .expect("Address in tree should be valid");
            compute_leaf(address_to_field_element(addr_bytes))
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
    verifying_key_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Verifying proof...");
    
    // Load proof
    let proof_str = fs::read_to_string(&proof_path)
        .map_err(|e| format!("Failed to read proof file: {}", e))?;
    let proof_file: ProofFile = serde_json::from_str(&proof_str)
        .map_err(|e| format!("Invalid proof JSON: {}", e))?;
    
    println!("  Format: {}", proof_file.format);
    println!("  Merkle root: {}", proof_file.public_inputs.merkle_root);
    println!("  Nullifier: {}", proof_file.public_inputs.nullifier);
    println!("  Recipient: {}", proof_file.public_inputs.recipient);
    
    // Check if we have a verifying key to perform full verification
    if verifying_key_path.is_some() {
        println!("  Verifying key provided but full verification from JSON format");
        println!("  is not yet implemented. Use the smart contract for on-chain verification.");
        println!("  Format validation passed.");
    } else {
        println!("⚠️  No verifying key provided - performing format check only");
        println!("   Use --verifying-key <path> for full cryptographic verification");
        println!("   (Note: full verification from JSON is not yet implemented)");
    }
    
    println!("\n✓ Proof format is valid");
    
    Ok(())
}

/// Derive public key and address from private key
fn derive_cmd(private_key_hex: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("Deriving keys from private key...");
    
    let private_key_bytes = parse_private_key_hex(&private_key_hex)
        .map_err(|e| format!("Invalid private key: {}", e))?;
    
    let derived = derive_all_from_private_key(&private_key_bytes)
        .map_err(|e| format!("Failed to derive keys: {}", e))?;
    
    println!("  Private Key: 0x{}", hex::encode(private_key_bytes));
    println!("  Public Key X: 0x{}", hex::encode(derived.pk_x));
    println!("  Public Key Y: 0x{}", hex::encode(derived.pk_y));
    println!("  Address:      0x{}", hex::encode(derived.address));
    println!("  pk_x as field element: {}", derived.pkx_fe);
    println!("  pk_y as field element: {}", derived.pky_fe);
    println!("  addr as field element: {}", derived.addr_fe);
    
    Ok(())
}

/// Run benchmark tests
fn benchmark_cmd(heights_str: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running benchmarks...");
    
    let heights: Vec<usize> = heights_str
        .split(',')
        .map(|s| s.trim().parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Invalid height value: {}", e))?;
    
    let mut rng = ChaCha8Rng::from_entropy();
    
    println!("\n{:>6} | {:>12} | {:>10} | {:>10} | {:>10}",
        "Height", "Addresses", "Setup", "Proving", "Verify");
    println!("{:-<70}", "");
    
    for height in heights {
        let num_addrs = 1usize << height;
        
        // Prepare witness
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
