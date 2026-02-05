//! ZK Drop Setup Tool
//! 
//! Generates Groth16 proving and verifying keys for the airdrop circuit.
//! Also exports the Solidity verifier contract.
//!
//! Usage:
//!   cargo run --bin setup -- --tree-height 26 --output ./keys

use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
// Note: SeedableRng is re-exported from ark_std via rand
use clap::Parser;
use rand_chacha::ChaCha8Rng;
use std::fs;
use std::path::PathBuf;

use zkdrop_cli::TestMerkleCircuit;

/// CLI arguments
#[derive(Parser)]
#[command(name = "zkdrop-setup")]
#[command(about = "Generate Groth16 keys and verifier for ZK Drop")]
struct Cli {
    /// Tree height (determines circuit size)
    #[arg(short, long, default_value = "26")]
    tree_height: usize,
    
    /// Chain ID for nullifier computation
    #[arg(short, long, default_value = "8453")]
    chain_id: u64,
    
    /// Output directory for keys
    #[arg(short, long, default_value = "./keys")]
    output: PathBuf,
    
    /// Export Solidity verifier
    #[arg(long, default_value = "true")]
    solidity: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║           ZK Drop - Groth16 Setup Ceremony               ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    
    // Create output directory
    fs::create_dir_all(&cli.output)?;
    
    println!("Configuration:");
    println!("  Tree height: {}", cli.tree_height);
    println!("  Chain ID: {} (Base mainnet)", cli.chain_id);
    println!("  Output directory: {}", cli.output.display());
    println!();
    
    // Generate circuit with dummy witness for setup
    println!("Generating circuit...");
    use ark_ff::UniformRand;
    use rand::SeedableRng;
    
    let mut rng = ChaCha8Rng::seed_from_u64(42); // Fixed seed for reproducibility
    let leaf = ark_bn254::Fr::rand(&mut rng);
    let path: Vec<ark_bn254::Fr> = (0..cli.tree_height).map(|_| ark_bn254::Fr::rand(&mut rng)).collect();
    let indices: Vec<bool> = (0..cli.tree_height).map(|i| i % 2 == 0).collect();
    
    // Compute root using same hash as circuit
    let mut current = leaf;
    for i in 0..cli.tree_height {
        let (left, right) = if indices[i] {
            (path[i], current)
        } else {
            (current, path[i])
        };
        current = zkdrop_cli::poseidon::poseidon_hash_arity2(left, right);
    }
    let root = current;
    
    let circuit = TestMerkleCircuit::new(cli.tree_height)
        .with_witness(leaf, path, indices, root);
    
    // Generate trusted setup
    println!("Running trusted setup (this may take a few minutes)...");
    let mut setup_rng = ChaCha8Rng::from_entropy();
    
    let start = std::time::Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut setup_rng)?;
    let setup_time = start.elapsed();
    
    println!("✓ Setup completed in {:.2}s", setup_time.as_secs_f64());
    println!();
    
    // Save proving key
    let pk_path = cli.output.join("proving_key.bin");
    let mut pk_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&pk, &mut pk_bytes)?;
    fs::write(&pk_path, pk_bytes)?;
    println!("✓ Proving key saved to: {}", pk_path.display());
    println!("  Size: {} bytes", std::fs::metadata(&pk_path)?.len());
    
    // Save verifying key
    let vk_path = cli.output.join("verifying_key.bin");
    let mut vk_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&vk, &mut vk_bytes)?;
    fs::write(&vk_path, vk_bytes)?;
    println!("✓ Verifying key saved to: {}", vk_path.display());
    println!("  Size: {} bytes", std::fs::metadata(&vk_path)?.len());
    
    // Export Solidity verifier
    if cli.solidity {
        let solidity_path = cli.output.join("Groth16Verifier.sol");
        let solidity_code = generate_solidity_verifier(&vk);
        fs::write(&solidity_path, solidity_code)?;
        println!("✓ Solidity verifier saved to: {}", solidity_path.display());
        
        // Also save the full contract
        let contract_path = cli.output.join("ZKDropToken.sol");
        let contract_code = generate_full_contract(&vk);
        fs::write(&contract_path, contract_code)?;
        println!("✓ Full contract saved to: {}", contract_path.display());
    }
    
    // Export verification key as JSON
    let vk_json_path = cli.output.join("verifying_key.json");
    let vk_json = export_vk_json(&vk);
    fs::write(&vk_json_path, vk_json)?;
    println!("✓ Verification key (JSON) saved to: {}", vk_json_path.display());
    
    // Generate deployment script
    let deploy_script_path = cli.output.join("deploy.js");
    let deploy_script = generate_deploy_script();
    fs::write(&deploy_script_path, deploy_script)?;
    println!("✓ Deployment script saved to: {}", deploy_script_path.display());
    
    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("                    Setup Complete!                         ");
    println!("═══════════════════════════════════════════════════════════");
    println!();
    println!("Next steps:");
    println!("  1. Review contracts in {}", cli.output.display());
    println!("  2. Deploy using: node {}", deploy_script_path.display());
    println!("  3. Use proving_key.bin with CLI to generate proofs");
    println!("  4. Test with: cargo test");
    
    Ok(())
}

/// Generate complete Solidity verifier contract
fn generate_solidity_verifier(vk: &ark_groth16::VerifyingKey<Bn254>) -> String {
    let alpha_g1 = &vk.alpha_g1;
    let beta_g2 = &vk.beta_g2;
    let gamma_g2 = &vk.gamma_g2;
    let delta_g2 = &vk.delta_g2;
    let gamma_abc_g1 = &vk.gamma_abc_g1;
    
    // Generate IC array
    let mut ic_code = String::new();
    for (i, ic) in gamma_abc_g1.iter().enumerate() {
        ic_code.push_str(&format!(
            "        vkIC.push(G1Point({x}, {y})); // IC[{i}]\n",
            x = ic.x,
            y = ic.y,
            i = i
        ));
    }
    
    format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title BN254 Elliptic Curve Library
library BN254 {{
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    struct G1Point {{ uint256 x; uint256 y; }}
    struct G2Point {{ uint256 x1; uint256 x2; uint256 y1; uint256 y2; }}
    
    function g1Add(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {{
        uint256[4] memory input = [a.x, a.y, b.x, b.y];
        uint256[2] memory output;
        assembly {{
            if iszero(staticcall(gas(), 0x06, input, 0x80, output, 0x40)) {{ revert(0, 0) }}
        }}
        return G1Point(output[0], output[1]);
    }}
    
    function g1Mul(G1Point memory p, uint256 s) internal view returns (G1Point memory) {{
        uint256[3] memory input = [p.x, p.y, s];
        uint256[2] memory output;
        assembly {{
            if iszero(staticcall(gas(), 0x07, input, 0x60, output, 0x40)) {{ revert(0, 0) }}
        }}
        return G1Point(output[0], output[1]);
    }}
    
    function g1Neg(G1Point memory p) internal pure returns (G1Point memory) {{
        if (p.x == 0 && p.y == 0) return p;
        return G1Point(p.x, P - (p.y % P));
    }}
    
    function pairing(G1Point[] memory a, G2Point[] memory b) internal view returns (bool) {{
        require(a.length == b.length && a.length > 0, "BN254: invalid pairing");
        uint256 elements = a.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        
        for (uint256 i = 0; i < elements; i++) {{
            input[i * 6 + 0] = a[i].x;
            input[i * 6 + 1] = a[i].y;
            input[i * 6 + 2] = b[i].x1;
            input[i * 6 + 3] = b[i].x2;
            input[i * 6 + 4] = b[i].y1;
            input[i * 6 + 5] = b[i].y2;
        }}
        
        uint256[1] memory output;
        assembly {{
            if iszero(staticcall(gas(), 0x08, add(input, 0x20), mul(inputSize, 0x20), output, 0x20)) {{ revert(0, 0) }}
        }}
        return output[0] == 1;
    }}
}}

/// @title Groth16 Verifier for ZK Drop
contract Groth16Verifier {{
    using BN254 for BN254.G1Point;
    
    // Verification key
    BN254.G1Point public vkAlpha = BN254.G1Point({alpha_x}, {alpha_y});
    BN254.G2Point public vkBeta = BN254.G2Point({beta_x0}, {beta_x1}, {beta_y0}, {beta_y1});
    BN254.G2Point public vkGamma = BN254.G2Point({gamma_x0}, {gamma_x1}, {gamma_y0}, {gamma_y1});
    BN254.G2Point public vkDelta = BN254.G2Point({delta_x0}, {delta_x1}, {delta_y0}, {delta_y1});
    BN254.G1Point[] public vkIC;
    
    constructor() {{
{ic_code}
    }}
    
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) external view returns (bool) {{
        require(input.length + 1 == vkIC.length, "Invalid input length");
        
        // Compute vkX = IC[0] + sum(input[i] * IC[i+1])
        BN254.G1Point memory vkX = vkIC[0];
        for (uint256 i = 0; i < input.length; i++) {{
            vkX = vkX.g1Add(vkIC[i + 1].g1Mul(input[i]));
        }}
        
        // Pairing check: e(A,B) * e(-alpha,beta) * e(-C,delta) * e(vkX,gamma) == 1
        BN254.G1Point[] memory g1 = new BN254.G1Point[](4);
        BN254.G2Point[] memory g2 = new BN254.G2Point[](4);
        
        g1[0] = BN254.G1Point(a[0], a[1]);
        g2[0] = BN254.G2Point(b[0][0], b[0][1], b[1][0], b[1][1]);
        
        g1[1] = vkAlpha.g1Neg();
        g2[1] = vkBeta;
        
        g1[2] = BN254.G1Point(c[0], c[1]).g1Neg();
        g2[2] = vkDelta;
        
        g1[3] = vkX;
        g2[3] = vkGamma;
        
        return BN254.pairing(g1, g2);
    }}
    
    function inputCount() external view returns (uint256) {{
        return vkIC.length > 0 ? vkIC.length - 1 : 0;
    }}
}}
"#,
        alpha_x = alpha_g1.x,
        alpha_y = alpha_g1.y,
        beta_x0 = beta_g2.x.c0,
        beta_x1 = beta_g2.x.c1,
        beta_y0 = beta_g2.y.c0,
        beta_y1 = beta_g2.y.c1,
        gamma_x0 = gamma_g2.x.c0,
        gamma_x1 = gamma_g2.x.c1,
        gamma_y0 = gamma_g2.y.c0,
        gamma_y1 = gamma_g2.y.c1,
        delta_x0 = delta_g2.x.c0,
        delta_x1 = delta_g2.x.c1,
        delta_y0 = delta_g2.y.c0,
        delta_y1 = delta_g2.y.c1,
        ic_code = ic_code,
    )
}

/// Generate full ZKDropToken contract with integrated verifier
fn generate_full_contract(vk: &ark_groth16::VerifyingKey<Bn254>) -> String {
    let verifier_code = generate_solidity_verifier(vk);
    
    format!(r#"{verifier}

/// @title ZK Drop Token
/// @notice ERC20 token with privacy-preserving ZK claims
contract ZKDropToken {{
    // ERC20
    string public constant name = "ZK Drop Token";
    string public constant symbol = "ZKDROP";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    // Claim config
    bytes32 public immutable merkleRoot;
    Groth16Verifier public immutable verifier;
    uint256 public constant CLAIM_AMOUNT = 100000 * 10**18;
    uint256 public constant MAX_CLAIMS = 10000;
    uint256 public totalClaims;
    mapping(bytes32 => bool) public nullifierUsed;
    
    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Claim(bytes32 indexed nullifier, address indexed recipient, uint256 amount);
    
    constructor(bytes32 _merkleRoot, address _verifier) {{
        merkleRoot = _merkleRoot;
        verifier = Groth16Verifier(_verifier);
    }}
    
    function claim(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256 nullifier,
        address recipient
    ) external {{
        require(nullifier < 21888242871839275222246405745257275088548364400416034343698204186575808495617, "Invalid nullifier");
        require(!nullifierUsed[bytes32(nullifier)], "Already claimed");
        require(totalClaims < MAX_CLAIMS, "Max claims reached");
        require(recipient != address(0), "Invalid recipient");
        
        // Build public inputs
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = uint256(merkleRoot);
        inputs[1] = nullifier;
        inputs[2] = uint256(uint160(recipient));
        
        require(verifier.verifyProof(a, b, c, inputs), "Invalid proof");
        
        nullifierUsed[bytes32(nullifier)] = true;
        totalClaims++;
        
        balanceOf[recipient] += CLAIM_AMOUNT;
        totalSupply += CLAIM_AMOUNT;
        
        emit Claim(bytes32(nullifier), recipient, CLAIM_AMOUNT);
        emit Transfer(address(0), recipient, CLAIM_AMOUNT);
    }}
    
    function transfer(address to, uint256 amount) external returns (bool) {{
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }}
    
    function approve(address spender, uint256 amount) external returns (bool) {{
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }}
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {{
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        balanceOf[from] -= amount;
        allowance[from][msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }}
    
    event Approval(address indexed owner, address indexed spender, uint256 value);
}}
"#,
        verifier = verifier_code,
    )
}

/// Export verification key as JSON
fn export_vk_json(vk: &ark_groth16::VerifyingKey<Bn254>) -> String {
    use ark_serialize::CanonicalSerialize;
    
    let mut alpha_bytes = Vec::new();
    vk.alpha_g1.serialize_compressed(&mut alpha_bytes).unwrap();
    
    let mut beta_bytes = Vec::new();
    vk.beta_g2.serialize_compressed(&mut beta_bytes).unwrap();
    
    let mut gamma_bytes = Vec::new();
    vk.gamma_g2.serialize_compressed(&mut gamma_bytes).unwrap();
    
    let mut delta_bytes = Vec::new();
    vk.delta_g2.serialize_compressed(&mut delta_bytes).unwrap();
    
    let ic_json: Vec<String> = vk.gamma_abc_g1.iter().map(|ic| {
        format!(r#"{{"x":"{}","y":"{}"}}"#, ic.x, ic.y)
    }).collect();
    
    format!(r#"{{
  "protocol": "groth16",
  "curve": "bn254",
  "public_inputs": 3,
  "vk_alpha_1": "0x{alpha}",
  "vk_beta_2": "0x{beta}",
  "vk_gamma_2": "0x{gamma}",
  "vk_delta_2": "0x{delta}",
  "IC": [
    {ic}
  ]
}}"#,
        alpha = hex::encode(&alpha_bytes),
        beta = hex::encode(&beta_bytes),
        gamma = hex::encode(&gamma_bytes),
        delta = hex::encode(&delta_bytes),
        ic = ic_json.join(",\n    "),
    )
}

/// Generate Hardhat deployment script
fn generate_deploy_script() -> String {
    r#"// deploy.js - Hardhat deployment script
const { ethers } = require("hardhat");

async function main() {
    const [deployer] = await ethers.getSigners();
    console.log("Deploying contracts with account:", deployer.address);

    // Deploy Verifier
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.deployed();
    console.log("Verifier deployed to:", verifier.address);

    // Read merkle root (set your actual root here)
    const merkleRoot = process.env.MERKLE_ROOT || 
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    // Deploy Token
    const ZKDropToken = await ethers.getContractFactory("ZKDropToken");
    const token = await ZKDropToken.deploy(merkleRoot, verifier.address);
    await token.deployed();
    console.log("ZKDropToken deployed to:", token.address);

    // Save deployment info
    const deploymentInfo = {
        verifier: verifier.address,
        token: token.address,
        merkleRoot: merkleRoot,
        network: network.name,
        timestamp: new Date().toISOString()
    };
    
    const fs = require("fs");
    fs.writeFileSync(
        "deployment.json",
        JSON.stringify(deploymentInfo, null, 2)
    );
    
    console.log("Deployment info saved to deployment.json");
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
"#.to_string()
}
