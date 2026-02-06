//! Simplified circuit test with consistent values

use ark_bn254::Fr as Fr254;
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use zkdrop_cli::{
    circuit::{AirdropClaimCircuit, AirdropPublicInputs, AirdropPrivateInputs},
    poseidon::{poseidon_hash_arity2, poseidon_hash_arity4},
};

#[test]
fn test_circuit_with_consistent_witness() {
    println!("\n=== Test: Circuit with Consistent Witness ===\n");
    
    let tree_height = 4usize;
    let chain_id = 8453u64;
    
    // Generate consistent test values
    let mut rng = ChaCha8Rng::from_seed([42u8; 32]);
    
    // Private key (just a test value)
    let private_key = Fr254::from(42u64);
    
    // Public key coordinates
    let pk_x = Fr254::from(111u64);
    let pk_y = Fr254::from(222u64);
    
    // Compute address: keccak256(pk_x || pk_y)[12:32] as field element
    // For this test, we'll use a simple value
    let address = Fr254::from(0x12345678u64);
    
    // Build Merkle path manually (consistent values)
    let mut merkle_path: Vec<Fr254> = Vec::with_capacity(tree_height);
    let mut path_indices: Vec<bool> = Vec::with_capacity(tree_height);
    
    // Generate random siblings
    for i in 0..tree_height {
        merkle_path.push(Fr254::rand(&mut rng));
        path_indices.push(i % 2 == 0); // Alternate directions
    }
    
    // Compute root from address and path
    let mut current = address;
    for i in 0..tree_height {
        let (left, right) = if path_indices[i] {
            (merkle_path[i], current)
        } else {
            (current, merkle_path[i])
        };
        current = poseidon_hash_arity2(left, right);
    }
    let merkle_root = current;
    
    // Compute nullifier: H(chain_id, merkle_root, pk_x, pk_y)
    let nullifier = poseidon_hash_arity4([
        Fr254::from(chain_id),
        merkle_root,
        pk_x,
        pk_y,
    ]);
    
    // Recipient (any address as field element)
    let recipient = Fr254::from(0xdeadbeefu64);
    
    println!("Inputs:");
    println!("  Private key: {:?}", private_key);
    println!("  pk_x: {:?}", pk_x);
    println!("  pk_y: {:?}", pk_y);
    println!("  Address: {:?}", address);
    println!("  Merkle root: {:?}", merkle_root);
    println!("  Nullifier: {:?}", nullifier);
    println!("  Recipient: {:?}", recipient);
    
    // Build circuit
    let public_inputs = AirdropPublicInputs {
        merkle_root,
        nullifier,
        recipient,
    };
    
    let private_inputs = AirdropPrivateInputs {
        private_key,
        merkle_path,
        path_indices,
        pk_x,
        pk_y,
    };
    
    let circuit = AirdropClaimCircuit::new(tree_height, chain_id)
        .with_witness(public_inputs, private_inputs);
    
    // Generate constraints
    let cs = ConstraintSystemRef::new(ark_relations::r1cs::ConstraintSystem::new());
    
    println!("\nGenerating constraints...");
    match circuit.generate_constraints(cs.clone()) {
        Ok(_) => println!("  ✓ Constraints generated"),
        Err(e) => {
            println!("  ✗ Constraint generation failed: {:?}", e);
            panic!("Constraint generation failed");
        }
    }
    
    let num_constraints = cs.num_constraints();
    println!("  Constraints: {}", num_constraints);
    
    // Check satisfaction
    println!("\nChecking constraint satisfaction...");
    match cs.is_satisfied() {
        Ok(true) => println!("  ✓ All constraints satisfied"),
        Ok(false) => {
            println!("  ✗ Constraints NOT satisfied");
            if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                println!("    First unsatisfied: {}", unsat);
            }
            panic!("Constraints not satisfied");
        }
        Err(e) => {
            println!("  Error: {:?}", e);
            panic!("Error checking satisfaction");
        }
    }
    
    println!("\n=== Test Passed ===\n");
}
