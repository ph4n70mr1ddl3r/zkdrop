use rand::RngCore;
use ark_bn254::Fr as Fr254;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, eq::EqGadget, R1CSVar};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use zkdrop_cli::{
    merkle::MerkleTree,
    poseidon::{poseidon_hash_arity2_circuit, compute_leaf, address_to_field_element},
    keccak::compute_address_native,
    secp256k1::{derive_public_key, extract_public_key_coords, pubkey_to_field_elements},
};

/// Debug merkle verification step by step
#[test]
fn test_merkle_step_by_step() {
    println!("\n=== Step-by-Step Merkle Verification ===\n");
    
    let mut rng = ChaCha8Rng::from_seed([42u8; 32]);
    let tree_height = 4usize;
    let num_leaves = 1 << tree_height;
    
    // Generate key pair
    let mut private_key = [0u8; 32];
    rng.fill_bytes(&mut private_key);
    if private_key == [0u8; 32] { private_key[0] = 1; }
    
    let pubkey = derive_public_key(&private_key).expect("Valid key");
    let (pk_x_bytes, pk_y_bytes) = extract_public_key_coords(&pubkey);
    let (pk_x_fe, pk_y_fe) = pubkey_to_field_elements(&pk_x_bytes, &pk_y_bytes);
    
    // Compute address
    let address = compute_address_native(&pk_x_bytes, &pk_y_bytes);
    let address_fe = address_to_field_element(address);
    
    // Build tree
    let mut addresses: Vec<[u8; 20]> = (0..num_leaves).map(|i| {
        let mut addr = [0u8; 20];
        addr[19] = i as u8;
        addr
    }).collect();
    addresses[0] = address;
    
    let leaves: Vec<Fr254> = addresses.iter()
        .map(|addr| compute_leaf(address_to_field_element(*addr)))
        .collect();
    
    let tree = MerkleTree::new(leaves.clone()).expect("Failed to build tree");
    
    // Get proof
    let proof = tree.generate_proof(0).expect("Valid index");
    
    println!("Claiming address: 0x{}", hex::encode(address));
    println!("Address as field element: {:?}", address_fe.into_bigint());
    println!("Tree leaf (H(address, 0)): {:?}", leaves[0].into_bigint());
    println!("Tree root: {:?}", tree.root.into_bigint());
    println!("\nMerkle path:");
    for (i, elem) in proof.path.iter().enumerate() {
        println!("  Level {}: sibling={:?}, direction={}", 
                 i, elem.sibling.into_bigint(), elem.direction);
    }
    
    // Native verification
    let mut current = leaves[0];
    println!("\nNative verification:");
    for (i, elem) in proof.path.iter().enumerate() {
        let (left, right) = if elem.direction == 0 {
            (current, elem.sibling)
        } else {
            (elem.sibling, current)
        };
        current = zkdrop_cli::poseidon::poseidon_hash_arity2(left, right);
        println!("  Level {}: hash={:?}", i, current.into_bigint());
    }
    println!("  Final: {:?}", current.into_bigint());
    println!("  Matches root: {}", current == tree.root);
    
    // Now test the circuit logic manually
    println!("\n=== Circuit Logic Test ===");
    
    let cs = ConstraintSystemRef::new(ark_relations::r1cs::ConstraintSystem::new());
    
    // Allocate address
    let address_var = FpVar::new_witness(cs.clone(), || Ok(address_fe)).unwrap();
    println!("Allocated address: {:?}", address_var.value().unwrap().into_bigint());
    
    // Hash with zero
    let zero_var = FpVar::Constant(Fr254::from(0u64));
    let leaf_var = poseidon_hash_arity2_circuit(&address_var, &zero_var).unwrap();
    println!("Leaf hash: {:?}", leaf_var.value().unwrap().into_bigint());
    println!("Expected leaf: {:?}", leaves[0].into_bigint());
    println!("Leaf matches: {}", leaf_var.value().unwrap() == leaves[0]);
    
    // Allocate merkle path
    let merkle_path_vars: Vec<FpVar<Fr254>> = proof.path.iter().map(|p| {
        FpVar::new_witness(cs.clone(), || Ok(p.sibling)).unwrap()
    }).collect();
    
    // Verify merkle path
    let mut current_var = leaf_var;
    for (i, elem) in proof.path.iter().enumerate() {
        let (left, right) = if elem.direction == 0 {
            (&current_var, &merkle_path_vars[i])
        } else {
            (&merkle_path_vars[i], &current_var)
        };
        current_var = poseidon_hash_arity2_circuit(left, right).unwrap();
        println!("Level {}: {:?}", i, current_var.value().unwrap().into_bigint());
    }
    
    // Allocate root as input
    let root_var = FpVar::new_input(cs.clone(), || Ok(tree.root)).unwrap();
    
    // Enforce equality
    println!("\nComputed root: {:?}", current_var.value().unwrap().into_bigint());
    println!("Expected root: {:?}", root_var.value().unwrap().into_bigint());
    
    if let Err(e) = current_var.enforce_equal(&root_var) {
        println!("Enforce equal error: {:?}", e);
    }
    
    // Check constraints
    match cs.is_satisfied() {
        Ok(true) => println!("\n✓ All constraints satisfied"),
        Ok(false) => {
            if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
                println!("\n✗ Constraint {} not satisfied", unsat);
            }
        }
        Err(e) => println!("\nError: {:?}", e),
    }
}
