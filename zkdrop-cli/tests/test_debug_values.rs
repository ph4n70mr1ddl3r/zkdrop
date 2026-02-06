use rand::RngCore;
use ark_bn254::Fr as Fr254;
use ark_ff::PrimeField;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use zkdrop_cli::{
    merkle::MerkleTree,
    poseidon::{compute_leaf, address_to_field_element},
    keccak::compute_address_native,
    secp256k1::{derive_public_key, extract_public_key_coords, pubkey_to_field_elements},
};

#[test]
fn test_debug_merkle_values() {
    let mut rng = ChaCha8Rng::from_seed([42u8; 32]);
    let tree_height = 4usize;
    let num_leaves = 1 << tree_height;
    
    // Generate a single key pair
    let mut private_key = [0u8; 32];
    rng.fill_bytes(&mut private_key);
    if private_key == [0u8; 32] { private_key[0] = 1; }
    
    let pubkey = derive_public_key(&private_key).expect("Valid key");
    let (pk_x_bytes, pk_y_bytes) = extract_public_key_coords(&pubkey);
    let (pk_x_fe, pk_y_fe) = pubkey_to_field_elements(&pk_x_bytes, &pk_y_bytes);
    
    // Compute address
    let address = compute_address_native(&pk_x_bytes, &pk_y_bytes);
    let address_fe = address_to_field_element(address);
    
    println!("\n=== Debug Values ===");
    println!("Private key: 0x{}", hex::encode(private_key));
    println!("pk_x bytes: 0x{}", hex::encode(pk_x_bytes));
    println!("pk_y bytes: 0x{}", hex::encode(pk_y_bytes));
    println!("Address: 0x{}", hex::encode(address));
    println!("Address as field element: {:?}", address_fe.into_bigint());
    
    // Build tree with this address at index 0
    let mut addresses: Vec<[u8; 20]> = (0..num_leaves).map(|i| {
        let mut addr = [0u8; 20];
        addr[19] = i as u8;
        addr
    }).collect();
    addresses[0] = address;
    
    let leaves: Vec<Fr254> = addresses.iter()
        .map(|addr| compute_leaf(address_to_field_element(*addr)))
        .collect();
    
    println!("\nLeaf 0 (from our address): {:?}", leaves[0].into_bigint());
    println!("Expected leaf = H(address_fe, 0)");
    
    let tree = MerkleTree::new(leaves.clone()).expect("Failed to build tree");
    println!("Tree root: {:?}", tree.root.into_bigint());
    
    // Get proof for leaf 0
    let proof = tree.generate_proof(0).expect("Valid index");
    
    // Verify manually
    let zero = Fr254::from(0u64);
    let mut current = compute_leaf(address_fe);
    println!("\nManual verification:");
    println!("Start with leaf = H(address, 0) = {:?}", current.into_bigint());
    
    for (i, elem) in proof.path.iter().enumerate() {
        let (left, right) = if elem.direction == 0 {
            (current, elem.sibling)
        } else {
            (elem.sibling, current)
        };
        current = zkdrop_cli::poseidon::poseidon_hash_arity2(left, right);
        println!("Level {}: direction={}, hash={:?}", i, elem.direction, current.into_bigint());
    }
    
    println!("\nFinal computed root: {:?}", current.into_bigint());
    println!("Expected root: {:?}", tree.root.into_bigint());
    println!("Match: {}", current == tree.root);
    
    assert!(MerkleTree::verify_proof(&proof), "Native verification should pass");
    println!("✓ Native verification passed");
}
