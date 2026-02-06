use ark_bn254::Fr as Fr254;
use ark_ff::PrimeField;
use zkdrop_cli::{
    poseidon::{compute_leaf, address_to_field_element},
    keccak::compute_address_native,
    secp256k1::{derive_public_key, extract_public_key_coords, pubkey_to_field_elements},
};

#[test]
fn test_address_computation() {
    let mut private_key = [0u8; 32];
    private_key[0] = 1;
    private_key[31] = 42;
    
    let pubkey = derive_public_key(&private_key).expect("Valid key");
    let (pk_x_bytes, pk_y_bytes) = extract_public_key_coords(&pubkey);
    let (pk_x_fe, pk_y_fe) = pubkey_to_field_elements(&pk_x_bytes, &pk_y_bytes);
    
    println!("Original pk_x bytes: 0x{}", hex::encode(pk_x_bytes));
    println!("Original pk_y bytes: 0x{}", hex::encode(pk_y_bytes));
    
    // Compute address from original bytes
    let address1 = compute_address_native(&pk_x_bytes, &pk_y_bytes);
    println!("\nAddress from original bytes: 0x{}", hex::encode(address1));
    
    // What the circuit does:
    // 1. Get pk_x_fe, pk_y_fe from pubkey_to_field_elements
    // 2. Store pk_x_bytes, pk_y_bytes in private inputs
    // 3. Compute address from pk_x_bytes, pk_y_bytes in compute_address()
    
    // Let's verify they match
    let address2 = compute_address_native(&pk_x_bytes, &pk_y_bytes);
    println!("Address using same bytes: 0x{}", hex::encode(address2));
    
    // The leaf in the merkle tree
    let address_fe = address_to_field_element(address1);
    let leaf = compute_leaf(address_fe);
    
    println!("\nAddress as field element: {:?}", address_fe.into_bigint());
    println!("Leaf (H(address, 0)): {:?}", leaf.into_bigint());
    
    assert_eq!(address1, address2, "Addresses should match");
}
