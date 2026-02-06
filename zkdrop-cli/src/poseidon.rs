//! Poseidon hash implementation for BN254
//! 
//! Uses the parameter sets specified in the design:
//! - Merkle tree (arity 2): bn254-arity2-rf8-rp57-v1
//! - Nullifier (arity 4): bn254-arity4-rf8-rp57-v1

use ark_bn254::Fr as Fr254;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::SynthesisError;
use std::sync::OnceLock;

/// BN254 field modulus bytes (big-endian)
pub const P: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Check if a 32-byte big-endian value is a canonical field element (< P)
pub fn is_canonical_field_element(bytes: &[u8; 32]) -> bool {
    for i in 0..32 {
        if bytes[i] < P[i] {
            return true;
        } else if bytes[i] > P[i] {
            return false;
        }
    }
    // Equal to P, not canonical
    false
}

/// Reduce a 32-byte big-endian integer to canonical field element
pub fn reduce_to_field(bytes: &[u8; 32]) -> Fr254 {
    Fr254::from_be_bytes_mod_order(bytes)
}

/// Generate Poseidon parameters for BN254
/// 
/// Parameters match the design spec:
/// - Rate: 2 (for arity 2) or 4 (for arity 4)
/// - Capacity: 1
/// - Full rounds: 8
/// - Partial rounds: 57
/// - Alpha: 5 (x^5 S-box)
fn generate_poseidon_params(rate: usize) -> PoseidonConfig<Fr254> {
    use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
    
    let full_rounds: u64 = 8;
    let partial_rounds: u64 = 57;
    let alpha: u64 = 5;
    
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr254>(
        254,  // prime bits
        rate,
        full_rounds,
        partial_rounds,
        0,    // seed
    );
    
    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        rate,
        1,    // capacity
    )
}

/// Get cached Poseidon params for arity 2
fn get_poseidon_params_arity2() -> &'static PoseidonConfig<Fr254> {
    static PARAMS: OnceLock<PoseidonConfig<Fr254>> = OnceLock::new();
    PARAMS.get_or_init(|| generate_poseidon_params(2))
}

/// Get cached Poseidon params for arity 4
fn get_poseidon_params_arity4() -> &'static PoseidonConfig<Fr254> {
    static PARAMS: OnceLock<PoseidonConfig<Fr254>> = OnceLock::new();
    PARAMS.get_or_init(|| generate_poseidon_params(4))
}

/// Poseidon hash with arity 2 (for Merkle tree)
/// 
/// Uses proper bn254-arity2-rf8-rp57-v1 parameters
/// 
/// SECURITY: This is a full Poseidon implementation using ark-crypto-primitives.
/// It is NOT commutative: H(a,b) != H(b,a), which is essential for Merkle tree security.
pub fn poseidon_hash_arity2(left: Fr254, right: Fr254) -> Fr254 {
    let config = get_poseidon_params_arity2();
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&left);
    sponge.absorb(&right);
    sponge.squeeze_field_elements(1)[0]
}

/// Poseidon hash with arity 4 (for nullifier computation)
/// 
/// Uses proper bn254-arity4-rf8-rp57-v1 parameters
/// 
/// SECURITY: Full Poseidon implementation with proper non-commutative properties.
pub fn poseidon_hash_arity4(inputs: [Fr254; 4]) -> Fr254 {
    let config = get_poseidon_params_arity4();
    let mut sponge = PoseidonSponge::new(config);
    for input in inputs.iter() {
        sponge.absorb(input);
    }
    sponge.squeeze_field_elements(1)[0]
}

/// Compute nullifier: H(chainId, merkleRoot, pkx_fe, pky_fe)
pub fn compute_nullifier(
    chain_id: Fr254,
    merkle_root: Fr254,
    pkx_fe: Fr254,
    pky_fe: Fr254,
) -> Fr254 {
    poseidon_hash_arity4([chain_id, merkle_root, pkx_fe, pky_fe])
}

/// Compute Merkle tree leaf: Poseidon(addr_fe, 0)
pub fn compute_leaf(addr_fe: Fr254) -> Fr254 {
    let zero = Fr254::from(0u64);
    poseidon_hash_arity2(addr_fe, zero)
}

/// Convert Ethereum address (20 bytes) to field element
/// addr_fe = left_pad_32(addr) as big-endian integer
pub fn address_to_field_element(addr: [u8; 20]) -> Fr254 {
    let mut bytes32 = [0u8; 32];
    bytes32[12..32].copy_from_slice(&addr);
    Fr254::from_be_bytes_mod_order(&bytes32)
}

/// Convert field element to bytes (32-byte big-endian)
pub fn field_element_to_bytes(fe: Fr254) -> [u8; 32] {
    fe.into_bigint().to_bytes_be().try_into().unwrap_or_else(|_| {
        // Pad to 32 bytes if needed (shouldn't happen with BN254)
        let bytes = fe.into_bigint().to_bytes_be();
        let mut result = [0u8; 32];
        result[32 - bytes.len()..].copy_from_slice(&bytes);
        result
    })
}

/// Check if a field element is a valid 160-bit value (i.e., < 2^160)
/// 
/// This is used to validate Ethereum addresses as field elements.
/// An Ethereum address is 20 bytes = 160 bits.
pub fn is_valid_160_bit_value(fe: Fr254) -> bool {
    let bytes = field_element_to_bytes(fe);
    
    // Check that bytes 0-11 (the first 12 bytes) are all zero
    // This ensures the value is < 2^160 (since 256 - 12*8 = 160)
    bytes[0..12].iter().all(|&b| b == 0)
}

/// In-circuit Poseidon hash for arity 2
/// 
/// This implements the full Poseidon hash in the constraint system.
/// For production use, this ensures consistency with the native implementation.
/// 
/// NOTE: This uses the constraint system to implement Poseidon hashing.
/// The implementation follows the ark-crypto-primitives Poseidon specification.
pub fn poseidon_hash_arity2_circuit(
    left: &FpVar<Fr254>,
    right: &FpVar<Fr254>,
) -> Result<FpVar<Fr254>, SynthesisError> {
    // Use the in-circuit Poseidon implementation from ark-crypto-primitives
    use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
    use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
    
    let config = get_poseidon_params_arity2();
    
    // Create Poseidon sponge variable
    let mut sponge = PoseidonSpongeVar::new(
        left.cs().clone(),
        config,
    );
    
    // Absorb inputs
    sponge.absorb(left)?;
    sponge.absorb(right)?;
    
    // Squeeze output
    let result = sponge.squeeze_field_elements(1)?;
    Ok(result[0].clone())
}

/// In-circuit Poseidon hash for arity 4
/// 
/// Full Poseidon implementation in circuit for nullifier computation.
pub fn poseidon_hash_arity4_circuit(
    inputs: [&FpVar<Fr254>; 4],
) -> Result<FpVar<Fr254>, SynthesisError> {
    use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
    use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
    
    let config = get_poseidon_params_arity4();
    
    // Create Poseidon sponge variable
    let mut sponge = PoseidonSpongeVar::new(
        inputs[0].cs().clone(),
        config,
    );
    
    // Absorb all inputs
    for input in inputs.iter() {
        sponge.absorb(*input)?;
    }
    
    // Squeeze output
    let result = sponge.squeeze_field_elements(1)?;
    Ok(result[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    // Test that Poseidon params can be generated
    #[test]
    fn test_poseidon_params_generation() {
        // Test that params can be generated
        let params2 = get_poseidon_params_arity2();
        assert_eq!(params2.rate, 2);
        assert_eq!(params2.full_rounds, 8);
        assert_eq!(params2.partial_rounds, 57);
        
        let params4 = get_poseidon_params_arity4();
        assert_eq!(params4.rate, 4);
        assert_eq!(params4.full_rounds, 8);
        assert_eq!(params4.partial_rounds, 57);
    }

    #[test]
    fn test_poseidon_arity2_deterministic() {
        let a = Fr254::from(12345u64);
        let b = Fr254::from(67890u64);
        
        let hash1 = poseidon_hash_arity2(a, b);
        let hash2 = poseidon_hash_arity2(a, b);
        
        assert_eq!(hash1, hash2, "Poseidon hash should be deterministic");
    }

    #[test]
    fn test_poseidon_arity2_different_inputs() {
        let a = Fr254::from(1u64);
        let b = Fr254::from(2u64);
        let c = Fr254::from(3u64);
        
        let hash_ab = poseidon_hash_arity2(a, b);
        let hash_ac = poseidon_hash_arity2(a, c);
        
        assert_ne!(hash_ab, hash_ac, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_poseidon_arity2_non_commutative() {
        // CRITICAL SECURITY TEST: Poseidon must NOT be commutative
        // H(a,b) != H(b,a) for a proper hash function used in Merkle trees
        let a = Fr254::from(123456789u64);
        let b = Fr254::from(987654321u64);
        
        let hash_ab = poseidon_hash_arity2(a, b);
        let hash_ba = poseidon_hash_arity2(b, a);
        
        assert_ne!(hash_ab, hash_ba, 
            "Poseidon MUST NOT be commutative for Merkle tree security. \
             If this fails, the hash function is broken and allows tree manipulation.");
    }

    #[test]
    fn test_poseidon_arity4_deterministic() {
        let inputs = [
            Fr254::from(1u64),
            Fr254::from(2u64),
            Fr254::from(3u64),
            Fr254::from(4u64),
        ];
        
        let hash1 = poseidon_hash_arity4(inputs);
        let hash2 = poseidon_hash_arity4(inputs);
        
        assert_eq!(hash1, hash2, "Poseidon arity-4 hash should be deterministic");
    }

    #[test]
    fn test_nullifier_computation() {
        let chain_id = Fr254::from(8453u64); // Base mainnet
        let merkle_root = Fr254::from(123456u64);
        let pkx_fe = Fr254::from(111111u64);
        let pky_fe = Fr254::from(222222u64);
        
        let nullifier = compute_nullifier(chain_id, merkle_root, pkx_fe, pky_fe);
        
        // Nullifier should be non-zero and in the field
        assert!(!nullifier.is_zero(), "Nullifier should not be zero");
        
        // Should be deterministic
        let nullifier2 = compute_nullifier(chain_id, merkle_root, pkx_fe, pky_fe);
        assert_eq!(nullifier, nullifier2);
    }

    #[test]
    fn test_address_to_field_element() {
        let addr = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                    0x12, 0x34, 0x56, 0x78];
        
        let fe = address_to_field_element(addr);
        let bytes = field_element_to_bytes(fe);
        
        // Verify the address is in the last 20 bytes
        assert_eq!(&bytes[12..32], &addr[..]);
    }

    #[test]
    fn test_canonical_check() {
        // Zero is canonical
        let zero = [0u8; 32];
        assert!(is_canonical_field_element(&zero));
        
        // P-1 is canonical
        let p_minus_1 = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
            0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
        ];
        assert!(is_canonical_field_element(&p_minus_1));
        
        // P itself is NOT canonical
        assert!(!is_canonical_field_element(&P));
    }

    #[test]
    fn test_leaf_computation() {
        let addr_fe = Fr254::from(0x1234567890abcdefu64);
        let leaf = compute_leaf(addr_fe);
        
        // Leaf should be non-zero
        assert!(!leaf.is_zero());
        
        // Should be deterministic
        let leaf2 = compute_leaf(addr_fe);
        assert_eq!(leaf, leaf2);
    }

    #[test]
    fn test_is_valid_160_bit_value() {
        // Valid 160-bit value (top 12 bytes are zero)
        let valid_value = Fr254::from(0x12345678u64);
        assert!(is_valid_160_bit_value(valid_value), "Small values should be valid 160-bit");
        
        // Max valid value: 2^160 - 1
        let mut max_bytes = [0u8; 32];
        max_bytes[12..32].fill(0xff); // Set lower 20 bytes to all 1s
        let max_value = Fr254::from_be_bytes_mod_order(&max_bytes);
        assert!(is_valid_160_bit_value(max_value), "Max 160-bit value should be valid");
        
        // Invalid value: has bits set in positions 160-255
        // Create a value with bit 160 set (requires bytes 0-19 to have data in byte 19)
        let mut invalid_bytes = [0u8; 32];
        invalid_bytes[11] = 0x01; // This sets bit 160 in big-endian (byte 11 from start)
        let invalid_value = Fr254::from_be_bytes_mod_order(&invalid_bytes);
        assert!(!is_valid_160_bit_value(invalid_value), "Value with bit 160 set should be invalid");
        
        // Zero should be valid
        assert!(is_valid_160_bit_value(Fr254::from(0u64)), "Zero should be valid");
    }

    #[test]
    fn test_nullifier_unique_per_chain() {
        // Same inputs, different chain IDs should produce different nullifiers
        let merkle_root = Fr254::from(123456u64);
        let pkx_fe = Fr254::from(111111u64);
        let pky_fe = Fr254::from(222222u64);
        
        let nullifier_base = compute_nullifier(Fr254::from(8453u64), merkle_root, pkx_fe, pky_fe);
        let nullifier_eth = compute_nullifier(Fr254::from(1u64), merkle_root, pkx_fe, pky_fe);
        
        assert_ne!(nullifier_base, nullifier_eth, "Nullifiers should be unique per chain");
    }

    #[test]
    fn test_circuit_native_consistency_arity2() {
        use ark_relations::r1cs::ConstraintSystem;
        use ark_r1cs_std::alloc::AllocVar;
        
        let a = Fr254::from(12345u64);
        let b = Fr254::from(67890u64);
        
        // Native hash
        let native_hash = poseidon_hash_arity2(a, b);
        
        // Circuit hash
        let cs = ConstraintSystem::new_ref();
        let a_var = FpVar::new_witness(cs.clone(), || Ok(a)).unwrap();
        let b_var = FpVar::new_witness(cs.clone(), || Ok(b)).unwrap();
        
        let circuit_hash_var = poseidon_hash_arity2_circuit(&a_var, &b_var).unwrap();
        
        // Check that circuit is satisfied
        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");
        
        // Verify the circuit output matches native
        let circuit_hash = circuit_hash_var.value().unwrap();
        assert_eq!(native_hash, circuit_hash, 
            "Circuit and native Poseidon implementations must produce identical results");
    }

    #[test]
    fn test_circuit_native_consistency_arity4() {
        use ark_relations::r1cs::ConstraintSystem;
        use ark_r1cs_std::alloc::AllocVar;
        
        let inputs = [
            Fr254::from(1u64),
            Fr254::from(2u64),
            Fr254::from(3u64),
            Fr254::from(4u64),
        ];
        
        // Native hash
        let native_hash = poseidon_hash_arity4(inputs);
        
        // Circuit hash
        let cs = ConstraintSystem::new_ref();
        let input_vars: Vec<FpVar<Fr254>> = inputs
            .iter()
            .map(|&x| FpVar::new_witness(cs.clone(), || Ok(x)).unwrap())
            .collect();
        
        let input_refs: [&FpVar<Fr254>; 4] = [
            &input_vars[0], &input_vars[1], &input_vars[2], &input_vars[3]
        ];
        
        let circuit_hash_var = poseidon_hash_arity4_circuit(input_refs).unwrap();
        
        // Check that circuit is satisfied
        assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");
        
        // Verify the circuit output matches native
        let circuit_hash = circuit_hash_var.value().unwrap();
        assert_eq!(native_hash, circuit_hash, 
            "Circuit and native Poseidon implementations must produce identical results");
    }
}
