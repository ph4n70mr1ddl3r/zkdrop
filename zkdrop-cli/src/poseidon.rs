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
use ark_r1cs_std::fields::{fp::FpVar, FieldVar};
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
/// Parameters:
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
/// TODO: Replace with proper Poseidon using bn254-arity2-rf8-rp57-v1 parameters
/// Currently uses placeholder: H(a,b) = a^5 + b^5 + a*b
/// This matches the in-circuit implementation
pub fn poseidon_hash_arity2(left: Fr254, right: Fr254) -> Fr254 {
    // Placeholder implementation (matches circuit)
    use ark_ff::Field;
    let left_5 = left.pow([5u64]);
    let right_5 = right.pow([5u64]);
    left_5 + right_5 + left * right
    
    // Proper implementation (when circuit is updated):
    // let config = get_poseidon_params_arity2();
    // let mut sponge = PoseidonSponge::new(config);
    // sponge.absorb(&left);
    // sponge.absorb(&right);
    // sponge.squeeze_field_elements(1)[0]
}

/// Poseidon hash with arity 4 (for nullifier computation)
/// 
/// TODO: Replace with proper Poseidon using bn254-arity4-rf8-rp57-v1 parameters
/// Currently uses placeholder: H(a,b,c,d) = a^5 + b^5 + c^5 + d^5 + a*b + c*d
pub fn poseidon_hash_arity4(inputs: [Fr254; 4]) -> Fr254 {
    // Placeholder implementation
    use ark_ff::Field;
    let mut result = Fr254::from(0u64);
    for x in inputs {
        result += x.pow([5u64]);
    }
    result + inputs[0] * inputs[1] + inputs[2] * inputs[3]
    
    // Proper implementation (when circuit is updated):
    // let config = get_poseidon_params_arity4();
    // let mut sponge = PoseidonSponge::new(config);
    // for input in inputs.iter() {
    //     sponge.absorb(input);
    // }
    // sponge.squeeze_field_elements(1)[0]
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
    fe.into_bigint().to_bytes_be().try_into().unwrap()
}

/// In-circuit Poseidon hash for arity 2
/// 
/// Note: This is a simplified version using the same x^5 + y^5 + xy formula
/// as the native hash. For production, you should use ark-crypto-primitives'
/// in-circuit Poseidon gadget.
pub fn poseidon_hash_arity2_circuit(
    left: &FpVar<Fr254>,
    right: &FpVar<Fr254>,
) -> Result<FpVar<Fr254>, SynthesisError> {
    // Simplified: use sum of powers
    // In production, use proper Poseidon gadget from ark-crypto-primitives
    let left_2 = left * left;
    let left_4 = &left_2 * &left_2;
    let left_5 = &left_4 * left;
    
    let right_2 = right * right;
    let right_4 = &right_2 * &right_2;
    let right_5 = &right_4 * right;
    
    Ok(left_5 + right_5 + left * right)
}

/// In-circuit Poseidon hash for arity 4
/// 
/// Note: This is a simplified version. For production, use proper Poseidon gadget.
pub fn poseidon_hash_arity4_circuit(
    inputs: [&FpVar<Fr254>; 4],
) -> Result<FpVar<Fr254>, SynthesisError> {
    let mut sum = FpVar::constant(Fr254::from(0u64));
    
    for input in inputs.iter() {
        let x2 = (*input) * (*input);
        let x4 = &x2 * &x2;
        let x5 = &x4 * (*input);
        sum = &sum + &x5;
    }
    
    // Add mixed terms
    let mixed = inputs[0] * inputs[1] + inputs[2] * inputs[3];
    Ok(sum + mixed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

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
}
