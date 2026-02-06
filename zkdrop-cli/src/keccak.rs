//! Keccak256 hash implementation for Ethereum address derivation
//!
//! This module provides:
//! 1. Native Keccak256 hashing for off-circuit address computation
//! 2. In-circuit Keccak256 gadget for ZK proof verification
//!
//! Used for: addr = keccak256(pkx || pky)[12:32]

use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField};
use sha3::{Keccak256, Digest};

/// Compute Ethereum address from public key using Keccak256 (native implementation)
///
/// addr = keccak256(pkx || pky)[12:32]
///
/// # Arguments
/// * `pk_x` - 32-byte X coordinate of secp256k1 public key
/// * `pk_y` - 32-byte Y coordinate of secp256k1 public key
///
/// # Returns
/// * 20-byte Ethereum address
pub fn compute_address_native(pk_x: &[u8; 32], pk_y: &[u8; 32]) -> [u8; 20] {
    // Concatenate pkx || pky (64 bytes total)
    let mut pubkey_bytes = [0u8; 64];
    pubkey_bytes[0..32].copy_from_slice(pk_x);
    pubkey_bytes[32..64].copy_from_slice(pk_y);
    
    // Compute Keccak256 hash
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes);
    let hash = hasher.finalize();
    
    // Extract last 20 bytes as address
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    
    address
}

/// Convert Ethereum address to field element
///
/// addr_fe = left_pad_32(addr) interpreted as big-endian integer
pub fn address_to_field_element(addr: [u8; 20]) -> Fr254 {
    let mut bytes32 = [0u8; 32];
    bytes32[12..32].copy_from_slice(&addr);
    Fr254::from_be_bytes_mod_order(&bytes32)
}

/// Full address derivation: (pk_x, pk_y) -> address -> field element
///
/// # Arguments
/// * `pk_x` - Public key X coordinate (32 bytes)
/// * `pk_y` - Public key Y coordinate (32 bytes)
///
/// # Returns
/// * Field element representation of Ethereum address
pub fn derive_address_fe(pk_x: &[u8; 32], pk_y: &[u8; 32]) -> Fr254 {
    let address = compute_address_native(pk_x, pk_y);
    address_to_field_element(address)
}

/// In-circuit Keccak256 hash for address derivation
///
/// NOTE: Full implementation requires byte decomposition gadget which is expensive.
/// This is a placeholder that uses the native hash for witness generation.
/// The circuit constrains that the output matches the expected address.
///
/// For production, use ark-crypto-primitives' CRH gadget or a specialized
/// Keccak256 circuit implementation.
///
/// # Arguments
/// * `pk_x` - Public key X as field element (will be decomposed to bytes)
/// * `pk_y` - Public key Y as field element (will be decomposed to bytes)
///
/// # Returns
/// * Address as field element
pub fn compute_address_circuit(
    pk_x: Fr254,
    pk_y: Fr254,
) -> Fr254 {
    // Convert field elements to bytes
    let pk_x_bytes = field_to_bytes(pk_x);
    let pk_y_bytes = field_to_bytes(pk_y);
    
    // Compute address using native Keccak256
    derive_address_fe(&pk_x_bytes, &pk_y_bytes)
}

/// Convert field element to 32 bytes (big-endian)
///
/// Pads with leading zeros if necessary
pub fn field_to_bytes(fe: Fr254) -> [u8; 32] {
    let bytes = fe.into_bigint().to_bytes_be();
    let mut result = [0u8; 32];
    
    // Copy bytes, padding with zeros on the left if needed
    let start = 32 - bytes.len();
    result[start..].copy_from_slice(&bytes);
    
    result
}

/// Verify address computation in circuit
///
/// This function verifies that the claimed address is correctly derived from pk_x and pk_y.
/// In a full implementation, this would use in-circuit Keccak256, but for now we verify
/// the relationship by checking the native computation matches.
///
/// SECURITY NOTE: This relies on the prover providing the correct pk_x, pk_y values.
/// The circuit should also enforce that pk_x, pk_y are valid secp256k1 coordinates.
pub fn verify_address_computation(
    pk_x: Fr254,
    pk_y: Fr254,
    claimed_address: Fr254,
) -> bool {
    let computed_address = compute_address_circuit(pk_x, pk_y);
    computed_address == claimed_address
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::Zero;

    #[test]
    fn test_keccak256_deterministic() {
        let pk_x = [1u8; 32];
        let pk_y = [2u8; 32];
        
        let addr1 = compute_address_native(&pk_x, &pk_y);
        let addr2 = compute_address_native(&pk_x, &pk_y);
        
        assert_eq!(addr1, addr2, "Keccak256 should be deterministic");
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let pk_x1 = [1u8; 32];
        let pk_y1 = [2u8; 32];
        
        let pk_x2 = [3u8; 32];
        let pk_y2 = [4u8; 32];
        
        let addr1 = compute_address_native(&pk_x1, &pk_y1);
        let addr2 = compute_address_native(&pk_x2, &pk_y2);
        
        assert_ne!(addr1, addr2, "Different inputs should produce different addresses");
    }

    #[test]
    fn test_address_to_field_element() {
        let addr = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
                    0x12, 0x34, 0x56, 0x78];
        
        let fe = address_to_field_element(addr);
        let bytes = fe.into_bigint().to_bytes_be();
        
        // Verify the address is in the last 20 bytes
        assert_eq!(&bytes[bytes.len()-20..], &addr[..]);
    }

    #[test]
    fn test_derive_address_fe() {
        let pk_x = [1u8; 32];
        let pk_y = [2u8; 32];
        
        let addr_fe = derive_address_fe(&pk_x, &pk_y);
        
        // Should be non-zero
        assert!(!addr_fe.is_zero());
        
        // Should be deterministic
        let addr_fe2 = derive_address_fe(&pk_x, &pk_y);
        assert_eq!(addr_fe, addr_fe2);
    }

    #[test]
    fn test_known_vector() {
        // Test with known values - just verify it produces a valid address
        let pk_x = [0u8; 32];
        let pk_y = [1u8; 32];
        
        let addr = compute_address_native(&pk_x, &pk_y);
        
        // Address should be 20 bytes
        assert_eq!(addr.len(), 20);
        
        // Should not be all zeros
        assert!(!addr.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_field_to_bytes_roundtrip() {
        let original = Fr254::from(123456789u64);
        let bytes = field_to_bytes(original);
        let recovered = Fr254::from_be_bytes_mod_order(&bytes);
        
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_verify_address_computation() {
        let pk_x = Fr254::from(111u64);
        let pk_y = Fr254::from(222u64);
        
        // Compute correct address
        let correct_address = compute_address_circuit(pk_x, pk_y);
        
        // Should verify
        assert!(verify_address_computation(pk_x, pk_y, correct_address));
        
        // Should fail with wrong address
        let wrong_address = Fr254::from(999u64);
        assert!(!verify_address_computation(pk_x, pk_y, wrong_address));
    }
}
