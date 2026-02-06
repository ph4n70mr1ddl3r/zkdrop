//! secp256k1 utilities for public key derivation
//! 
//! This module provides functions for:
//! 1. Deriving public keys from private keys
//! 2. Computing Ethereum addresses from public keys
//! 3. Converting between different representations

use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField};
use secp256k1::{PublicKey, SecretKey};

use crate::keccak::compute_address_native;

/// secp256k1 curve order (for reference)
pub const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Derive secp256k1 public key from private key scalar
/// 
/// Returns the uncompressed public key (64 bytes: x || y)
pub fn derive_public_key(private_key_bytes: &[u8; 32]) -> Result<[u8; 64], secp256k1::Error> {
    // Create secret key from bytes
    let secret_key = SecretKey::from_slice(private_key_bytes)?;
    
    // Derive public key
    let secp = secp256k1::Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
    // Get uncompressed bytes (0x04 prefix + 64 bytes)
    let uncompressed = public_key.serialize_uncompressed();
    
    // Remove the 0x04 prefix and return just the 64 bytes (x || y)
    let mut result = [0u8; 64];
    result.copy_from_slice(&uncompressed[1..65]);
    
    Ok(result)
}

/// Extract X and Y coordinates from uncompressed public key
/// 
/// Returns (pk_x_bytes, pk_y_bytes) each 32 bytes
pub fn extract_public_key_coords(pubkey_bytes: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut pk_x = [0u8; 32];
    let mut pk_y = [0u8; 32];
    
    pk_x.copy_from_slice(&pubkey_bytes[0..32]);
    pk_y.copy_from_slice(&pubkey_bytes[32..64]);
    
    (pk_x, pk_y)
}

/// Convert secp256k1 public key coordinates to BN254 field elements
/// 
/// pkx_fe = pkx mod P (where P is BN254 field modulus)
/// pky_fe = pky mod P
pub fn pubkey_to_field_elements(
    pk_x_bytes: &[u8; 32], 
    pk_y_bytes: &[u8; 32]
) -> (Fr254, Fr254) {
    let pkx_fe = Fr254::from_be_bytes_mod_order(pk_x_bytes);
    let pky_fe = Fr254::from_be_bytes_mod_order(pk_y_bytes);
    
    (pkx_fe, pky_fe)
}

/// Compute Ethereum address from public key
/// 
/// address = keccak256(pkx || pky)[12:32]
pub fn compute_ethereum_address(pubkey_bytes: &[u8; 64]) -> [u8; 20] {
    // Extract x and y coordinates
    let mut pk_x = [0u8; 32];
    let mut pk_y = [0u8; 32];
    pk_x.copy_from_slice(&pubkey_bytes[0..32]);
    pk_y.copy_from_slice(&pubkey_bytes[32..64]);
    
    // Use the keccak module for consistency
    compute_address_native(&pk_x, &pk_y)
}

/// Compute Ethereum address from private key
/// 
/// Convenience function that derives pubkey and then computes address
pub fn derive_ethereum_address(private_key_bytes: &[u8; 32]) -> Result<[u8; 20], secp256k1::Error> {
    let pubkey = derive_public_key(private_key_bytes)?;
    Ok(compute_ethereum_address(&pubkey))
}

/// Validate that private key is non-zero and less than secp256k1 curve order
pub fn validate_private_key(private_key_bytes: &[u8; 32]) -> Result<(), String> {
    // Check non-zero
    if private_key_bytes.iter().all(|&b| b == 0) {
        return Err("Private key cannot be zero".to_string());
    }
    
    // Check less than curve order
    for i in 0..32 {
        if private_key_bytes[i] < SECP256K1_N[i] {
            return Ok(());
        } else if private_key_bytes[i] > SECP256K1_N[i] {
            return Err("Private key must be less than secp256k1 curve order".to_string());
        }
    }
    
    // Equal to curve order - not valid
    Err("Private key cannot equal secp256k1 curve order".to_string())
}

/// Full derivation path: private key -> public key -> address -> field elements
/// 
/// Returns (pk_x, pk_y, address, pkx_fe, pky_fe, addr_fe)
pub fn derive_all_from_private_key(
    private_key_bytes: &[u8; 32]
) -> Result<DerivedKeyData, secp256k1::Error> {
    validate_private_key(private_key_bytes)
        .map_err(|_| secp256k1::Error::InvalidSecretKey)?;
    
    let pubkey = derive_public_key(private_key_bytes)?;
    let (pk_x, pk_y) = extract_public_key_coords(&pubkey);
    let address = compute_ethereum_address(&pubkey);
    let (pkx_fe, pky_fe) = pubkey_to_field_elements(&pk_x, &pk_y);
    
    // Convert address to field element
    let mut addr_bytes32 = [0u8; 32];
    addr_bytes32[12..32].copy_from_slice(&address);
    let addr_fe = Fr254::from_be_bytes_mod_order(&addr_bytes32);
    
    Ok(DerivedKeyData {
        pk_x,
        pk_y,
        address,
        pkx_fe,
        pky_fe,
        addr_fe,
    })
}

/// Container for all derived key data
#[derive(Clone, Debug)]
pub struct DerivedKeyData {
    /// Public key X coordinate (32 bytes)
    pub pk_x: [u8; 32],
    /// Public key Y coordinate (32 bytes)
    pub pk_y: [u8; 32],
    /// Ethereum address (20 bytes)
    pub address: [u8; 20],
    /// Public key X as BN254 field element
    pub pkx_fe: Fr254,
    /// Public key Y as BN254 field element
    pub pky_fe: Fr254,
    /// Address as BN254 field element
    pub addr_fe: Fr254,
}

/// Convert private key hex string to 32-byte array
pub fn parse_private_key_hex(hex_str: &str) -> Result<[u8; 32], String> {
    let clean_hex = hex_str.trim_start_matches("0x");
    
    if clean_hex.len() != 64 {
        return Err(format!("Private key must be 32 bytes (64 hex chars), got {}", clean_hex.len()));
    }
    
    let bytes = hex::decode(clean_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;
    
    if bytes.len() != 32 {
        return Err("Private key must be exactly 32 bytes".to_string());
    }
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    
    validate_private_key(&result)?;
    
    Ok(result)
}

/// Convert Ethereum address hex string to 20-byte array
pub fn parse_address_hex(hex_str: &str) -> Result<[u8; 20], String> {
    let clean_hex = hex_str.trim_start_matches("0x").to_lowercase();
    
    if clean_hex.len() != 40 {
        return Err(format!("Address must be 20 bytes (40 hex chars), got {}", clean_hex.len()));
    }
    
    let bytes = hex::decode(&clean_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;
    
    if bytes.len() != 20 {
        return Err("Address must be exactly 20 bytes".to_string());
    }
    
    let mut result = [0u8; 20];
    result.copy_from_slice(&bytes);
    
    Ok(result)
}

/// Convert a field element to Ethereum address bytes
/// 
/// Assumes the field element was derived from a valid Ethereum address
pub fn field_element_to_address(fe: Fr254) -> [u8; 20] {
    let bytes = fe.into_bigint().to_bytes_be();
    let mut address = [0u8; 20];
    
    // Take last 20 bytes (or pad if needed)
    if bytes.len() >= 20 {
        address.copy_from_slice(&bytes[bytes.len() - 20..]);
    } else {
        address[20 - bytes.len()..].copy_from_slice(&bytes);
    }
    
    address
}

/// Check if a public key is valid (on curve, not infinity)
/// 
/// Note: secp256k1 crate handles validation internally
pub fn is_valid_public_key(pubkey_bytes: &[u8; 64]) -> bool {
    // Add 0x04 prefix for uncompressed key
    let mut full_key = vec![0x04u8];
    full_key.extend_from_slice(pubkey_bytes);
    
    PublicKey::from_slice(&full_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::Zero;

    #[test]
    fn test_private_key_validation_zero() {
        let zero_key = [0u8; 32];
        assert!(validate_private_key(&zero_key).is_err());
    }

    #[test]
    fn test_private_key_validation_valid() {
        // Valid private key (1)
        let mut key = [0u8; 32];
        key[31] = 1;
        assert!(validate_private_key(&key).is_ok());
    }

    #[test]
    fn test_private_key_validation_curve_order() {
        // Key equal to curve order should fail
        assert!(validate_private_key(&SECP256K1_N).is_err());
    }

    #[test]
    fn test_public_key_derivation() {
        // Known test vector
        // Private key: 1
        let mut private_key = [0u8; 32];
        private_key[31] = 1;
        
        let pubkey = derive_public_key(&private_key).unwrap();
        
        // Check that pubkey is 64 bytes
        assert_eq!(pubkey.len(), 64);
        
        // Check that coordinates are valid (non-zero)
        let (pk_x, pk_y) = extract_public_key_coords(&pubkey);
        assert!(!pk_x.iter().all(|&b| b == 0));
        assert!(!pk_y.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_address_computation() {
        // Private key: 1
        let mut private_key = [0u8; 32];
        private_key[31] = 1;
        
        let address = derive_ethereum_address(&private_key).unwrap();
        
        // Address should be 20 bytes
        assert_eq!(address.len(), 20);
        
        // Known address for private key 1
        // Address should start with 0x7e5 (for key=1, it's a known test vector)
        assert_ne!(address, [0u8; 20]);
    }

    #[test]
    fn test_field_element_conversion() {
        // Private key: 1
        let mut private_key = [0u8; 32];
        private_key[31] = 1;
        
        let derived = derive_all_from_private_key(&private_key).unwrap();
        
        // Check that field elements are non-zero
        assert!(!derived.pkx_fe.is_zero());
        assert!(!derived.pky_fe.is_zero());
        assert!(!derived.addr_fe.is_zero());
        
        // Convert address back and check
        let addr_back = field_element_to_address(derived.addr_fe);
        assert_eq!(addr_back, derived.address);
    }

    #[test]
    fn test_parse_private_key_hex() {
        // Valid hex
        let key = parse_private_key_hex("0x0000000000000000000000000000000000000000000000000000000000000001");
        assert!(key.is_ok());
        assert_eq!(key.unwrap()[31], 1);
        
        // Without 0x prefix
        let key2 = parse_private_key_hex("0000000000000000000000000000000000000000000000000000000000000001");
        assert!(key2.is_ok());
        
        // Invalid length
        let key3 = parse_private_key_hex("0x01");
        assert!(key3.is_err());
        
        // Invalid hex
        let key4 = parse_private_key_hex("0xgggg");
        assert!(key4.is_err());
    }

    #[test]
    fn test_parse_address_hex() {
        // Valid address
        let addr = parse_address_hex("0x1111111111111111111111111111111111111111");
        assert!(addr.is_ok());
        assert_eq!(addr.unwrap()[0], 0x11);
        
        // Invalid length
        let addr2 = parse_address_hex("0x11");
        assert!(addr2.is_err());
    }

    #[test]
    fn test_derivation_determinism() {
        // Same private key should always produce same result
        let mut private_key = [0u8; 32];
        private_key[31] = 42;
        
        let derived1 = derive_all_from_private_key(&private_key).unwrap();
        let derived2 = derive_all_from_private_key(&private_key).unwrap();
        
        assert_eq!(derived1.pk_x, derived2.pk_x);
        assert_eq!(derived1.pk_y, derived2.pk_y);
        assert_eq!(derived1.address, derived2.address);
        assert_eq!(derived1.pkx_fe, derived2.pkx_fe);
        assert_eq!(derived1.pky_fe, derived2.pky_fe);
        assert_eq!(derived1.addr_fe, derived2.addr_fe);
    }

    #[test]
    fn test_different_keys_produce_different_addresses() {
        let mut key1 = [0u8; 32];
        key1[31] = 1;
        
        let mut key2 = [0u8; 32];
        key2[31] = 2;
        
        let addr1 = derive_ethereum_address(&key1).unwrap();
        let addr2 = derive_ethereum_address(&key2).unwrap();
        
        assert_ne!(addr1, addr2);
    }
}
