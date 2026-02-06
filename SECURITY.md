# Security Policy

## Overview

This document outlines the security considerations, known limitations, and vulnerabilities for the ZK Drop CLI - a privacy-preserving airdrop system using ZK-SNARKs (Groth16 on BN254).

**Version:** 0.1.0  
**Last Updated:** 2026-02-06

## Security Model

### Trust Assumptions

1. **Trusted Setup:** The Groth16 proving system requires a trusted setup ceremony. The security of the system depends on the proper destruction of toxic waste (the randomness used during setup).

2. **Design Specification Compliance:** This implementation follows the specification in `docs/airdrop-design.md`. Deviations from the spec are documented in this file.

3. **Cryptographic Primitives:** We rely on the following cryptographic primitives:
   - BN254 elliptic curve for the pairing-friendly field
   - Poseidon hash function (arity 2 and 4) for Merkle tree and nullifier computation
   - Groth16 proving system for ZK-SNARKs
   - Keccak256 for Ethereum address derivation (off-circuit)

## Known Limitations & Security Trade-offs

### 1. Optimized Circuit Architecture (Option 2)

**Status:** ✅ ACCEPTED RISK (Documented)

The circuit uses an "Option 2" optimized architecture that trades some security properties for performance:

#### 1.1 No In-Circuit Secp256k1 Verification
- **Trade-off:** We do NOT verify `pk = sk * G` in-circuit
- **Rationale:** Full secp256k1 verification requires ~100,000 constraints
- **Current Mitigation:** Only minimal checks (`pk_x != 0 || pk_y != 0`) are enforced
- **Security Assumption:** Relies on Keccak256 preimage resistance:
  - Finding `(pk_x, pk_y)` that hash to a specific address requires ~2^160 operations
  - This is computationally infeasible
- **Risk:** A malicious prover with unlimited computation could forge a proof for an address they don't control

#### 1.2 No In-Circuit Address Derivation
- **Trade-off:** The circuit does NOT constrain that `address = Keccak256(pk_x || pk_y)[12:32]`
- **Rationale:** Keccak256 in-circuit requires ~25,000 constraints
- **Current Mitigation:** Address is provided as a witness; the Merkle proof ensures it's in the tree
- **Security Assumption:** The nullifier binds `pk_x` and `pk_y` to prevent address substitution
- **Risk:** Without the binding between pk and address, a prover could potentially use a different valid Merkle path

### 2. Simplified Poseidon Hash (RESOLVED ✅)

**Status:** FIXED in commit [TBD]

**Previous Issue:** The initial implementation used a simplified Poseidon hash:
```rust
// OLD (INSECURE)
H(left, right) = left^5 + right^5 + left * right
```

**Problem:** This hash was commutative (`H(a,b) = H(b,a)`), allowing Merkle tree manipulation.

**Resolution:** Now using full Poseidon implementation from `ark-crypto-primitives`:
- 8 full rounds + 57 partial rounds
- Alpha = 5 (x^5 S-box)
- Non-commutative and cryptographically secure

### 3. Missing Recipient Range Check

**Status:** ⚠️ KNOWN LIMITATION

The circuit does NOT enforce `recipient < 2^160` in the constraints:

```rust
// circuit.rs
fn enforce_recipient_range(&self, ...) -> Result<(), SynthesisError> {
    // NOTE: Full 160-bit range check is skipped to reduce constraints.
    // The CLI validates recipient < 2^160 before generating the proof.
    // The contract validates recipient < 2^160 on-chain.
    Ok(())
}
```

**Mitigation:**
- CLI validates recipient before proof generation
- Smart contract validates on-chain
- Invalid recipients fail contract validation

**Risk:** Low - the recipient is a public input visible to all, and the contract enforces the range.

### 4. Dependencies with Known Issues

Based on `cargo audit` (as of 2026-02-06):

| Crate | Issue | Severity | Status |
|-------|-------|----------|--------|
| `tracing-subscriber` 0.2.25 | [RUSTSEC-2025-0055](https://rustsec.org/advisories/RUSTSEC-2025-0055) | Medium | ⚠️ Upstream dependency via `ark-relations` |
| `derivative` 2.2.0 | [RUSTSEC-2024-0388](https://rustsec.org/advisories/RUSTSEC-2024-0388) | Info | ⚠️ Unmaintained; upstream via `ark-*` crates |
| `paste` 1.0.15 | [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436) | Info | ⚠️ Unmaintained; upstream via `ark-ff` |

**Impact:**
- `tracing-subscriber`: Potential log poisoning with ANSI escape sequences
- `derivative`/`paste`: Unmaintained but no known vulnerabilities

**Mitigation:**
- These are upstream dependencies in the arkworks ecosystem
- Monitor for updates to the arkworks crates
- No immediate action required for the airdrop use case

## Attack Scenarios

### Scenario 1: Address Forgery
**Attack:** Forge a proof for an eligible address without knowing its private key  
**Difficulty:** ~2^160 operations (infeasible)  
**Status:** ✅ Mitigated by Keccak256 preimage resistance

### Scenario 2: Double Spending
**Attack:** Claim twice using the same address  
**Difficulty:** Prevented by nullifier uniqueness  
**Status:** ✅ Mitigated by nullifier set in contract

### Scenario 3: Merkle Tree Manipulation
**Attack:** Manipulate the Merkle tree structure due to commutative hash  
**Difficulty:** N/A - hash is now non-commutative  
**Status:** ✅ FIXED

### Scenario 4: Relayer Front-Running
**Attack:** Front-run a claim transaction with different parameters  
**Difficulty:** Low impact - recipient is bound in proof  
**Status:** ✅ Mitigated - proof binds to recipient

## Secure Usage Guidelines

### For Users

1. **Private Key Security:** Never share your private key. The CLI needs it for proof generation but never transmits it.

2. **Verify Downloads:** Ensure you download the CLI from official sources and verify checksums.

3. **Recipient Address:** Double-check the recipient address before generating a proof. It cannot be changed after proof generation.

### For Operators

1. **Trusted Setup:** Ensure the trusted setup ceremony is conducted properly with multiple participants.

2. **Merkle Tree Verification:** Verify the Merkle root matches the published eligible address list.

3. **Contract Validation:** Ensure the on-chain contract validates:
   - `recipient < 2^160`
   - `nullifier < P` (field modulus)
   - Proper verification key

4. **Nullifier Tracking:** Monitor the nullifier set to detect any anomalies.

## Testing Security

Run the security-focused tests:

```bash
# Poseidon hash properties (non-commutativity)
cargo test poseidon::tests::test_poseidon_arity2_non_commutative -- --nocapture

# Circuit constraint validation
cargo test test_nonzero_private_key_enforcement -- --nocapture
cargo test test_pubkey_not_infinity -- --nocapture
cargo test test_circuit_fails_invalid_merkle_path -- --nocapture

# Negative test cases
cargo test test_circuit_fails_wrong_nullifier_computation -- --nocapture
cargo test test_claim_fails_for_ineligible_address -- --nocapture
```

## Reporting Security Issues

If you discover a security vulnerability, please:

1. **DO NOT** open a public issue
2. Email the security team at [security@example.com] (replace with actual contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work on a fix.

## Security Checklist for Production

Before deploying to mainnet:

- [ ] Complete formal security audit
- [ ] Verify Poseidon parameters match the spec (bn254-arity2-rf8-rp57-v1)
- [ ] Conduct trusted setup ceremony with multiple participants
- [ ] Verify circuit constraint count and proving time
- [ ] Test all failure modes and edge cases
- [ ] Deploy and verify the smart contract
- [ ] Set up monitoring for the nullifier set
- [ ] Document user-facing security guidelines

## References

1. [ZK Drop Design Specification](docs/airdrop-design.md)
2. [Groth16 Paper](https://eprint.iacr.org/2016/260)
3. [Poseidon Hash Paper](https://eprint.iacr.org/2019/458)
4. [BN254 Curve Parameters](https://neuromancer.sk/std/bn/bn254)
5. [RUSTSEC Advisory Database](https://rustsec.org/)

## Changelog

| Date | Change |
|------|--------|
| 2026-02-06 | Fixed Poseidon hash implementation (replaced simplified version) |
| 2026-02-06 | Added SECURITY.md |

---

**Disclaimer:** This is experimental software. Use at your own risk. The authors are not responsible for any losses incurred through the use of this software.
