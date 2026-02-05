# ZK Drop CLI - Proving Time Benchmarks

This directory contains the Rust CLI and benchmarking tools for the privacy-preserving airdrop system.

## Structure

```
zkdrop-cli/
├── Cargo.toml          # Project configuration
├── src/
│   ├── lib.rs          # Main library exports
│   ├── circuit.rs      # ZK circuit implementations
│   ├── merkle.rs       # Merkle tree construction
│   └── poseidon.rs     # Poseidon hash implementation
├── benches/
│   ├── proving_time.rs         # Basic proving time benchmarks
│   └── merkle_tree_height.rs   # Scaling benchmarks with extrapolation
└── tests/
    └── proving_time_test.rs    # Integration tests with detailed reports
```

## Running Benchmarks

### 1. Criterion Benchmarks (Statistical Analysis)

```bash
# Basic proving time benchmarks
cargo bench --bench proving_time

# Merkle tree height scaling with extrapolation
cargo bench --bench merkle_tree_height
```

Criterion generates HTML reports in `target/criterion/`.

### 2. Integration Tests (Detailed Reports)

```bash
# Run proving time tests with output
cargo test proving_time -- --nocapture

# Run all tests
cargo test -- --nocapture
```

## Expected Results

Based on the circuit design:

| Tree Height | Max Addresses | Est. Constraints | Est. Proving Time* |
|-------------|---------------|------------------|-------------------|
| 10 | 1,024 | ~127,000 | ~1-5 seconds |
| 16 | 65,536 | ~128,200 | ~2-10 seconds |
| 20 | 1,048,576 | ~129,000 | ~3-15 seconds |
| **26** | **67,108,864** | **~130,200** | **~5-30 seconds** |

*Estimates assume optimized Groth16 on modern hardware. Full circuit with secp256k1 + Keccak256 may be 2-5x slower.

## Performance Factors

The proving time depends on:

1. **Constraint count**: ~130k for height 26
   - secp256k1 pubkey derivation: ~100k constraints
   - Keccak256: ~25k constraints
   - Merkle path (26 levels): ~5k constraints
   - Nullifier + misc: ~1k constraints

2. **Hardware**:
   - CPU: Multi-core helps with FFTs
   - Memory: 8GB+ recommended for large circuits
   - Optional: GPU acceleration (not included in this version)

3. **Optimization strategies**:
   - Parallel witness generation
   - Custom Poseidon gates
   - Assembly-optimized field arithmetic

## Interpreting Results

### Acceptable Proving Times

| Time | UX Assessment |
|------|---------------|
| < 30s | ✅ Excellent - users can wait |
| 30s - 2min | ⚠️ Acceptable - needs progress indicator |
| 2min - 5min | ⚠️ Slow - consider optimizations |
| > 5min | ❌ Too slow - optimizations required |

### If Proving is Too Slow

1. **Use GPU acceleration**: Replace ark-groth16 with bellperson or rapidsnark
2. **Distributed proving**: Split witness generation across cores
3. **Circuit optimizations**: Custom gates for Poseidon and secp256k1
4. **Precomputation**: Cache FFT tables between proofs

## Design Document Compliance

The benchmarks test the circuit architecture specified in `docs/airdrop-design.md`:

- ✅ BN254 field
- ✅ Groth16 proving system
- ✅ Poseidon hash (arity 2 and 4)
- ✅ Merkle tree height 26 for 65M addresses
- ✅ Nullifier computation structure

## Future Improvements

1. Add full secp256k1 gadget (currently simulated)
2. Add Keccak256 gadget (currently simulated)
3. GPU acceleration support
4. Parallel witness generation
5. Proof caching for testing
