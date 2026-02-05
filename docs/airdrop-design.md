# Privacy Airdrop Token Design (Base)

Specification for a privacy-preserving airdrop token system:
- A single contract that is both ERC-20 token and claim/airdrop contract.
- A web app that submits proofs and can sponsor gas until funds are exhausted.
- A Rust CLI for offline proof generation.

Goal: allow eligible users (from a public list of ~65M Ethereum addresses) to claim tokens without revealing which eligible address they control, prevent double-claims, and allow any recipient address.

## 1. Requirements

**Core**
- Eligibility list is public and fixed.
- Claim proof must not link to the eligible address.
- Prevent double claims.
- Claimant chooses recipient address.
- Fixed claim amount of 100,000 tokens (18 decimals), i.e. `100000 * 1e18`.
- Limit to the first 10,000 claims; further claims are rejected.
- Proofs are generated offline; prioritize lowest on-chain gas, even with per-circuit trusted setup.
- Deployment target: Base.
- Prefer Rust for CLI and proof generation.
- Slow proof generation is acceptable; it's offline and there is no claim deadline.

**Web app**
- Anyone can submit proofs to claim.
- Optionally sponsor gas while funds last; after that, users pay.

**Non-goals (for now)**
- KYC or user identity.
- Address recovery or disputes.
- Dynamic eligibility updates post-deploy.

## 2. High-Level Architecture

**On-chain (single contract)**
- ERC-20 token logic.
- Immutable `merkleRoot` of eligibility list.
- ZK verifier contract (embedded or linked).
- Nullifier set to prevent double-claims.
- `claim(proof, publicInputs)` mints tokens.

**Off-chain**
- **CLI (Rust)**: Takes user’s private key, computes ZK proof of eligibility, outputs public inputs and proof.
- **Web app**: Submits proof to chain (directly or via relayer for sponsored claims).
- **Relayer** (optional): Pays gas for claims until the budget is exhausted.

## 3. Cryptographic Approach

### 3.1 Proof statement (what the ZK proof asserts)
The prover shows knowledge of private key `sk`:
1. `pk = secp256k1_pubkey(sk)` (derived in-circuit; no separate `pk` input). The circuit must enforce `sk != 0`, and must enforce that `pk` is on-curve and not the point at infinity. See Section 11 for the choice between a full validation gadget vs an optimized gadget that still enforces these minimum constraints.
2. Let `pkx` and `pky` be the 32-byte big-endian X and Y coordinates of `pk` (uncompressed, no `0x04` prefix).
3. `addr` is the last 20 bytes of `keccak256(pkx || pky)` (Ethereum address).
4. `addr_fe = left_pad_32(addr)` interpreted as a big-endian field element.
5. `addr` is included in the Merkle tree of eligible addresses (leaf is `Poseidon(addr_fe, 0)`).
6. The Merkle proof is for the same `addr` derived from `pk`.
7. `nullifier = H(chainId, merkleRoot, pkx_fe, pky_fe)` is computed using the arity-4 Poseidon parameter set listed in Section 3.2 and a fixed input order. This is the only domain separation mechanism (no extra salt or tag). `pkx_fe = pkx mod P` and `pky_fe = pky mod P` (see Section 13). This reduction can map distinct pubkeys to the same `(pkx_fe, pky_fe)` pair; the design assumes this collision risk is negligible and acceptable for the airdrop.
8. The circuit enforces that the `merkleRoot` used in the nullifier computation equals the public input value `merkleRoot`.

**Public inputs** (on-chain):
`merkleRoot`, `nullifier`, `recipient` (ordering in Section 12.3; encoding in Section 13). Each is passed as a `uint256` to the verifier and contract.

`chainId` is fixed in the circuit/verifier and not provided at runtime. For Base mainnet, `chainId = 8453`. Encoding rules are in Section 13.
- The circuit is per-chain; changing `chainId` (e.g., Base Sepolia) requires a new setup and verifier.

**Binding `recipient` in-circuit**
- The circuit must enforce `recipient < 2^160` and that the packed 160-bit value equals the public input `recipient`. `recipient` is not included in the nullifier, so this binding must be enforced by circuit constraints (the contract only checks the range). Without this binding, a relayer could substitute a different `recipient` and still pass the on-chain range check.

**Private inputs**:
- `sk` (private key)
- Merkle path for `addr`

**Why this works**
- The address stays private because only `nullifier` is public and `pk` is never revealed.
- Computing `nullifier = H(chainId, merkleRoot, pkx_fe, pky_fe)` avoids linkability to the address list because it binds to the secret key (via the derived public key reduced mod `p`) and is preimage-resistant under Poseidon. `chainId` is fixed in-circuit, which separates nullifiers per chain without a runtime `chainId` input.
- Double-claim is prevented by storing `nullifier` in contract storage.

### 3.2 Hashes
- Use Poseidon for in-circuit Merkle hashing; the parameter set (field, arity, rounds, constants source) must be fixed and shared by all tooling and the contract verifier.
- Use Keccak for Ethereum address derivation inside the circuit, hashing the 64 raw bytes `pkx || pky` (big-endian, no reduction, no byte swaps).
**Poseidon parameter sets (canonical)**
- Merkle tree (arity 2): `bn254-arity2-rf8-rp57-v1`.
- Nullifier + `chainId` (arity 4): `bn254-arity4-rf8-rp57-v1`.

### 3.3 ZK system options
Tradeoff: *trustless setup* vs *gas cost*. Two tracks:

**Track A: Gas-minimized (selected)**  
- Use Groth16 on BN254.  
- EVM verifier is very cheap (lowest gas).  
- Requires a trusted setup per circuit.  

**Track B: Transparent (trustless)**  
- Use STARK or transparent SNARK (no trusted setup).  
- Proofs are larger, verification is more expensive on EVM.  
- On L2, still workable but significantly higher gas.  

**Decision**  
- Use Track A to minimize per-claim gas on Base.  
- The setup should be a public ceremony to reduce trust risk.  

We can keep the interface constant and swap verifier contracts later if needed, but this would require a redeploy unless an upgradeable pattern is explicitly adopted.

## 4. Merkle Tree Construction

**Inputs**: ~65M Ethereum addresses (public file).
The eligibility list must contain at least one address (`N >= 1`).

**Eligibility list file (source of truth)**
- A plain text file containing one Ethereum address per line.
- Must be lowercase, 0x-prefixed, exactly 40 hex chars after `0x`, and unique.
- The file order is canonical and must be preserved. Utilities must not re-sort.
- The canonical leaf bytes are the 20 address bytes implied by each line; all hex strings and JSON formats are just serialization and must preserve those exact bytes and order.
- This file is the source for Merkle root generation and Merkle path derivation. Tooling may also emit a derived JSON Merkle tree file (Section 12.1) that embeds the same ordered addresses for interoperability.

**Leaf format**
- `leaf = Poseidon(addr_fe, 0)` using the arity-2 parameter set, where `addr_fe` is the 20-byte Ethereum address left-padded to 32 bytes, interpreted as a big-endian integer (see Section 13). The `0` is the field element zero.

**Tree**
- Binary Merkle tree with Poseidon hash.
- Height rule: build level-by-level from the leaf list. If a level has an odd node count and more than one node, duplicate the last node to form a pair, then hash pairs to produce the next level. Repeat until a single root remains. For `N = 1`, the root is the lone leaf (no hashing). The number of hash levels is the smallest `h` such that `2^h >= N`. Implementations must not pre-pad the leaf list to a power of two using a different rule.
- Merkle path length equals the number of hash levels from leaf to root.

**Proof path**
- CLI computes the Merkle path for the user’s address.
- Path is a private input to the ZK proof.
- Direction/index convention: for level `i` (0 = leaf), the path includes the sibling hash and a direction bit where `0 = current node is left`, `1 = current node is right`; the path array is ordered from leaf level upward, and `direction[i]` must equal bit `i` of the 0-based leaf index (LSB-first). Hash order is always `H(left, right)` based on the direction bit. `index` is the source of truth; tooling must recompute `direction` from `index` and reject any mismatch.
- If a node is duplicated due to an odd count at a level, its sibling is the node itself and the direction bit must still follow the leaf index convention above; hashing with identical siblings yields a deterministic parent.

## 5. Smart Contract Design

### 5.1 Contract state
- `bytes32 merkleRoot` (immutable; canonical big-endian field element; constructor must check `uint256(merkleRoot) < P`)
- `mapping(bytes32 => bool) nullifierUsed`
- `uint256 totalClaims`
- `uint256 claimAmount` (`100000 * 1e18`)
- `uint256 maxClaims` (10,000)
- ERC-20 storage (`balances`, `totalSupply`, etc.)

### 5.2 Claim function (core)
```
struct PublicInputs {
    uint256 merkleRoot;
    uint256 nullifier;
    uint256 recipient;
}
```
```
function claim(
    Proof calldata proof,
    PublicInputs calldata inputs
) external {
    require(bytes32(inputs.merkleRoot) == merkleRoot, "bad root");
    require(inputs.nullifier < P, "non-canonical nullifier");
    require(inputs.recipient < (1 << 160), "non-canonical recipient");
    require(!nullifierUsed[bytes32(inputs.nullifier)], "already claimed");
    require(totalClaims < maxClaims, "claims closed"); // enforce cap before verifying to save gas

    verifyProof(proof, inputs); // ZK verifier

    nullifierUsed[bytes32(inputs.nullifier)] = true;
    uint256 amount = claimAmount;
    totalClaims += 1;
    address recipient = address(uint160(inputs.recipient));
    _mint(recipient, amount);
}
```

**Notes**
- `recipient` is part of the public input; the contract derives the mint address from `inputs.recipient`.

### 5.3 Verifier
- The verifier contract is generated from the chosen ZK system.
- Keep verifier logic in a separate internal contract or library.

### 5.4 Gas sponsorship
- Sponsoring gas is an **off-chain** policy.
- Web app runs a relayer wallet that pays gas for claims until the budget is exhausted.

## 6. Web App Design

**Inputs**
- Proof file (format per Section 12.3).

**Flow**
1. User uploads or pastes proof data.
2. Web app validates format and calls `claim()` with the proof and public inputs.
3. If sponsoring is enabled and budget remains, submit via relayer.
4. Otherwise, prompt user to submit via their own wallet.

**Relayer**
- Simple transaction sender service with a capped budget.
- Optional: allow a user signature to prevent relayer misuse (e.g., submitting with unintended gas policy); not required since recipient is bound.
- If a relayer signature/nonce is added later, decide whether it is verified on-chain outside the ZK proof or included in the ZK statement; document and implement consistently. If it is outside the ZK proof, it must bind the same `recipient` as the proof public input. Any relayer signature/nonce must be carried either in a new proof format version or as a separate payload outside `zkdrop/proof-v1`.

## 7. CLI Design (Rust)

**Goals**
- Offline proof generation.
- Deterministic outputs.
- Minimal dependencies beyond ZK stack.

**Inputs**
- Private key (hardware wallet integration later).
- One of:
  - Merkle tree file (canonical format) from which the CLI derives the Merkle path, or
  - Merkle path file (canonical format) already computed for the address.
- Recipient address.

**Outputs**
- Proof file (format per Section 12.3), including `recipient` in public inputs.

**Flow**
1. Parse private key.
2. Derive pubkey (fixed encoding; see Section 3.1) and compute address.
3. Find Merkle path for address.
4. Compute `pkx_fe = pkx mod P`, `pky_fe = pky mod P`, then `nullifier = H(chainId, merkleRoot, pkx_fe, pky_fe)`.
5. Generate proof.
6. Emit proof file (format per Section 12.3).

**Rust options**
- For Track A (Groth16): `arkworks`, `snark-verifier`.
- For Track B (transparent): `plonky2`, `starky`, or RISC-based proving (SP1/Risc0).

## 8. Security Considerations

**Front-running**
- Proofs are bound to `recipient`; front-running only benefits the same recipient.

**Relayer misuse**
- If a relayer signature/nonce is added, it must bind the same `recipient` as the proof public input (see Section 6).

**Double claims**
- Prevented by `nullifierUsed` mapping.

**Linkability**
- Nullifier derived from `pk` avoids direct mapping to addresses.

**Merkle root integrity**
- Root must match the public list. Provide reproducible build scripts and checksums.

## 9. Performance & Cost

**On-chain gas**
- Dominated by proof verification.

**Off-chain proof generation**
- Expensive but acceptable; seconds to minutes.

**Storage**
- `nullifierUsed` mapping grows with claims; there is no safe pruning unless an alternate anti-double-claim mechanism is introduced.

## 10. Implementation Roadmap

1. Lock Track A ZK system (Groth16 on BN254, per-circuit setup).
2. Implement Merkle tree builder and root generator.
3. Build circuit: secp256k1 -> keccak -> merkle inclusion -> nullifier.
4. Generate verifier contract + Solidity integration.
5. Implement ERC-20 + claim contract.
6. Build Rust CLI for proof generation.
7. Build web app + relayer.
8. Testnet deployment and audits.

## 11. Open Questions

- Do we want to publish a supply projection table for transparency?
- Do we want to expose `maxClaims` and `claimAmount` as immutable or upgradeable values?
- Do we want a full secp256k1 validation gadget, or an optimized gadget that still enforces the minimum constraints (non-zero `sk`, `pk` on-curve, not infinity)?

## 12. Canonical File Formats

This section defines minimal, interoperable formats for Merkle data and proof artifacts so the CLI, web app, and third-party tooling agree on exact bytes.
All formats are UTF-8 JSON.
All hex strings in canonical JSON formats must be lowercase and `0x`-prefixed. Fields representing fixed-size values must be fixed-length for their type; the `proof` field is verifier-specific and may be variable length.

**12.1 Merkle tree file (derived JSON)**
- Fields:
  - `format`: string, must be `zkdrop/merkle-tree-v1`.
  - `hash`: string, must be `poseidon` (tools must reject any other value).
  - `field`: string, identifies the field (e.g., `bn254`).
  - `poseidon`: string, parameter set identifier for Poseidon Merkle hashing (must be exactly `bn254-arity2-rf8-rp57-v1`, see Section 3.2).
  - `leaf_encoding`: string, must be `eth_address_be_32` (leaf hash is `Poseidon(addr_fe, 0)` per Section 4).
- `root`: 32-byte hex with `0x` prefix (canonical big-endian field element, `< P`).
- `addresses`: array of 20-byte hex addresses with `0x` prefix (must match the source list order exactly; do not sort).
- The leaf index is the array index in `addresses` (0-based).

Example:
```json
{
  "format": "zkdrop/merkle-tree-v1",
  "hash": "poseidon",
  "field": "bn254",
  "poseidon": "bn254-arity2-rf8-rp57-v1",
  "leaf_encoding": "eth_address_be_32",
  "root": "0x2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c",
  "addresses": [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222"
  ]
}
```

**12.2 Merkle path file**
- Fields:
  - `format`: string, must be `zkdrop/merkle-path-v1`.
- `root`: 32-byte hex with `0x` prefix (canonical big-endian field element, `< P`).
- `leaf`: 20-byte hex with `0x` prefix (Ethereum address; leaf hash derived per Section 4).
- `index`: integer, 0-based leaf index in the published list.
- `path`: array of objects `{ sibling: 32-byte hex, direction: 0 or 1 }` ordered from leaf to root.
- The path order and direction must follow Section 4.

Example:
```json
{
  "format": "zkdrop/merkle-path-v1",
  "root": "0x2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c",
  "leaf": "0x1111111111111111111111111111111111111111",
  "index": 0,
  "path": [
    {
      "sibling": "0x3b7d4e1f3b7d4e1f3b7d4e1f3b7d4e1f3b7d4e1f3b7d4e1f3b7d4e1f3b7d4e1f",
      "direction": 0
    },
    {
      "sibling": "0x7a9c0d1e7a9c0d1e7a9c0d1e7a9c0d1e7a9c0d1e7a9c0d1e7a9c0d1e7a9c0d1e",
      "direction": 1
    }
  ]
}
```

**12.3 Proof file**
- Fields:
  - `format`: string, must be `zkdrop/proof-v1`.
  - `proof`: hex string with `0x` prefix (verifier-specific byte encoding).
  - `public_inputs`: array of 32-byte hex with `0x` prefix ordered `[merkleRoot, nullifier, recipient]` (length must be 3). Each element is a big-endian `uint256` (see Section 13).
  - No other fields are part of the canonical format.

Tools must validate `format` strings and reject any mismatch.

Example:
```json
{
  "format": "zkdrop/proof-v1",
  "proof": "0x0123abcd",
  "public_inputs": [
    "0x2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c2f1c3a7c",
    "0x8e1a9d0f8e1a9d0f8e1a9d0f8e1a9d0f8e1a9d0f8e1a9d0f8e1a9d0f8e1a9d0f",
    "0x0000000000000000000000001111111111111111111111111111111111111111"
  ]
}
```
## 13. Encoding (Canonical Bytes)

**Canonical encoding rules (source of truth)**
- `P` is the BN254 field modulus.
- Field elements are 32-byte big-endian integers with `0 <= x < P`. Non-canonical values must be rejected by tooling and treated as invalid by verifiers.
- `merkleRoot` is the canonical big-endian 32-byte encoding of the Poseidon root field element and must satisfy `< P` (enforced by tooling, circuit if possible, and the contract constructor check plus equality in `claim`).
- `chainId` is a circuit constant and is not a public input. It is encoded as a 32-byte big-endian integer (`uint256`), then interpreted modulo `P`.
- `addr_fe` is the 20-byte address left-padded to 32 bytes, interpreted as a big-endian integer. For BN254 this is always `< P` because the field size exceeds 160 bits.
- `pkx` and `pky` are the 32-byte big-endian coordinates of the secp256k1 public key.
- `pkx_fe` and `pky_fe` are `pkx mod P` and `pky mod P` as field elements used for hashing inside the circuit.
- `recipient_fe = uint256(uint160(recipient_address))` encoded as a 32-byte big-endian integer.
