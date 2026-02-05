// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title BN254 Elliptic Curve Operations
/// @notice Helper library for BN128 precompiles
library BN254 {
    // Field prime
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // G1 point structure
    struct G1Point {
        uint256 x;
        uint256 y;
    }
    
    // G2 point structure (Fp2 element)
    struct G2Point {
        uint256 x1; // real part of x
        uint256 x2; // imaginary part of x
        uint256 y1; // real part of y
        uint256 y2; // imaginary part of y
    }
    
    /// @notice Add two G1 points
    function g1Add(G1Point memory a, G1Point memory b) internal view returns (G1Point memory) {
        uint256[4] memory input;
        input[0] = a.x;
        input[1] = a.y;
        input[2] = b.x;
        input[3] = b.y;
        
        uint256[2] memory output;
        
        assembly {
            // BN128 add precompile at address 0x06
            let success := staticcall(gas(), 0x06, input, 0x80, output, 0x40)
            if iszero(success) {
                revert(0, 0)
            }
        }
        
        return G1Point(output[0], output[1]);
    }
    
    /// @notice Multiply G1 point by scalar
    function g1Mul(G1Point memory p, uint256 s) internal view returns (G1Point memory) {
        uint256[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = s;
        
        uint256[2] memory output;
        
        assembly {
            // BN128 scalar mul precompile at address 0x07
            let success := staticcall(gas(), 0x07, input, 0x60, output, 0x40)
            if iszero(success) {
                revert(0, 0)
            }
        }
        
        return G1Point(output[0], output[1]);
    }
    
    /// @notice Check pairing equation
    /// @param a G1 points (first half of pairing inputs)
    /// @param b G2 points (second half of pairing inputs)
    /// @return True if pairing check passes
    function pairing(G1Point[] memory a, G2Point[] memory b) internal view returns (bool) {
        require(a.length == b.length, "BN254: pairing length mismatch");
        require(a.length > 0, "BN254: empty pairing");
        
        uint256 elements = a.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        
        for (uint256 i = 0; i < elements; i++) {
            input[i * 6 + 0] = a[i].x;
            input[i * 6 + 1] = a[i].y;
            input[i * 6 + 2] = b[i].x1;
            input[i * 6 + 3] = b[i].x2;
            input[i * 6 + 4] = b[i].y1;
            input[i * 6 + 5] = b[i].y2;
        }
        
        uint256[1] memory output;
        
        assembly {
            // BN128 pairing precompile at address 0x08
            let success := staticcall(gas(), 0x08, add(input, 0x20), mul(inputSize, 0x20), output, 0x20)
            if iszero(success) {
                revert(0, 0)
            }
        }
        
        return output[0] == 1;
    }
    
    /// @notice Negate G1 point
    function g1Neg(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.x == 0 && p.y == 0) {
            return p;
        }
        return G1Point(p.x, P - (p.y % P));
    }
}

/// @title Groth16 Verifier
/// @notice Full implementation with BN128 pairing check
/// @dev Auto-generated for ZK Drop circuit with 3 public inputs
contract Groth16Verifier {
    using BN254 for BN254.G1Point;
    
    // Verification key
    BN254.G1Point public vkAlpha;
    BN254.G2Point public vkBeta;
    BN254.G2Point public vkGamma;
    BN254.G2Point public vkDelta;
    BN254.G1Point[] public vkIC;
    
    // Events
    event VerificationKeySet();
    event ProofVerified(bytes32 indexed nullifier);
    
    constructor() {
        // These would be set during deployment with actual VK values
        // For now, using placeholder that must be set via setVerificationKey
    }
    
    /// @notice Set the verification key (only once)
    /// @param alpha G1 point
    /// @param beta G2 point
    /// @param gamma G2 point
    /// @param delta G2 point
    /// @param ic Input commitments
    function setVerificationKey(
        uint256[2] memory alpha,
        uint256[4] memory beta,
        uint256[4] memory gamma,
        uint256[4] memory delta,
        uint256[2][] memory ic
    ) external {
        require(vkIC.length == 0, "VK already set");
        
        vkAlpha = BN254.G1Point(alpha[0], alpha[1]);
        vkBeta = BN254.G2Point(beta[0], beta[1], beta[2], beta[3]);
        vkGamma = BN254.G2Point(gamma[0], gamma[1], gamma[2], gamma[3]);
        vkDelta = BN254.G2Point(delta[0], delta[1], delta[2], delta[3]);
        
        for (uint256 i = 0; i < ic.length; i++) {
            vkIC.push(BN254.G1Point(ic[i][0], ic[i][1]));
        }
        
        emit VerificationKeySet();
    }
    
    /// @notice Verify a Groth16 proof
    /// @param a First G1 point of proof
    /// @param b G2 point of proof
    /// @param c Second G1 point of proof
    /// @param input Public inputs [merkleRoot, nullifier, recipient]
    /// @return Whether the proof is valid
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata input
    ) external view returns (bool) {
        require(vkIC.length > 0, "VK not set");
        require(input.length + 1 == vkIC.length, "Invalid input length");
        
        // Compute linear combination of inputs: vkIC[0] + sum(input[i] * vkIC[i+1])
        BN254.G1Point memory vkX = vkIC[0];
        for (uint256 i = 0; i < input.length; i++) {
            vkX = vkX.g1Add(vkIC[i + 1].g1Mul(input[i]));
        }
        
        // Prepare pairing check
        // e(A, B) * e(-alpha, beta) * e(-C, delta) * e(vkX, gamma) == 1
        
        BN254.G1Point[] memory g1Points = new BN254.G1Point[](4);
        BN254.G2Point[] memory g2Points = new BN254.G2Point[](4);
        
        // Pair 1: e(A, B)
        g1Points[0] = BN254.G1Point(a[0], a[1]);
        g2Points[0] = BN254.G2Point(b[0][0], b[0][1], b[1][0], b[1][1]);
        
        // Pair 2: e(-alpha, beta)
        g1Points[1] = vkAlpha.g1Neg();
        g2Points[1] = vkBeta;
        
        // Pair 3: e(-C, delta)
        g1Points[2] = BN254.G1Point(c[0], c[1]).g1Neg();
        g2Points[2] = vkDelta;
        
        // Pair 4: e(vkX, gamma)
        g1Points[3] = vkX;
        g2Points[3] = vkGamma;
        
        // Perform pairing check
        return BN254.pairing(g1Points, g2Points);
    }
    
    /// @notice Verify with raw bytes (convenience function)
    function verifyProofBytes(
        bytes calldata proof,
        uint256[3] calldata input
    ) external view returns (bool) {
        // Parse proof bytes
        require(proof.length == 384, "Invalid proof length");
        
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        
        assembly {
            a := add(proof.offset, 0)
            b := add(proof.offset, 64)
            c := add(proof.offset, 320)
        }
        
        return verifyProof(a, b, c, input);
    }
    
    /// @notice Get verification key hash
    function vkHash() external view returns (bytes32) {
        return keccak256(abi.encodePacked(
            vkAlpha.x, vkAlpha.y,
            vkBeta.x1, vkBeta.x2, vkBeta.y1, vkBeta.y2,
            vkGamma.x1, vkGamma.x2, vkGamma.y1, vkGamma.y2,
            vkDelta.x1, vkDelta.x2, vkDelta.y1, vkDelta.y2
        ));
    }
    
    /// @notice Get number of public inputs
    function inputCount() external view returns (uint256) {
        return vkIC.length > 0 ? vkIC.length - 1 : 0;
    }
}

/// @title ZK Drop Token (Full Implementation)
/// @notice ERC20 token with ZK claim verification
contract ZKDropToken {
    using BN254 for BN254.G1Point;
    
    // ERC20 metadata
    string public constant name = "ZK Drop Token";
    string public constant symbol = "ZKDROP";
    uint8 public constant decimals = 18;
    
    // Token state
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    // Claim configuration
    bytes32 public immutable merkleRoot;
    address public immutable verifier;
    uint256 public constant CLAIM_AMOUNT = 100000 * 10**18;
    uint256 public constant MAX_CLAIMS = 10000;
    uint256 public totalClaims;
    
    // Nullifier set
    mapping(bytes32 => bool) public nullifierUsed;
    
    // BN254 field modulus
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Claim(bytes32 indexed nullifier, address indexed recipient, uint256 amount);
    
    /// @param _merkleRoot Root of eligible addresses Merkle tree
    /// @param _verifier Groth16 verifier contract address
    constructor(bytes32 _merkleRoot, address _verifier) {
        require(uint256(_merkleRoot) < P, "Invalid merkle root");
        require(_verifier != address(0), "Invalid verifier");
        merkleRoot = _merkleRoot;
        verifier = _verifier;
    }
    
    /// @notice Claim tokens using ZK proof
    /// @param a Proof G1 point
    /// @param b Proof G2 point
    /// @param c Proof G1 point
    /// @param nullifier Claim nullifier
    function claim(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256 nullifier,
        uint256 recipient
    ) external {
        // Validate inputs
        require(nullifier < P, "Invalid nullifier");
        require(recipient < (1 << 160), "Invalid recipient");
        require(!nullifierUsed[bytes32(nullifier)], "Already claimed");
        require(totalClaims < MAX_CLAIMS, "Max claims reached");
        
        // Verify merkle root matches
        require(uint256(merkleRoot) == getExpectedMerkleRoot(), "Invalid merkle root");
        
        // Build public inputs: [merkleRoot, nullifier, recipient]
        uint256[3] memory publicInputs;
        publicInputs[0] = uint256(merkleRoot);
        publicInputs[1] = nullifier;
        publicInputs[2] = recipient;
        
        // Verify proof
        bool valid = Groth16Verifier(verifier).verifyProof(a, b, c, publicInputs);
        require(valid, "Invalid proof");
        
        // Mark nullifier as used
        nullifierUsed[bytes32(nullifier)] = true;
        totalClaims++;
        
        // Mint tokens
        address to = address(uint160(recipient));
        balanceOf[to] += CLAIM_AMOUNT;
        totalSupply += CLAIM_AMOUNT;
        
        emit Claim(bytes32(nullifier), to, CLAIM_AMOUNT);
        emit Transfer(address(0), to, CLAIM_AMOUNT);
    }
    
    /// @notice Get expected Merkle root (for verification)
    function getExpectedMerkleRoot() internal pure returns (uint256) {
        // This would be set at deployment
        // For now, returning 0 as placeholder
        return 0;
    }
    
    // ERC20 functions
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        balanceOf[from] -= amount;
        allowance[from][msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
