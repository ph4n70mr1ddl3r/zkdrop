// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title ZKDropToken
/// @notice Privacy-preserving airdrop token with ZK claim verification
/// @dev Implements the design from docs/airdrop-design.md
contract ZKDropToken is ERC20, Ownable {
    
    /// @notice Groth16 proof structure
    struct Proof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
    }
    
    /// @notice Public inputs for claim verification
    struct PublicInputs {
        uint256 merkleRoot;
        uint256 nullifier;
        uint256 recipient;
    }
    
    /// @notice BN254 field modulus
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    
    /// @notice Maximum value for 160-bit Ethereum address
    uint256 constant MAX_RECIPIENT = (1 << 160) - 1;
    
    /// @notice Merkle root of eligible addresses (immutable after deployment)
    bytes32 public immutable merkleRoot;
    
    /// @notice Nullifier set to prevent double claims
    mapping(bytes32 => bool) public nullifierUsed;
    
    /// @notice Total number of successful claims
    uint256 public totalClaims;
    
    /// @notice Maximum number of claims allowed
    uint256 public constant MAX_CLAIMS = 10000;
    
    /// @notice Amount of tokens per claim (100,000 tokens with 18 decimals)
    uint256 public constant CLAIM_AMOUNT = 100000 * 10**18;
    
    /// @notice Chain ID for nullifier computation (Base mainnet = 8453)
    uint256 public immutable chainId;
    
    /// @notice Groth16 verifier contract
    IVerifier public immutable verifier;
    
    /// @notice Emitted when a user claims tokens
    event Claim(
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount
    );
    
    /// @notice Emitted when the merkle root is set (at deployment)
    event MerkleRootSet(bytes32 indexed merkleRoot);
    
    /// @param _merkleRoot Root of the Merkle tree containing eligible addresses
    /// @param _verifier Address of the Groth16 verifier contract
    /// @param _chainId Chain ID for nullifier computation
    constructor(
        bytes32 _merkleRoot,
        address _verifier,
        uint256 _chainId
    ) ERC20("ZK Drop Token", "ZKDROP") Ownable(msg.sender) {
        require(uint256(_merkleRoot) < P, "Invalid merkle root");
        require(_verifier != address(0), "Invalid verifier");
        
        merkleRoot = _merkleRoot;
        verifier = IVerifier(_verifier);
        chainId = _chainId;
        
        emit MerkleRootSet(_merkleRoot);
    }
    
    /// @notice Claim tokens using a ZK proof
    /// @param _proof Groth16 proof of eligibility
    /// @param _inputs Public inputs (merkleRoot, nullifier, recipient)
    function claim(
        Proof calldata _proof,
        PublicInputs calldata _inputs
    ) external {
        // 1. Verify merkle root matches
        require(
            bytes32(_inputs.merkleRoot) == merkleRoot,
            "Invalid merkle root"
        );
        
        // 2. Verify nullifier is canonical field element
        require(_inputs.nullifier < P, "Invalid nullifier");
        
        // 3. Verify recipient fits in 160 bits
        require(_inputs.recipient <= MAX_RECIPIENT, "Invalid recipient");
        
        // 4. Check nullifier hasn't been used
        bytes32 nullifierHash = bytes32(_inputs.nullifier);
        require(!nullifierUsed[nullifierHash], "Already claimed");
        
        // 5. Check claim cap
        require(totalClaims < MAX_CLAIMS, "Max claims reached");
        
        // 6. Verify ZK proof
        require(
            verifyProof(_proof, _inputs),
            "Invalid proof"
        );
        
        // 7. Mark nullifier as used
        nullifierUsed[nullifierHash] = true;
        
        // 8. Increment claim count
        totalClaims++;
        
        // 9. Mint tokens to recipient
        address recipient = address(uint160(_inputs.recipient));
        _mint(recipient, CLAIM_AMOUNT);
        
        emit Claim(nullifierHash, recipient, CLAIM_AMOUNT);
    }
    
    /// @notice Verify a Groth16 proof
    /// @param _proof The proof to verify
    /// @param _inputs The public inputs
    /// @return Whether the proof is valid
    function verifyProof(
        Proof calldata _proof,
        PublicInputs calldata _inputs
    ) internal view returns (bool) {
        // Prepare public inputs array: [merkleRoot, nullifier, recipient]
        uint256[3] memory publicSignals = [
            _inputs.merkleRoot,
            _inputs.nullifier,
            _inputs.recipient
        ];
        
        return verifier.verifyProof(
            _proof.a,
            _proof.b,
            _proof.c,
            publicSignals
        );
    }
    
    /// @notice Check if a nullifier has been used
    /// @param _nullifier The nullifier to check
    /// @return Whether the nullifier has been used
    function isNullifierUsed(uint256 _nullifier) external view returns (bool) {
        return nullifierUsed[bytes32(_nullifier)];
    }
    
    /// @notice Get remaining claim slots
    /// @return Number of remaining claim slots
    function remainingClaims() external view returns (uint256) {
        if (totalClaims >= MAX_CLAIMS) {
            return 0;
        }
        return MAX_CLAIMS - totalClaims;
    }
    
    /// @notice Get total supply cap (max claims * claim amount)
    /// @return Maximum possible total supply
    function maxSupply() external pure returns (uint256) {
        return MAX_CLAIMS * CLAIM_AMOUNT;
    }
}

/// @title IVerifier
/// @notice Interface for Groth16 verifier contract
interface IVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[3] calldata input
    ) external view returns (bool);
}
