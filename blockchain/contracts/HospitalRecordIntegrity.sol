// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title HospitalRecordIntegrity
 * @notice Smart contract for anchoring cryptographic SHA-256 integrity proofs
 * of hospital patient profiles and medical record versions.
 * 
 * ACADEMIC & SECURITY ARCHITECTURE:
 * - Append-only cryptographic ledger.
 * - Stores ONLY opaque record types, record IDs, version numbers, SHA-256 hashes,
 *   block timestamps, and anchoring signer addresses.
 * - NEVER stores any protected health information (PHI) or personally identifiable
 *   information (PII) such as patient names, diagnoses, symptoms, or prescriptions.
 * - Prevents hash overwrites and tampering with historical versions.
 */
contract HospitalRecordIntegrity {
    // Contract owner / primary administrator
    address public owner;

    // Authorized anchoring accounts
    mapping(address => bool) public authorizedSigners;

    // Structure of an anchored integrity record
    struct RecordAnchor {
        string recordType;     // "PATIENT_PROFILE" or "MEDICAL_RECORD"
        uint256 recordId;      // Database internal record ID
        uint256 version;       // Monotonically increasing version number
        bytes32 recordHash;    // Deterministic SHA-256 hash of canonical record
        uint256 timestamp;     // Block timestamp when anchored
        address anchoredBy;    // Address that submitted the anchor
        bool exists;           // Existence flag
    }

    // Mapping from unique recordKey to RecordAnchor
    // recordKey = keccak256(abi.encodePacked(recordType, ":", recordId, ":v", version))
    mapping(bytes32 => RecordAnchor) private records;

    // Array of all anchored keys for auditing and explorer listing
    bytes32[] private recordKeys;

    // Events
    event RecordHashStored(
        bytes32 indexed recordKey,
        string recordType,
        uint256 indexed recordId,
        uint256 version,
        bytes32 recordHash,
        uint256 timestamp,
        address indexed anchoredBy
    );

    event SignerAuthorized(address indexed signer);
    event SignerRevoked(address indexed signer);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "HospitalRecordIntegrity: caller is not the owner");
        _;
    }

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || authorizedSigners[msg.sender],
            "HospitalRecordIntegrity: caller is not authorized to anchor records"
        );
        _;
    }

    /**
     * @notice Constructor sets the deploying account as owner and authorized signer.
     */
    constructor() {
        owner = msg.sender;
        authorizedSigners[msg.sender] = true;
        emit SignerAuthorized(msg.sender);
    }

    /**
     * @notice Compute deterministic record lookup key
     */
    function getRecordKey(
        string memory recordType,
        uint256 recordId,
        uint256 version
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(recordType, ":", recordId, ":v", version));
    }

    /**
     * @notice Anchor a SHA-256 hash proof on the blockchain.
     * Rejects duplicate versions and zero hashes.
     */
    function storeRecordHash(
        string memory recordType,
        uint256 recordId,
        uint256 version,
        bytes32 hash
    ) external onlyAuthorized returns (bytes32) {
        require(bytes(recordType).length > 0, "Record type cannot be empty");
        require(recordId > 0, "Record ID must be greater than zero");
        require(version > 0, "Version must be greater than zero");
        require(hash != bytes32(0), "Hash cannot be zero bytes");

        bytes32 key = getRecordKey(recordType, recordId, version);
        require(!records[key].exists, "Record version already anchored on blockchain");

        records[key] = RecordAnchor({
            recordType: recordType,
            recordId: recordId,
            version: version,
            recordHash: hash,
            timestamp: block.timestamp,
            anchoredBy: msg.sender,
            exists: true
        });

        recordKeys.push(key);

        emit RecordHashStored(
            key,
            recordType,
            recordId,
            version,
            hash,
            block.timestamp,
            msg.sender
        );

        return key;
    }

    /**
     * @notice Retrieve an anchored record hash and proof metadata.
     */
    function getRecordHash(
        string memory recordType,
        uint256 recordId,
        uint256 version
    ) external view returns (
        bytes32 hash,
        uint256 timestamp,
        address anchoredBy,
        bool exists
    ) {
        bytes32 key = getRecordKey(recordType, recordId, version);
        RecordAnchor memory rec = records[key];
        return (rec.recordHash, rec.timestamp, rec.anchoredBy, rec.exists);
    }

    /**
     * @notice Check whether a hash anchor exists for a specific version.
     */
    function hashExists(
        string memory recordType,
        uint256 recordId,
        uint256 version
    ) external view returns (bool) {
        bytes32 key = getRecordKey(recordType, recordId, version);
        return records[key].exists;
    }

    /**
     * @notice Get total count of anchored records.
     */
    function totalAnchoredRecords() external view returns (uint256) {
        return recordKeys.length;
    }

    /**
     * @notice Retrieve record details by index for explorer listing.
     */
    function getRecordAtIndex(uint256 index) external view returns (
        bytes32 key,
        string memory recordType,
        uint256 recordId,
        uint256 version,
        bytes32 recordHash,
        uint256 timestamp,
        address anchoredBy
    ) {
        require(index < recordKeys.length, "Index out of bounds");
        bytes32 k = recordKeys[index];
        RecordAnchor memory rec = records[k];
        return (
            k,
            rec.recordType,
            rec.recordId,
            rec.version,
            rec.recordHash,
            rec.timestamp,
            rec.anchoredBy
        );
    }

    /**
     * @notice Authorize an account to submit anchors.
     */
    function authorizeSigner(address signer) external onlyOwner {
        require(signer != address(0), "Invalid address");
        authorizedSigners[signer] = true;
        emit SignerAuthorized(signer);
    }

    /**
     * @notice Revoke anchoring authorization.
     */
    function revokeSigner(address signer) external onlyOwner {
        require(signer != owner, "Cannot revoke contract owner");
        authorizedSigners[signer] = false;
        emit SignerRevoked(signer);
    }

    /**
     * @notice Transfer contract ownership.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        authorizedSigners[newOwner] = true;
    }
}
