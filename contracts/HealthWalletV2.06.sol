// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title HealthWalletV2.06
 * @dev Unified health record management with Merkle tree-based partial sharing
 * 
 * NEW FEATURES:
 * - Unified storage for all record types
 * - Merkle tree support for selective attribute disclosure
 * - IPFS-based partial share packages
 * - Generic structure for PERSONAL_INFO, MEDICATION, VACCINATION, MEDICAL_REPORT
 */
contract HealthWalletV2_06 is Ownable, AccessControl, ReentrancyGuard, Pausable {
    
    // ============================================
    // ENUMS
    // ============================================
    enum RecordType {
        PERSONAL_INFO,
        MEDICATION,
        VACCINATION,
        MEDICAL_REPORT
    }
    
    // ============================================
    // STRUCTS
    // ============================================
    
    /**
     * @dev Unified Record Reference (all record types)
     */
    struct UnifiedRecordRef {
        address owner;
        bytes32 merkleRoot;           // Root of Merkle tree for verification
        string ipfsHash;              // Full encrypted record on IPFS
        string ownerEncryptedKey;     // AES key encrypted with owner's key
        string backendEncryptedKey;   // AES key encrypted with backend's RSA key
        RecordType recordType;        // Type of record
        uint256 timestamp;
        bool isDeleted;
    }
    
    /**
     * @dev Partial Access with IPFS Package
     */
    struct PartialAccessWithIPFS {
        address sharedWith;
        uint256 expiryTime;
        string shareIPFSHash;         // Points to encrypted partial share package
        bool isActive;
    }
    
    // ============================================
    // STATE VARIABLES
    // ============================================
    
    // Single counter for all record types
    uint256 private recordCounter;
    
    // Unified storage for all records
    mapping(uint256 => UnifiedRecordRef) public unifiedRecords;
    
    // Owner's record IDs
    mapping(address => uint256[]) private userRecordIds;
    
    // Partial access grants
    mapping(uint256 => PartialAccessWithIPFS[]) public partialAccessList;
    
    // ============================================
    // EVENTS
    // ============================================
    
    event RecordAdded(
        uint256 indexed recordId,
        address indexed owner,
        RecordType recordType,
        bytes32 merkleRoot,
        uint256 timestamp
    );
    
    event RecordUpdated(
        uint256 indexed recordId,
        bytes32 newMerkleRoot,
        uint256 timestamp
    );
    
    event RecordDeleted(
        uint256 indexed recordId,
        uint256 timestamp
    );
    
    event PartialAccessGranted(
        uint256 indexed recordId,
        address indexed owner,
        address indexed receiver,
        string shareIPFSHash,
        uint256 expiryTime
    );
    
    event PartialAccessRevoked(
        uint256 indexed recordId,
        uint256 accessIndex,
        uint256 timestamp
    );
    
    // ============================================
    // CONSTRUCTOR
    // ============================================
    
    constructor() Ownable(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
    
    // ============================================
    // CORE FUNCTIONS
    // ============================================
    
    /**
     * @dev Add a record (works for all record types)
     */
    function addRecord(
        string memory ipfsHash,
        string memory ownerEncryptedKey,
        string memory backendEncryptedKey,
        bytes32 merkleRoot,
        RecordType recordType
    ) external whenNotPaused returns (uint256) {
        recordCounter++;
        
        unifiedRecords[recordCounter] = UnifiedRecordRef({
            owner: msg.sender,
            merkleRoot: merkleRoot,
            ipfsHash: ipfsHash,
            ownerEncryptedKey: ownerEncryptedKey,
            backendEncryptedKey: backendEncryptedKey,
            recordType: recordType,
            timestamp: block.timestamp,
            isDeleted: false
        });
        
        userRecordIds[msg.sender].push(recordCounter);
        
        emit RecordAdded(recordCounter, msg.sender, recordType, merkleRoot, block.timestamp);
        
        return recordCounter;
    }
    
    /**
     * @dev Update a record
     */
    function updateRecord(
        uint256 recordId,
        string memory newIpfsHash,
        string memory newOwnerEncryptedKey,
        string memory newBackendEncryptedKey,
        bytes32 newMerkleRoot
    ) external whenNotPaused {
        require(unifiedRecords[recordId].owner == msg.sender, "Not owner");
        require(!unifiedRecords[recordId].isDeleted, "Record deleted");
        
        UnifiedRecordRef storage record = unifiedRecords[recordId];
        record.ipfsHash = newIpfsHash;
        record.ownerEncryptedKey = newOwnerEncryptedKey;
        record.backendEncryptedKey = newBackendEncryptedKey;
        record.merkleRoot = newMerkleRoot;
        
        emit RecordUpdated(recordId, newMerkleRoot, block.timestamp);
    }
    
    /**
     * @dev Soft delete a record
     */
    function deleteRecord(uint256 recordId) external whenNotPaused {
        require(unifiedRecords[recordId].owner == msg.sender, "Not owner");
        require(!unifiedRecords[recordId].isDeleted, "Already deleted");
        
        unifiedRecords[recordId].isDeleted = true;
        
        emit RecordDeleted(recordId, block.timestamp);
    }
    
    /**
     * @dev Get a record
     */
    function getRecord(uint256 recordId) external view returns (UnifiedRecordRef memory) {
        require(recordId > 0 && recordId <= recordCounter, "Invalid record ID");
        return unifiedRecords[recordId];
    }
    
    /**
     * @dev Get all record IDs for a user
     */
    function getUserRecordIds(address user) external view returns (uint256[] memory) {
        return userRecordIds[user];
    }
    
    // ============================================
    // PARTIAL SHARING FUNCTIONS
    // ============================================
    
    /**
     * @dev Grant partial access with IPFS package
     */
    function grantPartialAccessWithIPFS(
        uint256 recordId,
        address receiver,
        string memory shareIPFSHash,
        uint256 expiryTime
    ) external whenNotPaused {
        require(unifiedRecords[recordId].owner == msg.sender, "Not owner");
        require(!unifiedRecords[recordId].isDeleted, "Record deleted");
        require(receiver != address(0), "Invalid receiver");
        require(receiver != msg.sender, "Cannot share with self");
        require(expiryTime > block.timestamp, "Invalid expiry time");
        require(bytes(shareIPFSHash).length > 0, "Invalid IPFS hash");
        
        partialAccessList[recordId].push(PartialAccessWithIPFS({
            sharedWith: receiver,
            expiryTime: expiryTime,
            shareIPFSHash: shareIPFSHash,
            isActive: true
        }));
        
        emit PartialAccessGranted(recordId, msg.sender, receiver, shareIPFSHash, expiryTime);
    }
    
    /**
     * @dev Revoke partial access
     */
    function revokePartialAccess(uint256 recordId, uint256 accessIndex) external whenNotPaused {
        require(unifiedRecords[recordId].owner == msg.sender, "Not owner");
        require(accessIndex < partialAccessList[recordId].length, "Invalid index");
        
        partialAccessList[recordId][accessIndex].isActive = false;
        
        emit PartialAccessRevoked(recordId, accessIndex, block.timestamp);
    }
    
    /**
     * @dev Get partial access for a specific user
     */
    function getPartialAccess(uint256 recordId, address user) 
        external 
        view 
        returns (PartialAccessWithIPFS memory) 
    {
        PartialAccessWithIPFS[] memory accessList = partialAccessList[recordId];
        
        for (uint i = 0; i < accessList.length; i++) {
            if (accessList[i].sharedWith == user && 
                accessList[i].isActive &&
                accessList[i].expiryTime > block.timestamp) {
                return accessList[i];
            }
        }
        
        revert("No active access");
    }
    
    /**
     * @dev Get all partial access grants for a record
     */
    function getAllPartialAccess(uint256 recordId) 
        external 
        view 
        returns (PartialAccessWithIPFS[] memory) 
    {
        require(
            unifiedRecords[recordId].owner == msg.sender ||
            hasRole(DEFAULT_ADMIN_ROLE, msg.sender),
            "Not authorized"
        );
        
        return partialAccessList[recordId];
    }
    
    /**
     * @dev Check if user has access to a record
     */
    function hasPartialAccess(uint256 recordId, address user) external view returns (bool) {
        PartialAccessWithIPFS[] memory accessList = partialAccessList[recordId];
        
        for (uint i = 0; i < accessList.length; i++) {
            if (accessList[i].sharedWith == user && 
                accessList[i].isActive &&
                accessList[i].expiryTime > block.timestamp) {
                return true;
            }
        }
        
        return false;
    }
    
    // ============================================
    // UTILITY FUNCTIONS
    // ============================================
    
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }
    
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
    
    function getTotalRecords() external view returns (uint256) {
        return recordCounter;
    }
}
