// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PartialShareExtension
 * @dev Extension contract for existing HealthWallet - adds Merkle-based partial sharing
 * 
 * USAGE: Deploy this separately, your existing contract stays unchanged
 * Android app maintains both contract addresses
 */
contract PartialShareExtension {
    
    struct PartialAccess {
        address sharedWith;
        uint256 expiryTime;
        string shareIPFSHash;      // Points to encrypted partial share package
        bytes32 merkleRoot;        // For verification
        bool isActive;
    }
    
    // recordId => list of partial accesses
    mapping(uint256 => PartialAccess[]) public partialAccessList;
    
    // recordId => owner address (for authorization)
    mapping(uint256 => address) public recordOwners;
    
    // receiver => list of recordIds shared with them (for discovery)
    mapping(address => uint256[]) private receiverToRecords;
    
    // owner => list of recordIds owned by them (for sender view)
    mapping(address => uint256[]) private ownerToRecords;
    
    event PartialAccessGranted(
        uint256 indexed recordId,
        address indexed owner,
        address indexed receiver,
        string shareIPFSHash,
        bytes32 merkleRoot,
        uint256 expiryTime
    );
    
    event PartialAccessRevoked(
        uint256 indexed recordId,
        uint256 accessIndex
    );
    
    /**
     * @dev Register a record owner (called once per record)
     */
    function registerRecord(uint256 recordId, address owner) external {
        require(recordOwners[recordId] == address(0), "Already registered");
        recordOwners[recordId] = owner;
        ownerToRecords[owner].push(recordId);
    }
    
    /**
     * @dev Grant partial access with IPFS package
     */
    function grantPartialAccess(
        uint256 recordId,
        address receiver,
        string memory shareIPFSHash,
        bytes32 merkleRoot,
        uint256 expiryTime
    ) external {
        require(recordOwners[recordId] == msg.sender, "Not owner");
        require(receiver != address(0), "Invalid receiver");
        require(receiver != msg.sender, "Cannot share with self");
        require(expiryTime > block.timestamp, "Invalid expiry");
        require(bytes(shareIPFSHash).length > 0, "Invalid IPFS hash");
        
        partialAccessList[recordId].push(PartialAccess({
            sharedWith: receiver,
            expiryTime: expiryTime,
            shareIPFSHash: shareIPFSHash,
            merkleRoot: merkleRoot,
            isActive: true
        }));
        
        // Add reverse lookup for receiver discovery
        uint256[] storage records = receiverToRecords[receiver];
        bool exists = false;
        for (uint i = 0; i < records.length; i++) {
            if (records[i] == recordId) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            receiverToRecords[receiver].push(recordId);
        }
        
        emit PartialAccessGranted(recordId, msg.sender, receiver, shareIPFSHash, merkleRoot, expiryTime);
    }
    
    /**
     * @dev Revoke partial access
     */
    function revokePartialAccess(uint256 recordId, uint256 accessIndex) external {
        require(recordOwners[recordId] == msg.sender, "Not owner");
        require(accessIndex < partialAccessList[recordId].length, "Invalid index");
        
        partialAccessList[recordId][accessIndex].isActive = false;
        
        emit PartialAccessRevoked(recordId, accessIndex);
    }
    
    /**
     * @dev Get partial access for a specific user
     */
    function getPartialAccess(uint256 recordId, address user) 
        external 
        view 
        returns (PartialAccess memory) 
    {
        PartialAccess[] memory accessList = partialAccessList[recordId];
        
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
     * @dev Check if user has access
     */
    function hasPartialAccess(uint256 recordId, address user) external view returns (bool) {
        PartialAccess[] memory accessList = partialAccessList[recordId];
        
        for (uint i = 0; i < accessList.length; i++) {
            if (accessList[i].sharedWith == user && 
                accessList[i].isActive &&
                accessList[i].expiryTime > block.timestamp) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * @dev Get all partial access grants for a record
     */
    function getAllPartialAccess(uint256 recordId) external view returns (PartialAccess[] memory) {
        return partialAccessList[recordId];
    }
    
    /**
     * @dev Get all recordIds that have been shared with a receiver
     * Used for discovery - receiver can query what's been shared with them
     */
    function getSharedRecordsForReceiver(address receiver) 
        external 
        view 
        returns (uint256[] memory) 
    {
        return receiverToRecords[receiver];
    }
    
    /**
     * @dev Get all active (non-expired, non-revoked) shares for a receiver
     * Returns array of tuples: (recordId, owner, ipfsHash, merkleRoot, expiryTime)
     */
    function getActiveSharesForReceiver(address receiver) 
        external 
        view 
        returns (
            uint256[] memory recordIds,
            address[] memory owners,
            string[] memory ipfsHashes,
            bytes32[] memory merkleRoots,
            uint256[] memory expiryTimes
        ) 
    {
        uint256[] memory allRecords = receiverToRecords[receiver];
        
        // First pass: count active shares
        uint256 activeCount = 0;
        for (uint i = 0; i < allRecords.length; i++) {
            PartialAccess[] memory accessList = partialAccessList[allRecords[i]];
            for (uint j = 0; j < accessList.length; j++) {
                if (accessList[j].sharedWith == receiver && 
                    accessList[j].isActive &&
                    accessList[j].expiryTime > block.timestamp) {
                    activeCount++;
                    // Count ALL active shares, not just one per recordId
                }
            }
        }
        
        // Initialize return arrays
        recordIds = new uint256[](activeCount);
        owners = new address[](activeCount);
        ipfsHashes = new string[](activeCount);
        merkleRoots = new bytes32[](activeCount);
        expiryTimes = new uint256[](activeCount);
        
        // Second pass: populate arrays
        uint256 index = 0;
        for (uint i = 0; i < allRecords.length; i++) {
            uint256 recordId = allRecords[i];
            PartialAccess[] memory accessList = partialAccessList[recordId];
            
            for (uint j = 0; j < accessList.length; j++) {
                if (accessList[j].sharedWith == receiver && 
                    accessList[j].isActive &&
                    accessList[j].expiryTime > block.timestamp) {
                    recordIds[index] = recordId;
                    owners[index] = recordOwners[recordId];
                    ipfsHashes[index] = accessList[j].shareIPFSHash;
                    merkleRoots[index] = accessList[j].merkleRoot;
                    expiryTimes[index] = accessList[j].expiryTime;
                    index++;
                    // Continue to detect all shares, even multiple for the same recordId
                }
            }
        }
        
        return (recordIds, owners, ipfsHashes, merkleRoots, expiryTimes);
    }
    
    /**
     * @dev Get all partial shares sent by an owner (all records they've shared)
     * Returns details of all shares sent by the owner across all their records
     */
    function getSentPartialShares(address owner) 
        external 
        view 
        returns (
            uint256[] memory recordIds,
            address[] memory receivers,
            string[] memory ipfsHashes,
            bytes32[] memory merkleRoots,
            uint256[] memory expiryTimes,
            bool[] memory isActiveArray
        ) 
    {
        uint256[] memory ownedRecords = ownerToRecords[owner];
        
        // First pass: count total shares sent
        uint256 totalShares = 0;
        for (uint i = 0; i < ownedRecords.length; i++) {
            totalShares += partialAccessList[ownedRecords[i]].length;
        }
        
        // Initialize return arrays
        recordIds = new uint256[](totalShares);
        receivers = new address[](totalShares);
        ipfsHashes = new string[](totalShares);
        merkleRoots = new bytes32[](totalShares);
        expiryTimes = new uint256[](totalShares);
        isActiveArray = new bool[](totalShares);
        
        // Second pass: populate arrays
        uint256 index = 0;
        for (uint i = 0; i < ownedRecords.length; i++) {
            uint256 recordId = ownedRecords[i];
            PartialAccess[] memory accessList = partialAccessList[recordId];
            
            for (uint j = 0; j < accessList.length; j++) {
                recordIds[index] = recordId;
                receivers[index] = accessList[j].sharedWith;
                ipfsHashes[index] = accessList[j].shareIPFSHash;
                merkleRoots[index] = accessList[j].merkleRoot;
                expiryTimes[index] = accessList[j].expiryTime;
                isActiveArray[index] = accessList[j].isActive && 
                                       accessList[j].expiryTime > block.timestamp;
                index++;
            }
        }
        
        return (recordIds, receivers, ipfsHashes, merkleRoots, expiryTimes, isActiveArray);
    }
}
