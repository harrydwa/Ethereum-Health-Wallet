// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title HealthWallet
 * @dev A decentralized health records management system
 * Uses OpenZeppelin for secure access control
 */
contract HealthWallet is Ownable, AccessControl {
    
    // Define role for healthcare providers
    bytes32 public constant PROVIDER_ROLE = keccak256("PROVIDER_ROLE");
    
    // Enum for different types of health records
    enum RecordType { 
        LAB_REPORT,
        PRESCRIPTION,
        MEDICAL_IMAGE,
        DIAGNOSIS,
        VACCINATION,
        VISIT_SUMMARY
    }
    
    // Main health record metadata structure
    struct HealthRecord {
        uint256 recordId;
        address patientAddress;
        string ipfsHash;
        RecordType recordType;
        uint256 timestamp;
        address issuedBy;
        bool isActive;
        string encryptedKey;
        uint256 version;
    }
    
    // Access control structure for sharing records
    struct AccessGrant {
        address grantedTo;
        uint256[] recordIds;
        uint256 expiryTime;
        bool isActive;
        uint256 grantedAt;
    }
    
    // Enum for audit log actions
    enum AuditAction {
        VIEW,
        DOWNLOAD,
        SHARE,
        UPDATE,
        DELETE
    }
    
    // Audit log for tracking access
    struct AccessLog {
        address accessor;
        uint256 timestamp;
        AuditAction action;
    }
    
    // Storage mappings
    mapping(address => uint256[]) private patientRecords;
    mapping(uint256 => HealthRecord) private records;
    mapping(address => mapping(address => AccessGrant)) private accessGrants;
    mapping(uint256 => AccessLog[]) private auditLogs;
    mapping(address => address) public emergencyContact;
    
    // Counter for generating unique record IDs
    uint256 private recordCounter;
    
    // Events
    event RecordAdded(
        uint256 indexed recordId, 
        address indexed patient, 
        string ipfsHash,
        RecordType recordType
    );
    
    event RecordUpdated(
        uint256 indexed recordId,
        string newIpfsHash,
        uint256 version
    );
    
    event AccessGranted(
        address indexed patient, 
        address indexed grantedTo, 
        uint256 expiryTime
    );
    
    event AccessRevoked(
        address indexed patient, 
        address indexed revokedFrom
    );
    
    event RecordAccessed(
        uint256 indexed recordId,
        address indexed accessor,
        uint256 timestamp
    );
    
    event EmergencyAccessUsed(
        address indexed patient,
        address indexed emergencyContact,
        uint256 timestamp
    );
    
    // Constructor - grants DEFAULT_ADMIN_ROLE to deployer
    constructor() Ownable(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
    
    // Modifiers for access control
    modifier onlyAuthorizedProvider() {
        require(hasRole(PROVIDER_ROLE, msg.sender), "Not an authorized provider");
        _;
    }
    
    modifier onlyPatient(uint256 _recordId) {
        require(
            records[_recordId].patientAddress == msg.sender,
            "Only patient can perform this action"
        );
        _;
    }
    
    modifier onlyAuthorized(uint256 _recordId) {
        require(
            hasAccess(records[_recordId].patientAddress, msg.sender, _recordId),
            "Not authorized to access this record"
        );
        _;
    }
    
    modifier recordExists(uint256 _recordId) {
        require(_recordId > 0 && _recordId <= recordCounter, "Record does not exist");
        require(records[_recordId].isActive, "Record is not active");
        _;
    }
    
    /**
     * @dev Add a new health record
     */
    function addRecord(
        string memory _ipfsHash,
        RecordType _recordType,
        string memory _encryptedKey
    ) public returns (uint256) {
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");
        
        recordCounter++;
        
        records[recordCounter] = HealthRecord({
            recordId: recordCounter,
            patientAddress: msg.sender,
            ipfsHash: _ipfsHash,
            recordType: _recordType,
            timestamp: block.timestamp,
            issuedBy: msg.sender,
            isActive: true,
            encryptedKey: _encryptedKey,
            version: 1
        });
        
        patientRecords[msg.sender].push(recordCounter);
        
        emit RecordAdded(recordCounter, msg.sender, _ipfsHash, _recordType);
        return recordCounter;
    }
    
    /**
     * @dev Add a record issued by a healthcare provider
     */
    function addRecordByProvider(
        address _patientAddress,
        string memory _ipfsHash,
        RecordType _recordType,
        string memory _encryptedKey
    ) public onlyAuthorizedProvider returns (uint256) {
        require(_patientAddress != address(0), "Invalid patient address");
        require(bytes(_ipfsHash).length > 0, "IPFS hash cannot be empty");
        
        recordCounter++;
        
        records[recordCounter] = HealthRecord({
            recordId: recordCounter,
            patientAddress: _patientAddress,
            ipfsHash: _ipfsHash,
            recordType: _recordType,
            timestamp: block.timestamp,
            issuedBy: msg.sender,
            isActive: true,
            encryptedKey: _encryptedKey,
            version: 1
        });
        
        patientRecords[_patientAddress].push(recordCounter);
        
        emit RecordAdded(recordCounter, _patientAddress, _ipfsHash, _recordType);
        return recordCounter;
    }
    
    /**
     * @dev Update an existing record
     */
    function updateRecord(
        uint256 _recordId,
        string memory _newIpfsHash,
        string memory _newEncryptedKey
    ) public recordExists(_recordId) onlyPatient(_recordId) {
        HealthRecord storage record = records[_recordId];
        record.ipfsHash = _newIpfsHash;
        record.encryptedKey = _newEncryptedKey;
        record.version++;
        
        emit RecordUpdated(_recordId, _newIpfsHash, record.version);
    }
    
    /**
     * @dev Soft delete a record
     */
    function deleteRecord(uint256 _recordId) 
        public 
        recordExists(_recordId) 
        onlyPatient(_recordId) 
    {
        records[_recordId].isActive = false;
    }
    
    /**
     * @dev Grant access to specific records
     */
    function grantAccess(
        address _grantee,
        uint256[] memory _recordIds,
        uint256 _durationInDays
    ) public {
        require(_grantee != address(0), "Invalid address");
        require(_recordIds.length > 0, "Must grant access to at least one record");
        require(_durationInDays > 0 && _durationInDays <= 3650, "Invalid duration");
        
        for (uint i = 0; i < _recordIds.length; i++) {
            require(
                records[_recordIds[i]].patientAddress == msg.sender,
                "You don't own all specified records"
            );
        }
        
        uint256 expiryTime = block.timestamp + (_durationInDays * 1 days);
        
        accessGrants[msg.sender][_grantee] = AccessGrant({
            grantedTo: _grantee,
            recordIds: _recordIds,
            expiryTime: expiryTime,
            isActive: true,
            grantedAt: block.timestamp
        });
        
        emit AccessGranted(msg.sender, _grantee, expiryTime);
    }
    
    /**
     * @dev Revoke access from a healthcare provider
     */
    function revokeAccess(address _grantee) public {
        require(accessGrants[msg.sender][_grantee].isActive, "No active access grant");
        accessGrants[msg.sender][_grantee].isActive = false;
        emit AccessRevoked(msg.sender, _grantee);
    }
    
    /**
     * @dev Check if an address has access to a specific record
     */
    function hasAccess(
        address _patient,
        address _requester,
        uint256 _recordId
    ) public view returns (bool) {
        if (_patient == _requester) return true;
        
        if (emergencyContact[_patient] == _requester) {
            return true;
        }
        
        AccessGrant memory grant = accessGrants[_patient][_requester];
        
        if (!grant.isActive) return false;
        if (block.timestamp > grant.expiryTime) return false;
        
        for (uint i = 0; i < grant.recordIds.length; i++) {
            if (grant.recordIds[i] == _recordId) return true;
        }
        
        return false;
    }
    
    /**
     * @dev Get all record IDs for a patient
     */
    function getPatientRecords(address _patient) 
        public 
        view 
        returns (uint256[] memory) 
    {
        if (msg.sender == _patient) {
            return patientRecords[_patient];
        }

        require(hasGeneralAccess(_patient, msg.sender), "Not authorized");

        uint256[] storage all = patientRecords[_patient];
        uint256 allowedCount = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (hasAccess(_patient, msg.sender, all[i])) {
                allowedCount++;
            }
        }

        uint256[] memory result = new uint256[](allowedCount);
        uint256 idx = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (hasAccess(_patient, msg.sender, all[i])) {
                result[idx] = all[i];
                idx++;
            }
        }

        return result;
    }
    
    /**
     * @dev Get details of a specific record
     */
    function getRecord(uint256 _recordId) 
        public 
        view
        recordExists(_recordId)
        onlyAuthorized(_recordId)
        returns (HealthRecord memory) 
    {
        return records[_recordId];
    }
    
    /**
     * @dev Log access to a record
     */
    function logAccess(uint256 _recordId, AuditAction _action) 
        public 
        recordExists(_recordId)
        onlyAuthorized(_recordId)
    {
        if (emergencyContact[records[_recordId].patientAddress] == msg.sender) {
            emit EmergencyAccessUsed(
                records[_recordId].patientAddress,
                msg.sender,
                block.timestamp
            );
        }
        
        auditLogs[_recordId].push(AccessLog({
            accessor: msg.sender,
            timestamp: block.timestamp,
            action: _action
        }));
        
        emit RecordAccessed(_recordId, msg.sender, block.timestamp);
    }
    
    /**
     * @dev Get audit logs for a record
     */
    function getAuditLogs(uint256 _recordId) 
        public 
        view
        recordExists(_recordId)
        onlyPatient(_recordId)
        returns (AccessLog[] memory) 
    {
        return auditLogs[_recordId];
    }
    
    /**
     * @dev Set emergency contact
     */
    function setEmergencyContact(address _emergencyContact) public {
        require(_emergencyContact != address(0), "Invalid address");
        emergencyContact[msg.sender] = _emergencyContact;
    }
    
    /**
     * @dev Check if requester has general access
     */
    function hasGeneralAccess(address _patient, address _requester) 
        internal 
        view 
        returns (bool) 
    {
        if (emergencyContact[_patient] == _requester) return true;
        
        AccessGrant memory grant = accessGrants[_patient][_requester];
        return grant.isActive && block.timestamp <= grant.expiryTime;
    }
    
    /**
     * @dev Get access grant details
     */
    function getAccessGrant(address _patient, address _grantee) 
        public 
        view 
        returns (AccessGrant memory) 
    {
        require(
            msg.sender == _patient || msg.sender == _grantee,
            "Not authorized"
        );
        return accessGrants[_patient][_grantee];
    }
    
    /**
     * @dev Get total number of records
     */
    function getTotalRecords() public view returns (uint256) {
        return recordCounter;
    }
    
    // ============================================
    // OPENZEPPELIN ACCESS CONTROL FUNCTIONS
    // ============================================
    
    /**
     * @dev Authorize a healthcare provider (only admin)
     * Uses OpenZeppelin's AccessControl
     */
    function authorizeProvider(address _provider) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_provider != address(0), "Invalid provider address");
        grantRole(PROVIDER_ROLE, _provider);
    }
    
    /**
     * @dev Revoke provider authorization (only admin)
     */
    function revokeProviderAuthorization(address _provider) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(PROVIDER_ROLE, _provider);
    }
    
    /**
     * @dev Check if an address is an authorized provider
     */
    function isAuthorizedProvider(address _provider) public view returns (bool) {
        return hasRole(PROVIDER_ROLE, _provider);
    }
}