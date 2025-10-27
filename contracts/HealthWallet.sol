// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title HealthWallet
 * @dev A decentralized health records management system
 * Stores metadata and IPFS pointers on-chain, actual health data on IPFS
 */
contract HealthWallet {
    
    // Enum for different types of health records
    enum RecordType { 
        LAB_REPORT,      // Blood tests, urine tests, etc.
        PRESCRIPTION,    // Doctor's prescriptions
        MEDICAL_IMAGE,   // X-rays, CT scans, MRI
        DIAGNOSIS,       // Doctor's diagnosis
        VACCINATION,     // Vaccine records
        VISIT_SUMMARY    // Hospital visit summaries
    }
    
    // Main health record metadata structure
    struct HealthRecord {
        uint256 recordId;
        address patientAddress;      // Patient's wallet address
        string ipfsHash;             // IPFS CID (Content Identifier)
        RecordType recordType;
        uint256 timestamp;           // When record was created
        address issuedBy;            // Doctor/Hospital wallet address
        bool isActive;               // For soft deletes
        string encryptedKey;         // Encrypted symmetric key for data decryption
        uint256 version;             // Version number for updates
    }
    
    // Access control structure for sharing records
    struct AccessGrant {
        address grantedTo;           // Doctor/Hospital granted access
        uint256[] recordIds;         // Which records they can access
        uint256 expiryTime;          // Time-based access expiry
        bool isActive;               // Can be revoked
        uint256 grantedAt;           // When access was granted
    }
    
    // Audit log for tracking access
    struct AccessLog {
        address accessor;
        uint256 timestamp;
        string action;               // "VIEW", "DOWNLOAD", etc.
    }
    
    // Storage mappings
    mapping(address => uint256[]) private patientRecords;
    mapping(uint256 => HealthRecord) private records;
    mapping(address => mapping(address => AccessGrant)) private accessGrants;
    mapping(uint256 => AccessLog[]) private auditLogs;
    mapping(address => address) public emergencyContact;
    
    // Counter for generating unique record IDs
    uint256 private recordCounter;
    
    // Events for tracking important actions
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
    
    // Modifiers for access control
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
     * @param _ipfsHash IPFS hash where encrypted health data is stored
     * @param _recordType Type of health record
     * @param _encryptedKey Encrypted symmetric key for decryption
     * @return recordId The ID of the newly created record
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
     * @param _patientAddress Address of the patient
     * @param _ipfsHash IPFS hash of the encrypted data
     * @param _recordType Type of record
     * @param _encryptedKey Encrypted key for the patient
     */
    function addRecordByProvider(
        address _patientAddress,
        string memory _ipfsHash,
        RecordType _recordType,
        string memory _encryptedKey
    ) public returns (uint256) {
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
     * @dev Update an existing record (creates a new version)
     * @param _recordId ID of the record to update
     * @param _newIpfsHash New IPFS hash
     * @param _newEncryptedKey New encrypted key
     */
    function updateRecord(
        uint256 _recordId,
        string memory _newIpfsHash,
        string memory _newEncryptedKey
    ) public onlyPatient(_recordId) recordExists(_recordId) {
        HealthRecord storage record = records[_recordId];
        record.ipfsHash = _newIpfsHash;
        record.encryptedKey = _newEncryptedKey;
        record.version++;
        
        emit RecordUpdated(_recordId, _newIpfsHash, record.version);
    }
    
    /**
     * @dev Soft delete a record
     * @param _recordId ID of the record to delete
     */
    function deleteRecord(uint256 _recordId) 
        public 
        onlyPatient(_recordId) 
        recordExists(_recordId) 
    {
        records[_recordId].isActive = false;
    }
    
    /**
     * @dev Grant access to specific records for a healthcare provider
     * @param _grantee Address to grant access to
     * @param _recordIds Array of record IDs to grant access to
     * @param _durationInDays How many days the access should last
     */
    function grantAccess(
        address _grantee,
        uint256[] memory _recordIds,
        uint256 _durationInDays
    ) public {
        require(_grantee != address(0), "Invalid address");
        require(_recordIds.length > 0, "Must grant access to at least one record");
        
        // Verify patient owns all records
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
     * @param _grantee Address to revoke access from
     */
    function revokeAccess(address _grantee) public {
        require(accessGrants[msg.sender][_grantee].isActive, "No active access grant");
        accessGrants[msg.sender][_grantee].isActive = false;
        emit AccessRevoked(msg.sender, _grantee);
    }
    
    /**
     * @dev Check if an address has access to a specific record
     * @param _patient Patient's address
     * @param _requester Address requesting access
     * @param _recordId Record ID to check access for
     * @return bool True if access is granted
     */
    function hasAccess(
        address _patient,
        address _requester,
        uint256 _recordId
    ) public view returns (bool) {
        // Patient always has access to their own records
        if (_patient == _requester) return true;
        
        // Check emergency contact access
        if (emergencyContact[_patient] == _requester) return true;
        
        AccessGrant memory grant = accessGrants[_patient][_requester];
        
        if (!grant.isActive) return false;
        if (block.timestamp > grant.expiryTime) return false;
        
        // Check if recordId is in granted list
        for (uint i = 0; i < grant.recordIds.length; i++) {
            if (grant.recordIds[i] == _recordId) return true;
        }
        
        return false;
    }
    
    /**
     * @dev Get all record IDs for a patient
     * @param _patient Patient's address
     * @return Array of record IDs
     */
    function getPatientRecords(address _patient) 
        public 
        view 
        returns (uint256[] memory) 
    {
        require(
            msg.sender == _patient || hasGeneralAccess(_patient, msg.sender),
            "Not authorized"
        );
        return patientRecords[_patient];
    }
    
    /**
     * @dev Get details of a specific record
     * @param _recordId Record ID
     * @return HealthRecord struct
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
     * @dev Log access to a record (for audit trail)
     * @param _recordId Record being accessed
     * @param _action Action being performed
     */
    function logAccess(uint256 _recordId, string memory _action) 
        public 
        recordExists(_recordId)
        onlyAuthorized(_recordId)
    {
        auditLogs[_recordId].push(AccessLog({
            accessor: msg.sender,
            timestamp: block.timestamp,
            action: _action
        }));
        
        emit RecordAccessed(_recordId, msg.sender, block.timestamp);
    }
    
    /**
     * @dev Get audit logs for a record
     * @param _recordId Record ID
     * @return Array of AccessLog entries
     */
    function getAuditLogs(uint256 _recordId) 
        public 
        view
        onlyPatient(_recordId)
        returns (AccessLog[] memory) 
    {
        return auditLogs[_recordId];
    }
    
    /**
     * @dev Set emergency contact who can access all records
     * @param _emergencyContact Address of emergency contact
     */
    function setEmergencyContact(address _emergencyContact) public {
        require(_emergencyContact != address(0), "Invalid address");
        emergencyContact[msg.sender] = _emergencyContact;
    }
    
    /**
     * @dev Check if requester has general access (for multiple records)
     * @param _patient Patient address
     * @param _requester Requester address
     * @return bool True if has access
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
     * @param _patient Patient address
     * @param _grantee Grantee address
     * @return AccessGrant struct
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
     * @dev Get total number of records in the system
     * @return Total record count
     */
    function getTotalRecords() public view returns (uint256) {
        return recordCounter;
    }
}
