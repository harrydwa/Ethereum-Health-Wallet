// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title HealthWalletV3
 * @dev Privacy-focused health record management - ALL sensitive data encrypted and stored off-chain
 * @notice Only metadata and encrypted IPFS hashes stored on-chain for maximum privacy
 *
 * VERSION 3 CHANGES:
 * - Added encryptedKey field to MedicalReportRef for per-record random key encryption
 * - Updated addReport and updateReport functions to accept encryptedKey parameter
 *
 * PRIVACY MODEL:
 * - Sensitive data encrypted client-side using user's key
 * - Encrypted data stored on IPFS
 * - Only IPFS hash (CID) stored on blockchain
 * - Minimal metadata on-chain (timestamps, types, IDs)
 * - Access control via blockchain, data retrieval via IPFS
 */
contract HealthWalletV3 is Ownable, AccessControl, ReentrancyGuard, Pausable {

    // ============================================
    // ROLES
    // ============================================
    bytes32 public constant HEALTHCARE_PROVIDER_ROLE = keccak256("HEALTHCARE_PROVIDER_ROLE");
    bytes32 public constant HOSPITAL_ROLE = keccak256("HOSPITAL_ROLE");
    bytes32 public constant CLINIC_ROLE = keccak256("CLINIC_ROLE");
    bytes32 public constant INSURANCE_ROLE = keccak256("INSURANCE_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    // ============================================
    // ENUMS (Safe to store - no sensitive data)
    // ============================================
    enum RecordType {
        PERSONAL_INFO,
        MEDICATION,
        VACCINATION,
        MEDICAL_REPORT
    }

    enum ReportType {
        LAB_RESULT,
        DOCTOR_NOTE,
        PRESCRIPTION,
        IMAGING,
        PATHOLOGY,
        CONSULTATION,
        DISCHARGE_SUMMARY,
        OTHER
    }

    enum RecipientType {
        DOCTOR,
        HOSPITAL,
        CLINIC,
        INSURANCE_COMPANY,
        PHARMACY,
        LABORATORY,
        OTHER
    }

    enum AccessLevel {
        VIEW_ONLY,
        FULL_ACCESS,
        EMERGENCY_ONLY
    }

    enum ShareStatus {
        ACTIVE,
        EXPIRED,
        REVOKED
    }

    enum DataCategory {
        PERSONAL_INFO,
        MEDICATION_RECORDS,
        VACCINATION_RECORDS,
        MEDICAL_REPORTS,
        ALL_DATA
    }

    enum VaccineCode {
        COVID_19,      // 0
        MEASLES,       // 1
        POLIO,         // 2
        TETANUS,       // 3
        INFLUENZA,     // 4
        HPV,           // 5
        HEPATITIS_B,   // 6
        HEPATITIS_A,   // 7
        VARICELLA,     // 8
        MENINGOCOCCAL, // 9
        PNEUMOCOCCAL,  // 10
        TUBERCULOSIS,  // 11
        ROTAVIRUS,     // 12
        DIPHTHERIA,    // 13
        PERTUSSIS,     // 14
        OTHER          // 15
    }

    // ============================================
    // STRUCTS (Only metadata - no sensitive data)
    // ============================================

    /**
     * @dev User Crypto Profile - Manages RSA public key for sharing
     * Full public key stored on IPFS for gas efficiency
     */
    struct UserCryptoProfile {
        bytes32 publicKeyHash;      // Hash of public key for verification
        string publicKeyIpfsHash;   // IPFS hash of full RSA public key
        uint256 keyVersion;         // For key rotation support
        bool isSet;
    }

    /**
     * @dev Encrypted Personal Info Reference
     * Actual data (name, email, phone, etc.) encrypted and stored on IPFS
     * Public key now managed separately in UserCryptoProfile
     */
    struct PersonalInfoRef {
        string encryptedDataIpfsHash;  // IPFS hash of encrypted JSON
        uint256 createdAt;
        uint256 lastUpdated;
        bool exists;
        string encryptedKey;           // Encrypted random AES key for this record
    }

    /**
     * @dev Encrypted Medication Record Reference
     * Actual data encrypted and stored on IPFS
     */
    struct MedicationRecordRef {
        uint256 id;
        string encryptedDataIpfsHash;  // IPFS hash of encrypted medication data
        string encryptedKey;           // AES key encrypted with user's master key
        bool isActive;                 // Only status visible (for filtering)
        uint256 startDate;             // Date metadata (for chronological ordering)
        uint256 endDate;
        uint256 createdAt;
        bool isDeleted;                // Soft delete flag
    }

    /**
     * @dev Encrypted Vaccination Record Reference
     * Actual data encrypted and stored on IPFS
     */
    struct VaccinationRecordRef {
        uint256 id;
        string encryptedDataIpfsHash;      // IPFS hash of encrypted vaccination data
        string encryptedCertificateIpfsHash; // IPFS hash of encrypted certificate
        uint256 vaccinationDate;           // Date metadata only
        uint256 createdAt;
        string encryptedKey;           // NEW: Encrypted random AES key for this record
        bool isDeleted;                // Soft delete flag
    }

    /**
     * @dev Encrypted Medical Report Reference
     * Actual data encrypted and stored on IPFS
     */
    struct MedicalReportRef {
        uint256 id;
        string encryptedDataIpfsHash;  // IPFS hash of encrypted report data
        string encryptedFileIpfsHash;  // IPFS hash of encrypted report file (if exists)
        ReportType reportType;         // Type visible for filtering
        bool hasFile;
        uint256 reportDate;            // Date metadata only
        uint256 createdAt;
        string encryptedKey;           // NEW: Encrypted random AES key for this record
        bool isDeleted;                // Soft delete flag
    }

    /**
     * @dev Share Record - Per-Record Sharing
     * Each share references a SPECIFIC record, not entire category
     */
    struct ShareRecord {
        uint256 id;
        address ownerAddress;              // Owner of the shared record
        address recipientAddress;          // Recipient's address
        bytes32 recipientNameHash;         // Hash of recipient name (privacy)
        string encryptedRecipientDataIpfsHash; // Encrypted recipient details on IPFS
        RecipientType recipientType;       // Type of recipient
        RecordType recordType;             // Type of record being shared
        uint256 recordId;                  // Specific record ID (0 for PersonalInfo)
        uint256 shareDate;
        uint256 expiryDate;
        AccessLevel accessLevel;
        ShareStatus status;
        string encryptedRecordKey;         // Record's AES key encrypted with recipient's RSA public key
    }

    /**
     * @dev Access Log - Minimal info, details encrypted
     * Who accessed is visible (address), but details encrypted
     */
    struct AccessLog {
        uint256 id;
        address accessorAddress;           // Who accessed (address visible)
        string encryptedDetailsIpfsHash;   // Encrypted details (name, location, purpose, IP)
        DataCategory accessedCategory;
        uint256 accessTime;
        bytes32 dataIntegrityHash;         // Hash for integrity verification
    }

    /**
     * @dev Vaccine Commitment - Track ZK proof commitments for vaccinations
     * Used for Option A: Local-first vaccine proofs with optional blockchain anchoring
     */
    struct VaccineCommitment {
        uint256 vaccineCode;           // VaccineCode enum value (COVID_19, MEASLES, etc.)
        uint256 commitment;            // Poseidon hash(vaccinationId, vaccineCode, salt)
        uint256 registeredAt;          // Timestamp of commitment registration
        bool isVerified;               // Whether ZK proof has been submitted/verified
        bytes32 proofHash;             // Hash of submitted ZK proof (if any)
        uint256 proofSubmittedAt;      // Timestamp of proof submission
        uint256 expiresAt;             // Optional expiration date (0 = never expires)
    }

    /**
     * @dev Age proof anchor (one-step model)
     */
    struct AgeProofAnchor {
        uint256 minAge;
        uint256 commitment;
        bool isVerified;
        bytes32 proofHash;
        uint256 proofSubmittedAt;
        uint256 updatedAt;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    // Counters
    uint256 private medicationCounter;
    uint256 private vaccinationCounter;
    uint256 private reportCounter;
    uint256 private shareCounter;
    uint256 private accessLogCounter;

    // User Address => Encrypted Personal Info Reference
    mapping(address => PersonalInfoRef) private personalInfoRefs;

    // User Address => Crypto Profile (RSA public key management)
    mapping(address => UserCryptoProfile) public userCryptoProfiles;

    // User Address => Medication IDs
    mapping(address => uint256[]) private userMedicationIds;
    mapping(uint256 => MedicationRecordRef) private medicationRefs;

    // User Address => Vaccination IDs
    mapping(address => uint256[]) private userVaccinationIds;
    mapping(uint256 => VaccinationRecordRef) private vaccinationRefs;

    // User Address => Report IDs
    mapping(address => uint256[]) private userReportIds;
    mapping(uint256 => MedicalReportRef) private reportRefs;

    // User Address => Share Record IDs
    mapping(address => uint256[]) private userShareIds;
    mapping(uint256 => ShareRecord) private shareRecords;

    // User Address => Access Log IDs
    mapping(address => uint256[]) private userAccessLogIds;
    mapping(uint256 => AccessLog) private accessLogs;

    // Track record ownership
    mapping(uint256 => address) private medicationOwner;
    mapping(uint256 => address) private vaccinationOwner;
    mapping(uint256 => address) private reportOwner;
    mapping(uint256 => address) private shareOwner;
    mapping(uint256 => address) private accessLogOwner;

    // Emergency contact addresses (only address visible, details encrypted)
    mapping(address => address) private emergencyContactAddresses;

    // User Address => Vaccine Code => Vaccine Commitment
    mapping(address => mapping(uint256 => VaccineCommitment)) private vaccineCommitments;
    
    // User Address => Array of vaccine codes they've registered commitments for
    mapping(address => uint256[]) private userVaccineCodes;
    
    // Track which vaccines have commitments for a user (for quick lookup)
    mapping(address => mapping(uint256 => bool)) private userHasVaccine;

    // User Address => Age proof anchor
    mapping(address => AgeProofAnchor) private ageProofAnchors;

    // ============================================
    // EVENTS
    // ============================================

    event PersonalInfoStored(address indexed user, string ipfsHash, uint256 timestamp);
    event PersonalInfoUpdated(address indexed user, string ipfsHash, uint256 timestamp);

    event MedicationAdded(address indexed user, uint256 indexed medicationId, string ipfsHash);
    event MedicationUpdated(address indexed user, uint256 indexed medicationId, string ipfsHash);
    event MedicationDeleted(address indexed user, uint256 indexed medicationId, uint256 timestamp);

    event VaccinationAdded(address indexed user, uint256 indexed vaccinationId, string ipfsHash);
    event VaccinationUpdated(address indexed user, uint256 indexed vaccinationId, string ipfsHash);
    event VaccinationDeleted(address indexed user, uint256 indexed vaccinationId, uint256 timestamp);

    event ReportAdded(address indexed user, uint256 indexed reportId, ReportType reportType, string ipfsHash);
    event ReportUpdated(address indexed user, uint256 indexed reportId, string ipfsHash);
    event ReportDeleted(address indexed user, uint256 indexed reportId, uint256 timestamp);

    event DataShared(
        address indexed owner,
        address indexed recipient,
        uint256 indexed shareId,
        DataCategory category,
        uint256 expiryDate
    );
    event ShareRevoked(address indexed owner, uint256 indexed shareId);

    event DataAccessed(
        address indexed owner,
        address indexed accessor,
        uint256 indexed logId,
        DataCategory category,
        uint256 timestamp
    );

    event EntityRegistered(address indexed entity, bytes32 role);
    event EntityRevoked(address indexed entity, bytes32 role);

    event EmergencyContactSet(address indexed user, address indexed emergencyContact);
    event PublicKeySet(address indexed user, string publicKeyIpfsHash, uint256 keyVersion);

    event VaccineCommitmentRegistered(
        address indexed user,
        uint256 indexed vaccineCode,
        uint256 commitment,
        uint256 timestamp
    );

    event VaccineProofSubmitted(
        address indexed user,
        uint256 indexed vaccineCode,
        bytes32 proofHash,
        uint256 timestamp
    );

    event AgeProofSubmitted(
        address indexed user,
        uint256 minAge,
        uint256 commitment,
        bytes32 proofHash,
        uint256 timestamp
    );

    // ============================================
    // CONSTRUCTOR
    // ============================================
    constructor() Ownable(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    // ============================================
    // MODIFIERS
    // ============================================

    modifier onlyPersonalInfoOwner() {
        require(personalInfoRefs[msg.sender].exists, "No info");
        _;
    }

    modifier onlyMedicationOwner(uint256 _medicationId) {
        require(medicationOwner[_medicationId] == msg.sender, "Not owner");
        _;
    }

    modifier onlyVaccinationOwner(uint256 _vaccinationId) {
        require(vaccinationOwner[_vaccinationId] == msg.sender, "Not owner");
        _;
    }

    modifier onlyReportOwner(uint256 _reportId) {
        require(reportOwner[_reportId] == msg.sender, "Not owner");
        _;
    }

    modifier onlyShareOwner(uint256 _shareId) {
        require(shareOwner[_shareId] == msg.sender, "Not owner");
        _;
    }

    // ============================================
    // PERSONAL INFO FUNCTIONS
    // ============================================

    /**
     * @dev Store encrypted personal information reference
     * @param _encryptedDataIpfsHash IPFS hash of encrypted personal data JSON
     * @param _encryptedKey Encrypted random AES key for this record
     *
     * Client must:
     * 1. Encrypt all personal data with symmetric key
     * 2. Upload encrypted data to IPFS
     * 3. Store only IPFS hash on blockchain
     * Note: Public key managed separately via setUserPublicKey()
     */
    function setPersonalInfo(
        string memory _encryptedDataIpfsHash,
        string memory _encryptedKey
    ) external whenNotPaused {
        bool isNew = !personalInfoRefs[msg.sender].exists;

        if (isNew) {
            personalInfoRefs[msg.sender] = PersonalInfoRef({
                encryptedDataIpfsHash: _encryptedDataIpfsHash,
                createdAt: block.timestamp,
                lastUpdated: block.timestamp,
                exists: true,
                encryptedKey: _encryptedKey
            });
            emit PersonalInfoStored(msg.sender, _encryptedDataIpfsHash, block.timestamp);
        } else {
            personalInfoRefs[msg.sender].encryptedDataIpfsHash = _encryptedDataIpfsHash;
            personalInfoRefs[msg.sender].lastUpdated = block.timestamp;
            personalInfoRefs[msg.sender].encryptedKey = _encryptedKey;
            emit PersonalInfoUpdated(msg.sender, _encryptedDataIpfsHash, block.timestamp);
        }
    }

    /**
     * @dev Set user's RSA public key for sharing functionality
     * @param _publicKeyIpfsHash IPFS hash where full RSA public key is stored
     * @param _publicKeyHash Hash of the public key for verification
     * 
     * Flow:
     * 1. Generate RSA key pair on client
     * 2. Upload public key to IPFS
     * 3. Store IPFS hash on blockchain
     */
    function setUserPublicKey(
        string memory _publicKeyIpfsHash,
        bytes32 _publicKeyHash
    ) external whenNotPaused {
        require(bytes(_publicKeyIpfsHash).length > 0, "Invalid IPFS hash");
        require(_publicKeyHash != bytes32(0), "Invalid key hash");

        uint256 newVersion = userCryptoProfiles[msg.sender].keyVersion + 1;

        userCryptoProfiles[msg.sender] = UserCryptoProfile({
            publicKeyHash: _publicKeyHash,
            publicKeyIpfsHash: _publicKeyIpfsHash,
            keyVersion: newVersion,
            isSet: true
        });

        emit PublicKeySet(msg.sender, _publicKeyIpfsHash, newVersion);
    }

    /**
     * @dev Get user's public key IPFS hash for sharing
     * @param _user Address of the user
     * @return publicKeyIpfsHash IPFS hash of user's RSA public key
     */
    function getUserPublicKey(address _user) external view returns (string memory) {
        require(userCryptoProfiles[_user].isSet, "Public key not set");
        return userCryptoProfiles[_user].publicKeyIpfsHash;
    }

    /**
     * @dev Get personal info reference (only returns IPFS hash)
     * Client must decrypt data after fetching from IPFS
     * Accessible by: owner, auditor, or recipient with active share
     */
    function getPersonalInfoRef(address _user)
        external
        view
        returns (PersonalInfoRef memory)
    {
        require(
            msg.sender == _user || 
            hasRole(AUDITOR_ROLE, msg.sender) ||
            _hasSharedRecordAccess(_user, msg.sender, RecordType.PERSONAL_INFO, 0),
            "No access"
        );
        require(personalInfoRefs[_user].exists, "Not found");
        return personalInfoRefs[_user];
    }

    // ============================================
    // MEDICATION RECORD FUNCTIONS
    // ============================================

    /**
     * @dev Add encrypted medication record
     * @param _encryptedDataIpfsHash IPFS hash of encrypted medication data
     * @param _isActive Whether medication is currently active (visible for filtering)
     * @param _startDate Start date (visible for chronological ordering)
     * @param _endDate End date (visible for chronological ordering)
     */
    function addMedication(
        string memory _encryptedDataIpfsHash,
        string memory _encryptedKey,
        bool _isActive,
        uint256 _startDate,
        uint256 _endDate
    ) external whenNotPaused onlyPersonalInfoOwner returns (uint256) {
        medicationCounter++;
        uint256 newId = medicationCounter;

        medicationRefs[newId] = MedicationRecordRef({
            id: newId,
            encryptedDataIpfsHash: _encryptedDataIpfsHash,
            encryptedKey: _encryptedKey,
            isActive: _isActive,
            startDate: _startDate,
            endDate: _endDate,
            createdAt: block.timestamp,
            isDeleted: false
        });

        medicationOwner[newId] = msg.sender;
        userMedicationIds[msg.sender].push(newId);

        emit MedicationAdded(msg.sender, newId, _encryptedDataIpfsHash);
        return newId;
    }

    /**
     * @dev Update medication record
     */
    function updateMedication(
        uint256 _medicationId,
        string memory _encryptedDataIpfsHash,
        string memory _encryptedKey,
        bool _isActive,
        uint256 _startDate,
        uint256 _endDate
    ) external whenNotPaused onlyMedicationOwner(_medicationId) {
        MedicationRecordRef storage med = medicationRefs[_medicationId];
        med.encryptedDataIpfsHash = _encryptedDataIpfsHash;
        med.encryptedKey = _encryptedKey;
        med.isActive = _isActive;
        med.startDate = _startDate;
        med.endDate = _endDate;

        emit MedicationUpdated(msg.sender, _medicationId, _encryptedDataIpfsHash);
    }

    /**
     * @dev Soft delete medication record
     * @param _medicationId ID of the medication to delete
     * @notice This is a soft delete - data remains on blockchain but marked as deleted
     * @notice Shared records remain accessible to recipients even after deletion
     */
    function deleteMedication(uint256 _medicationId) 
        external 
        whenNotPaused 
        onlyMedicationOwner(_medicationId) 
    {
        require(!medicationRefs[_medicationId].isDeleted, "Already deleted");
        medicationRefs[_medicationId].isDeleted = true;
        emit MedicationDeleted(msg.sender, _medicationId, block.timestamp);
    }

    /**
     * @dev Get all medication IDs for a user
     * For shared access, use getShareRecord() to get specific shared medications
     */
    function getMedicationIds(address _user)
        external
        view
        returns (uint256[] memory)
    {
        require(
            msg.sender == _user || hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );
        return userMedicationIds[_user];
    }

    /**
     * @dev Get medication reference (returns IPFS hash only)
     * Accessible by: owner, auditor, or recipient with active share
     */
    function getMedicationRef(uint256 _medicationId)
        external
        view
        returns (MedicationRecordRef memory)
    {
        address owner = medicationOwner[_medicationId];
        require(
            msg.sender == owner || 
            hasRole(AUDITOR_ROLE, msg.sender) ||
            _hasSharedRecordAccess(owner, msg.sender, RecordType.MEDICATION, _medicationId),
            "No access"
        );
        return medicationRefs[_medicationId];
    }

    // ============================================
    // VACCINATION RECORD FUNCTIONS
    // ============================================

    /**
     * @dev Add encrypted vaccination record
     * @param _encryptedDataIpfsHash IPFS hash of encrypted vaccination data
     * @param _encryptedCertificateIpfsHash IPFS hash of encrypted certificate file
     * @param _vaccinationDate Vaccination date (Unix timestamp)
     * @param _encryptedKey Encrypted random AES key for this record
     */
    function addVaccination(
        string memory _encryptedDataIpfsHash,
        string memory _encryptedCertificateIpfsHash,
        uint256 _vaccinationDate,
        string memory _encryptedKey
    ) external whenNotPaused onlyPersonalInfoOwner returns (uint256) {
        vaccinationCounter++;
        uint256 newId = vaccinationCounter;

        vaccinationRefs[newId] = VaccinationRecordRef({
            id: newId,
            encryptedDataIpfsHash: _encryptedDataIpfsHash,
            encryptedCertificateIpfsHash: _encryptedCertificateIpfsHash,
            vaccinationDate: _vaccinationDate,
            createdAt: block.timestamp,
            encryptedKey: _encryptedKey,
            isDeleted: false
        });

        vaccinationOwner[newId] = msg.sender;
        userVaccinationIds[msg.sender].push(newId);

        emit VaccinationAdded(msg.sender, newId, _encryptedDataIpfsHash);
        return newId;
    }

    /**
     * @dev Update vaccination record
     * @param _vaccinationId ID of the vaccination record to update
     * @param _encryptedDataIpfsHash IPFS hash of encrypted vaccination data
     * @param _encryptedCertificateIpfsHash IPFS hash of encrypted certificate file
     * @param _vaccinationDate Vaccination date (Unix timestamp)
     * @param _encryptedKey Encrypted random AES key for this record
     */
    function updateVaccination(
        uint256 _vaccinationId,
        string memory _encryptedDataIpfsHash,
        string memory _encryptedCertificateIpfsHash,
        uint256 _vaccinationDate,
        string memory _encryptedKey
    ) external whenNotPaused onlyVaccinationOwner(_vaccinationId) {
        VaccinationRecordRef storage vac = vaccinationRefs[_vaccinationId];
        vac.encryptedDataIpfsHash = _encryptedDataIpfsHash;
        vac.encryptedCertificateIpfsHash = _encryptedCertificateIpfsHash;
        vac.vaccinationDate = _vaccinationDate;
        vac.encryptedKey = _encryptedKey;

        emit VaccinationUpdated(msg.sender, _vaccinationId, _encryptedDataIpfsHash);
    }

    /**
     * @dev Soft delete vaccination record
     * @param _vaccinationId ID of the vaccination to delete
     * @notice This is a soft delete - data remains on blockchain but marked as deleted
     * @notice Shared records remain accessible to recipients even after deletion
     */
    function deleteVaccination(uint256 _vaccinationId) 
        external 
        whenNotPaused 
        onlyVaccinationOwner(_vaccinationId) 
    {
        require(!vaccinationRefs[_vaccinationId].isDeleted, "Already deleted");
        vaccinationRefs[_vaccinationId].isDeleted = true;
        emit VaccinationDeleted(msg.sender, _vaccinationId, block.timestamp);
    }

    /**
     * @dev Get all vaccination IDs for a user
     * For shared access, use getShareRecord() to get specific shared vaccinations
     */
    function getVaccinationIds(address _user)
        external
        view
        returns (uint256[] memory)
    {
        require(
            msg.sender == _user || hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );
        return userVaccinationIds[_user];
    }

    /**
     * @dev Get vaccination reference
     * Accessible by: owner, auditor, or recipient with active share
     */
    function getVaccinationRef(uint256 _vaccinationId)
        external
        view
        returns (VaccinationRecordRef memory)
    {
        address owner = vaccinationOwner[_vaccinationId];
        require(
            msg.sender == owner || 
            hasRole(AUDITOR_ROLE, msg.sender) ||
            _hasSharedRecordAccess(owner, msg.sender, RecordType.VACCINATION, _vaccinationId),
            "No access"
        );
        return vaccinationRefs[_vaccinationId];
    }

    // ============================================
    // MEDICAL REPORT FUNCTIONS
    // ============================================

    /**
     * @dev Add encrypted medical report
     */
    function addReport(
        string memory _encryptedDataIpfsHash,
        string memory _encryptedFileIpfsHash,
        ReportType _reportType,
        bool _hasFile,
        uint256 _reportDate,
        string memory _encryptedKey
    ) external whenNotPaused onlyPersonalInfoOwner returns (uint256) {
        reportCounter++;
        uint256 newId = reportCounter;

        reportRefs[newId] = MedicalReportRef({
            id: newId,
            encryptedDataIpfsHash: _encryptedDataIpfsHash,
            encryptedFileIpfsHash: _encryptedFileIpfsHash,
            reportType: _reportType,
            hasFile: _hasFile,
            reportDate: _reportDate,
            createdAt: block.timestamp,
            encryptedKey: _encryptedKey,
            isDeleted: false
        });

        reportOwner[newId] = msg.sender;
        userReportIds[msg.sender].push(newId);

        emit ReportAdded(msg.sender, newId, _reportType, _encryptedDataIpfsHash);
        return newId;
    }

    /**
     * @dev Update medical report
     */
    function updateReport(
        uint256 _reportId,
        string memory _encryptedDataIpfsHash,
        string memory _encryptedFileIpfsHash,
        ReportType _reportType,
        bool _hasFile,
        uint256 _reportDate,
        string memory _encryptedKey
    ) external whenNotPaused onlyReportOwner(_reportId) {
        MedicalReportRef storage report = reportRefs[_reportId];
        report.encryptedDataIpfsHash = _encryptedDataIpfsHash;
        report.encryptedFileIpfsHash = _encryptedFileIpfsHash;
        report.reportType = _reportType;
        report.hasFile = _hasFile;
        report.reportDate = _reportDate;
        report.encryptedKey = _encryptedKey;

        emit ReportUpdated(msg.sender, _reportId, _encryptedDataIpfsHash);
    }

    /**
     * @dev Soft delete medical report
     * @param _reportId ID of the report to delete
     * @notice This is a soft delete - data remains on blockchain but marked as deleted
     * @notice Shared records remain accessible to recipients even after deletion
     */
    function deleteReport(uint256 _reportId) 
        external 
        whenNotPaused 
        onlyReportOwner(_reportId) 
    {
        require(!reportRefs[_reportId].isDeleted, "Already deleted");
        reportRefs[_reportId].isDeleted = true;
        emit ReportDeleted(msg.sender, _reportId, block.timestamp);
    }

    /**
     * @dev Get all report IDs for a user
     * For shared access, use getShareRecord() to get specific shared reports
     */
    function getReportIds(address _user)
        external
        view
        returns (uint256[] memory)
    {
        require(
            msg.sender == _user || hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );
        return userReportIds[_user];
    }

    /**
     * @dev Get report reference
     * Accessible by: owner, auditor, or recipient with active share
     */
    function getReportRef(uint256 _reportId)
        external
        view
        returns (MedicalReportRef memory)
    {
        address owner = reportOwner[_reportId];
        require(
            msg.sender == owner || 
            hasRole(AUDITOR_ROLE, msg.sender) ||
            _hasSharedRecordAccess(owner, msg.sender, RecordType.MEDICAL_REPORT, _reportId),
            "No access"
        );
        return reportRefs[_reportId];
    }

    // ============================================
    // DATA SHARING FUNCTIONS
    // ============================================

    /**
     * @dev Share a specific record with recipient
     * @param _recipientAddress Recipient's blockchain address
     * @param _recipientNameHash Hash of recipient name (privacy)
     * @param _encryptedRecipientDataIpfsHash IPFS hash of encrypted recipient details
     * @param _recipientType Type of recipient
     * @param _recordType Type of record being shared
     * @param _recordId Specific record ID (use 0 for PersonalInfo since it's unique per user)
     * @param _expiryDate Expiry timestamp
     * @param _accessLevel Access level
     * @param _encryptedRecordKey Record's AES key encrypted with recipient's RSA public key
     *
     * SECURITY: Shares ONE specific record, not entire category
     * Each record has its own random AES key
     */
    function shareData(
        address _recipientAddress,
        bytes32 _recipientNameHash,
        string memory _encryptedRecipientDataIpfsHash,
        RecipientType _recipientType,
        RecordType _recordType,
        uint256 _recordId,
        uint256 _expiryDate,
        AccessLevel _accessLevel,
        string memory _encryptedRecordKey
    ) external whenNotPaused onlyPersonalInfoOwner returns (uint256) {
        require(_recipientAddress != address(0), "Invalid addr");
        require(_recipientAddress != msg.sender, "No self-share");
        require(_expiryDate > block.timestamp, "Invalid expiry");
        require(bytes(_encryptedRecordKey).length > 0, "Invalid encrypted key");

        // Validate record ownership based on type
        if (_recordType == RecordType.PERSONAL_INFO) {
            require(personalInfoRefs[msg.sender].exists, "No personal info");
        } else if (_recordType == RecordType.MEDICATION) {
            require(medicationOwner[_recordId] == msg.sender, "Not record owner");
        } else if (_recordType == RecordType.VACCINATION) {
            require(vaccinationOwner[_recordId] == msg.sender, "Not record owner");
        } else if (_recordType == RecordType.MEDICAL_REPORT) {
            require(reportOwner[_recordId] == msg.sender, "Not record owner");
        }

        shareCounter++;
        uint256 newId = shareCounter;

        shareRecords[newId] = ShareRecord({
            id: newId,
            ownerAddress: msg.sender,
            recipientAddress: _recipientAddress,
            recipientNameHash: _recipientNameHash,
            encryptedRecipientDataIpfsHash: _encryptedRecipientDataIpfsHash,
            recipientType: _recipientType,
            recordType: _recordType,
            recordId: _recordId,
            shareDate: block.timestamp,
            expiryDate: _expiryDate,
            accessLevel: _accessLevel,
            status: ShareStatus.ACTIVE,
            encryptedRecordKey: _encryptedRecordKey
        });

        shareOwner[newId] = msg.sender;
        userShareIds[msg.sender].push(newId);

        // Determine category for event (for backward compatibility)
        DataCategory category = _recordType == RecordType.PERSONAL_INFO ? DataCategory.PERSONAL_INFO :
                               _recordType == RecordType.MEDICATION ? DataCategory.MEDICATION_RECORDS :
                               _recordType == RecordType.VACCINATION ? DataCategory.VACCINATION_RECORDS :
                               DataCategory.MEDICAL_REPORTS;
        emit DataShared(msg.sender, _recipientAddress, newId, category, _expiryDate);
        return newId;
    }

    /**
     * @dev Revoke data sharing
     */
    function revokeShare(uint256 _shareId) external whenNotPaused onlyShareOwner(_shareId) {
        shareRecords[_shareId].status = ShareStatus.REVOKED;
        emit ShareRevoked(msg.sender, _shareId);
    }

    /**
     * @dev Get all share record IDs for a user (shares they created)
     */
    function getShareIds(address _user) external view returns (uint256[] memory) {
        require(msg.sender == _user || hasRole(AUDITOR_ROLE, msg.sender), "No auth");
        return userShareIds[_user];
    }

    /**
     * @dev Get all share IDs received by a user (shares where they are recipient)
     * @param _recipient Address of the recipient
     * @return Array of share IDs where user is the recipient
     */
    function getReceivedShareIds(address _recipient) external view returns (uint256[] memory) {
        require(msg.sender == _recipient || hasRole(AUDITOR_ROLE, msg.sender), "No auth");
        
        // Count received shares first
        uint256 count = 0;
        for (uint256 i = 1; i <= shareCounter; i++) {
            if (shareRecords[i].recipientAddress == _recipient && 
                shareRecords[i].status == ShareStatus.ACTIVE) {
                count++;
            }
        }
        
        // Populate array
        uint256[] memory receivedShares = new uint256[](count);
        uint256 index = 0;
        for (uint256 i = 1; i <= shareCounter; i++) {
            if (shareRecords[i].recipientAddress == _recipient && 
                shareRecords[i].status == ShareStatus.ACTIVE) {
                receivedShares[index] = i;
                index++;
            }
        }
        
        return receivedShares;
    }

    /**
     * @dev Get share record
     */
    function getShareRecord(uint256 _shareId) external view returns (ShareRecord memory) {
        address owner = shareOwner[_shareId];
        require(
            msg.sender == owner ||
            msg.sender == shareRecords[_shareId].recipientAddress ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No auth"
        );

        ShareRecord memory share = shareRecords[_shareId];

        // Auto-expire if past expiry date
        if (block.timestamp > share.expiryDate && share.status == ShareStatus.ACTIVE) {
            share.status = ShareStatus.EXPIRED;
        }

        return share;
    }

    /**
     * @dev Check if accessor has access to a specific record
     */
    function _hasSharedRecordAccess(
        address _owner,
        address _accessor,
        RecordType _recordType,
        uint256 _recordId
    ) private view returns (bool) {
        uint256[] memory shareIds = userShareIds[_owner];

        for (uint256 i = 0; i < shareIds.length; i++) {
            ShareRecord memory share = shareRecords[shareIds[i]];

            if (
                share.recipientAddress == _accessor &&
                share.status == ShareStatus.ACTIVE &&
                block.timestamp <= share.expiryDate &&
                share.recordType == _recordType &&
                share.recordId == _recordId
            ) {
                return true;
            }
        }

        return false;
    }

    // ============================================
    // ACCESS LOGGING FUNCTIONS (IMMUTABLE)
    // ============================================

    /**
     * @dev Log data access (immutable)
     * @param _owner Owner of the data
     * @param _encryptedDetailsIpfsHash IPFS hash of encrypted access details
     * @param _accessedCategory Category of data accessed
     * @param _dataIntegrityHash Hash for data integrity verification
     */
    function logDataAccess(
        address _owner,
        string memory _encryptedDetailsIpfsHash,
        DataCategory _accessedCategory,
        bytes32 _dataIntegrityHash
    ) external whenNotPaused returns (uint256) {
        // Verify accessor has permission (owner or auditor)
        // For shared access, recipient should log through their own flow
        require(
            msg.sender == _owner ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No permission"
        );

        accessLogCounter++;
        uint256 newId = accessLogCounter;

        accessLogs[newId] = AccessLog({
            id: newId,
            accessorAddress: msg.sender,
            encryptedDetailsIpfsHash: _encryptedDetailsIpfsHash,
            accessedCategory: _accessedCategory,
            accessTime: block.timestamp,
            dataIntegrityHash: _dataIntegrityHash
        });

        accessLogOwner[newId] = _owner;
        userAccessLogIds[_owner].push(newId);

        emit DataAccessed(_owner, msg.sender, newId, _accessedCategory, block.timestamp);
        return newId;
    }

    /**
     * @dev Get all access log IDs for a user
     */
    function getAccessLogIds(address _user) external view returns (uint256[] memory) {
        require(msg.sender == _user || hasRole(AUDITOR_ROLE, msg.sender), "No auth");
        return userAccessLogIds[_user];
    }

    /**
     * @dev Get access log (returns IPFS hash only, details must be decrypted)
     */
    function getAccessLog(uint256 _logId) external view returns (AccessLog memory) {
        address owner = accessLogOwner[_logId];
        require(
            msg.sender == owner ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No auth"
        );
        return accessLogs[_logId];
    }

    // ============================================
    // VACCINE COMMITMENT FUNCTIONS (Option A)
    // ============================================

    /**
     * @dev Register a vaccine commitment (Poseidon hash)
     * Called after user generates ZK proof in VaccineVerifyActivity
     * @param _vaccineCode Vaccine code (0=COVID_19, 1=MEASLES, etc.)
     * @param _commitment Poseidon hash(vaccinationId, vaccineCode, salt)
     * @return true if commitment registered successfully
     */
    function registerVaccineCommitment(
        uint256 _vaccineCode,
        uint256 _commitment
    ) external whenNotPaused onlyPersonalInfoOwner returns (bool) {
        require(_vaccineCode <= 15, "Invalid vaccine code");
        require(_commitment != 0, "Invalid commitment");

        // Register or update commitment
        if (!userHasVaccine[msg.sender][_vaccineCode]) {
            userVaccineCodes[msg.sender].push(_vaccineCode);
            userHasVaccine[msg.sender][_vaccineCode] = true;
        }

        vaccineCommitments[msg.sender][_vaccineCode] = VaccineCommitment({
            vaccineCode: _vaccineCode,
            commitment: _commitment,
            registeredAt: block.timestamp,
            isVerified: false,
            proofHash: bytes32(0),
            proofSubmittedAt: 0,
            expiresAt: 0  // Never expires by default
        });

        emit VaccineCommitmentRegistered(msg.sender, _vaccineCode, _commitment, block.timestamp);
        return true;
    }

    /**
     * @dev Submit ZK proof for a vaccine (marks commitment as verified)
     * Called after user submits proof to blockchain
     * @param _vaccineCode Vaccine code
     * @param _proofHash Hash of the ZK proof
     * @return true if proof recorded successfully
     */
    function submitVaccineProof(
        uint256 _vaccineCode,
        bytes32 _proofHash
    ) external whenNotPaused returns (bool) {
        require(_vaccineCode <= 15, "Invalid vaccine code");
        require(_proofHash != bytes32(0), "Invalid proof hash");

        VaccineCommitment storage commitment = vaccineCommitments[msg.sender][_vaccineCode];
        require(commitment.commitment != 0, "No commitment for vaccine");

        commitment.isVerified = true;
        commitment.proofHash = _proofHash;
        commitment.proofSubmittedAt = block.timestamp;

        emit VaccineProofSubmitted(msg.sender, _vaccineCode, _proofHash, block.timestamp);
        return true;
    }

    /**
     * @dev One-step vaccine anchor model: registers/updates commitment and marks proof verified in one tx.
     * @param _vaccineCode Vaccine code
     * @param _commitment Poseidon commitment
     * @param _proofHash Hash of the ZK proof
     */
    function submitVaccineProof(
        uint256 _vaccineCode,
        uint256 _commitment,
        bytes32 _proofHash
    ) external whenNotPaused onlyPersonalInfoOwner returns (bool) {
        require(_vaccineCode <= 15, "Invalid vaccine code");
        require(_commitment != 0, "Invalid commitment");
        require(_proofHash != bytes32(0), "Invalid proof hash");

        if (!userHasVaccine[msg.sender][_vaccineCode]) {
            userVaccineCodes[msg.sender].push(_vaccineCode);
            userHasVaccine[msg.sender][_vaccineCode] = true;
        }

        VaccineCommitment storage commitmentRef = vaccineCommitments[msg.sender][_vaccineCode];

        if (commitmentRef.registeredAt == 0) {
            commitmentRef.vaccineCode = _vaccineCode;
            commitmentRef.registeredAt = block.timestamp;
            commitmentRef.expiresAt = 0;
        }

        commitmentRef.commitment = _commitment;
        commitmentRef.isVerified = true;
        commitmentRef.proofHash = _proofHash;
        commitmentRef.proofSubmittedAt = block.timestamp;

        emit VaccineCommitmentRegistered(msg.sender, _vaccineCode, _commitment, block.timestamp);
        emit VaccineProofSubmitted(msg.sender, _vaccineCode, _proofHash, block.timestamp);
        return true;
    }

    /**
     * @dev One-step age anchor model.
     * @param _minAge Proved minimum age threshold (e.g., 18)
     * @param _commitment Commitment/hash related to the locally generated proof
     * @param _proofHash Hash of ZK proof payload
     */
    function submitAgeProof(
        uint256 _minAge,
        uint256 _commitment,
        bytes32 _proofHash
    ) external whenNotPaused onlyPersonalInfoOwner returns (bool) {
        require(_minAge >= 18 && _minAge <= 120, "Invalid min age");
        require(_commitment != 0, "Invalid commitment");
        require(_proofHash != bytes32(0), "Invalid proof hash");

        ageProofAnchors[msg.sender] = AgeProofAnchor({
            minAge: _minAge,
            commitment: _commitment,
            isVerified: true,
            proofHash: _proofHash,
            proofSubmittedAt: block.timestamp,
            updatedAt: block.timestamp
        });

        emit AgeProofSubmitted(msg.sender, _minAge, _commitment, _proofHash, block.timestamp);
        return true;
    }

    /**
     * @dev Returns true when user has an anchored age proof with minAge >= 18.
     */
    function checkAdultStatus(address _user) external view returns (bool) {
        AgeProofAnchor memory anchor = ageProofAnchors[_user];
        return anchor.isVerified && anchor.commitment != 0 && anchor.minAge >= 18;
    }

    /**
     * @dev Returns age verification status and latest anchor timestamp.
     */
    function getVerificationDetails(address _user) external view returns (bool, uint256) {
        AgeProofAnchor memory anchor = ageProofAnchors[_user];
        bool isAdult = anchor.isVerified && anchor.commitment != 0 && anchor.minAge >= 18;
        return (isAdult, anchor.proofSubmittedAt);
    }

    /**
     * @dev Returns the latest anchored age proof hash for a user (bytes32(0) if none).
     */
    function getAgeProofHash(address _user) external view returns (bytes32) {
        return ageProofAnchors[_user].proofHash;
    }

    /**
     * @dev Returns latest anchored vaccine proof hash for a user and vaccine code.
     *      Returns bytes32(0) if no proof was anchored.
     */
    function getVaccineProofHash(address _user, uint256 _vaccineCode) external view returns (bytes32) {
        return vaccineCommitments[_user][_vaccineCode].proofHash;
    }

    /**
     * @dev Get vaccine commitment for a user
     * @param _user Address of the user
     * @param _vaccineCode Vaccine code
     * @return VaccineCommitment struct (or empty if not registered)
     */
    function getVaccineCommitment(
        address _user,
        uint256 _vaccineCode
    ) external view returns (VaccineCommitment memory) {
        require(
            msg.sender == _user ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );
        return vaccineCommitments[_user][_vaccineCode];
    }

    /**
     * @dev Check if a user has a verified vaccination for a specific vaccine
     * @param _user Address to check
     * @param _vaccineCode Vaccine code
     * @return true if user has a verified ZK proof for this vaccine
     */
    function checkVaccinationStatus(
        address _user,
        uint256 _vaccineCode
    ) external view returns (bool) {
        VaccineCommitment memory commitment = vaccineCommitments[_user][_vaccineCode];
        
        // Check if commitment exists and is verified
        if (commitment.commitment == 0) {
            return false;  // No commitment registered
        }

        // Check if proof has been submitted
        if (commitment.isVerified) {
            // Check expiration if set
            if (commitment.expiresAt > 0 && block.timestamp > commitment.expiresAt) {
                return false;  // Proof expired
            }
            return true;  // Verified and not expired
        }

        return false;  // Commitment registered but not verified
    }

    /**
     * @dev Get all vaccine codes a user has registered commitments for
     * @param _user Address of the user
     * @return Array of vaccine codes
     */
    function getUserVaccineCodes(address _user)
        external
        view
        returns (uint256[] memory)
    {
        require(
            msg.sender == _user ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );
        return userVaccineCodes[_user];
    }

    /**
     * @dev Get multiple vaccine commitments at once
     * @param _user Address of the user
     * @param _vaccineCodes Array of vaccine codes to check
     * @return Array of VaccineCommitment structs
     */
    function getMultipleVaccineCommitments(
        address _user,
        uint256[] memory _vaccineCodes
    ) external view returns (VaccineCommitment[] memory) {
        require(
            msg.sender == _user ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );

        VaccineCommitment[] memory commitments = new VaccineCommitment[](_vaccineCodes.length);
        for (uint256 i = 0; i < _vaccineCodes.length; i++) {
            commitments[i] = vaccineCommitments[_user][_vaccineCodes[i]];
        }
        return commitments;
    }

    /**
     * @dev Revoke a vaccine commitment (user decides to unprove)
     * @param _vaccineCode Vaccine code to revoke
     */
    function revokeVaccineCommitment(uint256 _vaccineCode)
        external
        whenNotPaused
    {
        require(_vaccineCode <= 15, "Invalid vaccine code");
        require(
            userHasVaccine[msg.sender][_vaccineCode],
            "No commitment to revoke"
        );

        // Clear the commitment
        delete vaccineCommitments[msg.sender][_vaccineCode];
        userHasVaccine[msg.sender][_vaccineCode] = false;
    }

    // ============================================
    // EMERGENCY CONTACT
    // ============================================

    /**
     * @dev Set emergency contact address
     * Emergency contact details stored in personal info (encrypted)
     */
    function setEmergencyContact(address _emergencyContact) external {
        require(_emergencyContact != address(0), "Invalid addr");
        emergencyContactAddresses[msg.sender] = _emergencyContact;
        emit EmergencyContactSet(msg.sender, _emergencyContact);
    }

    /**
     * @dev Get emergency contact address
     */
    function getEmergencyContact(address _user) external view returns (address) {
        return emergencyContactAddresses[_user];
    }

    // ============================================
    // ENTITY REGISTRATION & ROLE MANAGEMENT
    // ============================================

    function registerHealthcareProvider(address _provider) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(HEALTHCARE_PROVIDER_ROLE, _provider);
        emit EntityRegistered(_provider, HEALTHCARE_PROVIDER_ROLE);
    }

    function registerHospital(address _hospital) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(HOSPITAL_ROLE, _hospital);
        emit EntityRegistered(_hospital, HOSPITAL_ROLE);
    }

    function registerClinic(address _clinic) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(CLINIC_ROLE, _clinic);
        emit EntityRegistered(_clinic, CLINIC_ROLE);
    }

    function registerInsurance(address _insurance) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(INSURANCE_ROLE, _insurance);
        emit EntityRegistered(_insurance, INSURANCE_ROLE);
    }

    function registerAuditor(address _auditor) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(AUDITOR_ROLE, _auditor);
        emit EntityRegistered(_auditor, AUDITOR_ROLE);
    }

    function revokeEntityRole(address _entity, bytes32 _role) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(_role, _entity);
        emit EntityRevoked(_entity, _role);
    }

    // ============================================
    // EMERGENCY FUNCTIONS
    // ============================================

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================

    function getTotalCounts() external view returns (
        uint256 medications,
        uint256 vaccinations,
        uint256 reports,
        uint256 shares,
        uint256 totalAccessLogs
    ) {
        return (
            medicationCounter,
            vaccinationCounter,
            reportCounter,
            shareCounter,
            accessLogCounter
        );
    }

    function hasPersonalInfo(address _user) external view returns (bool) {
        return personalInfoRefs[_user].exists;
    }
}