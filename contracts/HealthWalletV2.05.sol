// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title HealthWalletV2.05
 * @dev Privacy-focused health record management - ALL sensitive data encrypted and stored off-chain
 * @notice Only metadata and encrypted IPFS hashes stored on-chain for maximum privacy
 *
 * VERSION 2.05 CHANGES:
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
contract HealthWalletV2_05 is Ownable, AccessControl, ReentrancyGuard, Pausable {

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

    // ============================================
    // STRUCTS (Only metadata - no sensitive data)
    // ============================================

    /**
     * @dev Encrypted Personal Info Reference
     * Actual data (name, email, phone, etc.) encrypted and stored on IPFS
     */
    struct PersonalInfoRef {
        string encryptedDataIpfsHash;  // IPFS hash of encrypted JSON
        bytes32 publicKeyHash;         // Hash of user's public key (for verification)
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
        bool isActive;                 // Only status visible (for filtering)
        uint256 startDate;             // Date metadata (for chronological ordering)
        uint256 endDate;
        uint256 createdAt;
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
    }

    /**
     * @dev Share Record - Minimal public info
     * Recipient details encrypted and stored separately
     * IMPORTANT: Uses per-category keys for cryptographic isolation
     */
    struct ShareRecord {
        uint256 id;
        address recipientAddress;          // On-chain identity
        bytes32 recipientNameHash;         // Hash only (privacy)
        string encryptedRecipientDataIpfsHash; // Encrypted recipient details on IPFS
        RecipientType recipientType;       // Type visible
        DataCategory sharedDataCategory;
        uint256 shareDate;
        uint256 expiryDate;
        AccessLevel accessLevel;
        ShareStatus status;
        string encryptedCategoryKey;       // Category-specific key encrypted with recipient's public key
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

    // ============================================
    // EVENTS
    // ============================================

    event PersonalInfoStored(address indexed user, string ipfsHash, uint256 timestamp);
    event PersonalInfoUpdated(address indexed user, string ipfsHash, uint256 timestamp);

    event MedicationAdded(address indexed user, uint256 indexed medicationId, string ipfsHash);
    event MedicationUpdated(address indexed user, uint256 indexed medicationId, string ipfsHash);

    event VaccinationAdded(address indexed user, uint256 indexed vaccinationId, string ipfsHash);
    event VaccinationUpdated(address indexed user, uint256 indexed vaccinationId, string ipfsHash);

    event ReportAdded(address indexed user, uint256 indexed reportId, ReportType reportType, string ipfsHash);
    event ReportUpdated(address indexed user, uint256 indexed reportId, string ipfsHash);

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

    modifier hasDataAccess(address _user, DataCategory _category) {
        require(
            msg.sender == _user ||
            _hasSharedAccess(_user, msg.sender, _category) ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );
        _;
    }

    // ============================================
    // PERSONAL INFO FUNCTIONS
    // ============================================

    /**
     * @dev Store encrypted personal information reference
     * @param _encryptedDataIpfsHash IPFS hash of encrypted personal data JSON
     * @param _publicKeyHash Hash of user's public encryption key
     *
     * Client must:
     * 1. Encrypt all personal data with symmetric key
     * 2. Upload encrypted data to IPFS
     * 3. Store only IPFS hash on blockchain
     */
    function setPersonalInfo(
        string memory _encryptedDataIpfsHash,
        bytes32 _publicKeyHash,
        string memory _encryptedKey
    ) external whenNotPaused {
        bool isNew = !personalInfoRefs[msg.sender].exists;

        if (isNew) {
            personalInfoRefs[msg.sender] = PersonalInfoRef({
                encryptedDataIpfsHash: _encryptedDataIpfsHash,
                publicKeyHash: _publicKeyHash,
                createdAt: block.timestamp,
                lastUpdated: block.timestamp,
                exists: true,
                encryptedKey: _encryptedKey
            });
            emit PersonalInfoStored(msg.sender, _encryptedDataIpfsHash, block.timestamp);
        } else {
            personalInfoRefs[msg.sender].encryptedDataIpfsHash = _encryptedDataIpfsHash;
            personalInfoRefs[msg.sender].publicKeyHash = _publicKeyHash;
            personalInfoRefs[msg.sender].lastUpdated = block.timestamp;
            personalInfoRefs[msg.sender].encryptedKey = _encryptedKey;
            emit PersonalInfoUpdated(msg.sender, _encryptedDataIpfsHash, block.timestamp);
        }
    }

    /**
     * @dev Get personal info reference (only returns IPFS hash)
     * Client must decrypt data after fetching from IPFS
     */
    function getPersonalInfoRef(address _user)
        external
        view
        hasDataAccess(_user, DataCategory.PERSONAL_INFO)
        returns (PersonalInfoRef memory)
    {
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
        bool _isActive,
        uint256 _startDate,
        uint256 _endDate
    ) external whenNotPaused onlyPersonalInfoOwner returns (uint256) {
        medicationCounter++;
        uint256 newId = medicationCounter;

        medicationRefs[newId] = MedicationRecordRef({
            id: newId,
            encryptedDataIpfsHash: _encryptedDataIpfsHash,
            isActive: _isActive,
            startDate: _startDate,
            endDate: _endDate,
            createdAt: block.timestamp
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
        bool _isActive,
        uint256 _startDate,
        uint256 _endDate
    ) external whenNotPaused onlyMedicationOwner(_medicationId) {
        MedicationRecordRef storage med = medicationRefs[_medicationId];
        med.encryptedDataIpfsHash = _encryptedDataIpfsHash;
        med.isActive = _isActive;
        med.startDate = _startDate;
        med.endDate = _endDate;

        emit MedicationUpdated(msg.sender, _medicationId, _encryptedDataIpfsHash);
    }

    /**
     * @dev Get all medication IDs for a user
     */
    function getMedicationIds(address _user)
        external
        view
        hasDataAccess(_user, DataCategory.MEDICATION_RECORDS)
        returns (uint256[] memory)
    {
        return userMedicationIds[_user];
    }

    /**
     * @dev Get medication reference (returns IPFS hash only)
     */
    function getMedicationRef(uint256 _medicationId)
        external
        view
        returns (MedicationRecordRef memory)
    {
        address owner = medicationOwner[_medicationId];
        require(
            msg.sender == owner ||
            _hasSharedAccess(owner, msg.sender, DataCategory.MEDICATION_RECORDS) ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );
        return medicationRefs[_medicationId];
    }

    // ============================================
    // VACCINATION RECORD FUNCTIONS
    // ============================================

    /**
     * @dev Add encrypted vaccination record
     */
    function addVaccination(
        string memory _encryptedDataIpfsHash,
        string memory _encryptedCertificateIpfsHash,
        uint256 _vaccinationDate
    ) external whenNotPaused onlyPersonalInfoOwner returns (uint256) {
        vaccinationCounter++;
        uint256 newId = vaccinationCounter;

        vaccinationRefs[newId] = VaccinationRecordRef({
            id: newId,
            encryptedDataIpfsHash: _encryptedDataIpfsHash,
            encryptedCertificateIpfsHash: _encryptedCertificateIpfsHash,
            vaccinationDate: _vaccinationDate,
            createdAt: block.timestamp
        });

        vaccinationOwner[newId] = msg.sender;
        userVaccinationIds[msg.sender].push(newId);

        emit VaccinationAdded(msg.sender, newId, _encryptedDataIpfsHash);
        return newId;
    }

    /**
     * @dev Update vaccination record
     */
    function updateVaccination(
        uint256 _vaccinationId,
        string memory _encryptedDataIpfsHash,
        string memory _encryptedCertificateIpfsHash,
        uint256 _vaccinationDate
    ) external whenNotPaused onlyVaccinationOwner(_vaccinationId) {
        VaccinationRecordRef storage vac = vaccinationRefs[_vaccinationId];
        vac.encryptedDataIpfsHash = _encryptedDataIpfsHash;
        vac.encryptedCertificateIpfsHash = _encryptedCertificateIpfsHash;
        vac.vaccinationDate = _vaccinationDate;

        emit VaccinationUpdated(msg.sender, _vaccinationId, _encryptedDataIpfsHash);
    }

    /**
     * @dev Get all vaccination IDs for a user
     */
    function getVaccinationIds(address _user)
        external
        view
        hasDataAccess(_user, DataCategory.VACCINATION_RECORDS)
        returns (uint256[] memory)
    {
        return userVaccinationIds[_user];
    }

    /**
     * @dev Get vaccination reference
     */
    function getVaccinationRef(uint256 _vaccinationId)
        external
        view
        returns (VaccinationRecordRef memory)
    {
        address owner = vaccinationOwner[_vaccinationId];
        require(
            msg.sender == owner ||
            _hasSharedAccess(owner, msg.sender, DataCategory.VACCINATION_RECORDS) ||
            hasRole(AUDITOR_ROLE, msg.sender),
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
            encryptedKey: _encryptedKey
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
     * @dev Get all report IDs for a user
     */
    function getReportIds(address _user)
        external
        view
        hasDataAccess(_user, DataCategory.MEDICAL_REPORTS)
        returns (uint256[] memory)
    {
        return userReportIds[_user];
    }

    /**
     * @dev Get report reference
     */
    function getReportRef(uint256 _reportId)
        external
        view
        returns (MedicalReportRef memory)
    {
        address owner = reportOwner[_reportId];
        require(
            msg.sender == owner ||
            _hasSharedAccess(owner, msg.sender, DataCategory.MEDICAL_REPORTS) ||
            hasRole(AUDITOR_ROLE, msg.sender),
            "No access"
        );
        return reportRefs[_reportId];
    }

    // ============================================
    // DATA SHARING FUNCTIONS
    // ============================================

    /**
     * @dev Share data with an entity
     * @param _recipientAddress Recipient's blockchain address
     * @param _recipientNameHash Hash of recipient name (privacy)
     * @param _encryptedRecipientDataIpfsHash IPFS hash of encrypted recipient details
     * @param _recipientType Type of recipient
     * @param _dataCategory Category of data to share
     * @param _expiryDate Expiry timestamp
     * @param _accessLevel Access level
     * @param _encryptedCategoryKey Category-specific key encrypted with recipient's public key
     *
     * SECURITY: Each data category uses a different encryption key (derived from base key)
     * When sharing VACCINATIONS, only vaccination key is shared - cannot decrypt MEDICATIONS
     */
    function shareData(
        address _recipientAddress,
        bytes32 _recipientNameHash,
        string memory _encryptedRecipientDataIpfsHash,
        RecipientType _recipientType,
        DataCategory _dataCategory,
        uint256 _expiryDate,
        AccessLevel _accessLevel,
        string memory _encryptedCategoryKey
    ) external whenNotPaused onlyPersonalInfoOwner returns (uint256) {
        require(_recipientAddress != address(0), "Invalid addr");
        require(_recipientAddress != msg.sender, "No self-share");
        require(_expiryDate > block.timestamp, "Invalid expiry");

        shareCounter++;
        uint256 newId = shareCounter;

        shareRecords[newId] = ShareRecord({
            id: newId,
            recipientAddress: _recipientAddress,
            recipientNameHash: _recipientNameHash,
            encryptedRecipientDataIpfsHash: _encryptedRecipientDataIpfsHash,
            recipientType: _recipientType,
            sharedDataCategory: _dataCategory,
            shareDate: block.timestamp,
            expiryDate: _expiryDate,
            accessLevel: _accessLevel,
            status: ShareStatus.ACTIVE,
            encryptedCategoryKey: _encryptedCategoryKey
        });

        shareOwner[newId] = msg.sender;
        userShareIds[msg.sender].push(newId);

        emit DataShared(msg.sender, _recipientAddress, newId, _dataCategory, _expiryDate);
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
     * @dev Get all share record IDs for a user
     */
    function getShareIds(address _user) external view returns (uint256[] memory) {
        require(msg.sender == _user || hasRole(AUDITOR_ROLE, msg.sender), "No auth");
        return userShareIds[_user];
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
     * @dev Internal function to check shared access
     */
    function _hasSharedAccess(
        address _owner,
        address _accessor,
        DataCategory _category
    ) private view returns (bool) {
        uint256[] memory shareIds = userShareIds[_owner];

        for (uint256 i = 0; i < shareIds.length; i++) {
            ShareRecord memory share = shareRecords[shareIds[i]];

            if (
                share.recipientAddress == _accessor &&
                share.status == ShareStatus.ACTIVE &&
                block.timestamp <= share.expiryDate &&
                (share.sharedDataCategory == _category || share.sharedDataCategory == DataCategory.ALL_DATA)
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
        // Verify accessor has permission
        require(
            msg.sender == _owner ||
            _hasSharedAccess(_owner, msg.sender, _accessedCategory) ||
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