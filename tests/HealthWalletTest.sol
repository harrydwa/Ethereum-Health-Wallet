// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../contracts/HealthWallet.sol";
import "remix_tests.sol";
import "remix_accounts.sol";

contract HealthWalletTest {
    HealthWallet private healthWallet;

    // Test accounts
    address public acc0;  // Owner
    address public acc1;  // Patient 1
    address public acc2;  // Patient 2
    address public acc3;  // Provider
    address public acc4;  // Regular user
    address public acc5;  // Emergency contact

    // Setup before all tests
    function beforeAll() public {
        acc0 = TestsAccounts.getAccount(0);
        acc1 = TestsAccounts.getAccount(1);
        acc2 = TestsAccounts.getAccount(2);
        acc3 = TestsAccounts.getAccount(3);
        acc4 = TestsAccounts.getAccount(4);
        acc5 = TestsAccounts.getAccount(5);
    }

    // Setup before each test
    function beforeEach() public {
        healthWallet = new HealthWallet();
    }

    // Test contract deployment
    function testDeployment() public {
        Assert.notEqual(address(healthWallet), address(0), "Contract should be deployed");
        Assert.equal(healthWallet.getTotalRecords(), 0, "Should start with 0 records");
    }

    // Test provider authorization
    function testAuthorizeProvider() public {
        TestsAccounts.setAccount(acc0); // Use owner account
        healthWallet.authorizeProvider(acc3);
        Assert.ok(healthWallet.isAuthorizedProvider(acc3), "Provider should be authorized");
    }

    // Test provider revocation
    function testRevokeProvider() public {
         TestsAccounts.setAccount(acc0); 
        healthWallet.authorizeProvider(acc3);
        healthWallet.revokeProviderAuthorization(acc3);
        Assert.ok(!healthWallet.isAuthorizedProvider(acc3), "Provider should be revoked");
    }

    // Test patient adding record
    function testPatientAddRecord() public {
         TestsAccounts.setAccount(acc0);  // Act as patient
        uint256 recordId = healthWallet.addRecord(
            "ipfs://QmTest123",
            HealthWallet.RecordType.PRESCRIPTION,
            "Test prescription"
        );

        Assert.gt(recordId, 0, "Record ID should be valid");
        Assert.equal(healthWallet.getTotalRecords(), 1, "Should have 1 record");
    }

    // Test provider adding record for patient
    function testProviderAddRecord() public {
         TestsAccounts.setAccount(acc3); 
        healthWallet.authorizeProvider(acc3);

           TestsAccounts.setAccount(acc3);   // Act as authorized provider
        uint256 recordId = healthWallet.addRecordByProvider(
            acc1,
            "ipfs://QmProviderTest",
            HealthWallet.RecordType.LAB_REPORT,
            "Provider test record"
        );

        Assert.gt(recordId, 0, "Record should be created by provider");
    }

    // Test access granting
    function testGrantAccess() public {
           TestsAccounts.setAccount(acc1); 
        uint256 recordId = healthWallet.addRecord(
            "ipfs://QmTest",
            HealthWallet.RecordType.PRESCRIPTION,
            "Test"
        );

        // Grant access to user for 1 hour
        uint256 duration = 1 hours;
        healthWallet.grantAccess(acc4, [recordId], duration);

        Assert.ok(
            healthWallet.hasAccess(acc1, acc4, recordId),
            "User should have access to record"
        );
    }

    // Test access revocation
    function testRevokeAccess() public {
           TestsAccounts.setAccount(acc1); 
        uint256 recordId = healthWallet.addRecord(
            "ipfs://QmTest",
            HealthWallet.RecordType.PRESCRIPTION,
            "Test"
        );

        // Grant then revoke access
        healthWallet.grantAccess(acc4, [recordId], 1 hours);
        healthWallet.revokeAccess(acc4);

        Assert.ok(
            !healthWallet.hasAccess(acc1, acc4, recordId),
            "User should not have access after revocation"
        );
    }

    // Test emergency contact
    function testEmergencyContact() public {
           TestsAccounts.setAccount(acc1); 
        healthWallet.setEmergencyContact(acc5);
        Assert.equal(
            healthWallet.emergencyContact(acc1),
            acc5,
            "Emergency contact should be set"
        );
    }

    // Test record update
    function testUpdateRecord() public {
     TestsAccounts.setAccount(acc1); 
        uint256 recordId = healthWallet.addRecord(
            "ipfs://QmOld",
            HealthWallet.RecordType.PRESCRIPTION,
            "Old description"
        );

        healthWallet.updateRecord(
            recordId,
            "ipfs://QmNew",
            "New description"
        );

        HealthWallet.HealthRecord memory record = healthWallet.getRecord(recordId);
        Assert.equal(
            record.ipfsHash,
            "ipfs://QmNew",
            "IPFS hash should be updated"
        );
        Assert.equal(
            record.encryptedKey,
            "New description",
            "Description should be updated"
        );
    }

    // Test record deletion (soft delete)
    function testDeleteRecord() public {
         TestsAccounts.setAccount(acc1); 
        uint256 recordId = healthWallet.addRecord(
            "ipfs://QmTest",
            HealthWallet.RecordType.PRESCRIPTION,
            "Test"
        );

        healthWallet.deleteRecord(recordId);
        HealthWallet.HealthRecord memory record = healthWallet.getRecord(recordId);
        Assert.ok(!record.isActive, "Record should be marked inactive");
    }

    // Test getting patient records
    function testGetPatientRecords() public {
         TestsAccounts.setAccount(acc1); 
        healthWallet.addRecord(
            "ipfs://Qm1",
            HealthWallet.RecordType.PRESCRIPTION,
            "Record 1"
        );
        healthWallet.addRecord(
            "ipfs://Qm2",
            HealthWallet.RecordType.LAB_REPORT,
            "Record 2"
        );

        uint256[] memory records = healthWallet.getPatientRecords(acc1);
        Assert.equal(records.length, 2, "Should return 2 records");
    }
}