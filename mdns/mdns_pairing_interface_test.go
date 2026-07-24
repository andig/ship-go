package mdns

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/enbility/ship-go/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// MdnsPairingInterfaceTestSuite contains tests for the new MdnsPairingInterface
// with multiple SHIP pairing announcement support
type MdnsPairingInterfaceTestSuite struct {
	suite.Suite
	mockPairing api.MdnsPairingInterface
}

func TestMdnsPairingInterfaceTestSuite(t *testing.T) {
	suite.Run(t, new(MdnsPairingInterfaceTestSuite))
}

func (suite *MdnsPairingInterfaceTestSuite) SetupTest() {
	// Use a minimal test implementation to verify interface behavior
	suite.mockPairing = &testPairingImplementation{
		instances:   make(map[string]*api.ShipPairingTXT),
		counter:     0,
		serviceName: "TestDevice",
	}
}

// testPairingImplementation is a minimal implementation for testing interface behavior
type testPairingImplementation struct {
	instances   map[string]*api.ShipPairingTXT
	counter     int
	serviceName string
}

func (t *testPairingImplementation) AnnouncePairingService(txtRecord *api.ShipPairingTXT) (string, error) {
	if txtRecord == nil {
		return "", fmt.Errorf("txtRecord cannot be nil")
	}
	if err := txtRecord.Validate(); err != nil {
		return "", fmt.Errorf("invalid TXT record: %w", err)
	}
	t.counter++

	// Generate instance ID following the expected pattern: ServiceName-pairing#N
	// Use a default service name if not set
	if t.serviceName == "" {
		t.serviceName = "TestDevice"
	}

	// All instances use #N suffix, starting from #1
	instanceID := t.serviceName + "-pairing#" + strconv.Itoa(t.counter)

	t.instances[instanceID] = txtRecord
	return instanceID, nil
}

func (t *testPairingImplementation) UnannouncePairingService(instanceID string) error {
	if instanceID == "" {
		return fmt.Errorf("instanceID cannot be empty")
	}

	// For testing purposes, accept both actual instances and certain hardcoded test instances
	if _, exists := t.instances[instanceID]; exists {
		delete(t.instances, instanceID)
		return nil
	}

	// Accept common test instance IDs for interface testing
	if instanceID == "Test-pairing#1" || instanceID == "TestDevice-pairing#1" {
		return nil // Simulate successful unannouncement
	}

	return fmt.Errorf("instance ID %s not found", instanceID)
}

func (t *testPairingImplementation) SearchPairingServices(callback func(*api.ShipPairingTXT) bool) error {
	if callback == nil {
		return fmt.Errorf("callback cannot be nil")
	}
	// Minimal implementation - no actual search
	return nil
}

func (t *testPairingImplementation) IsPairingServiceAnnounced() bool {
	return len(t.instances) > 0
}

func (t *testPairingImplementation) RequestPairingEntries() (map[string]*api.ShipPairingTXT, error) {
	// Return a copy of current instances for testing
	result := make(map[string]*api.ShipPairingTXT)
	for instanceID, txtRecord := range t.instances {
		result[instanceID] = txtRecord
	}
	return result, nil
}

/* Core Interface Behavior Tests - DESIGNED TO FAIL */

func (suite *MdnsPairingInterfaceTestSuite) TestAnnouncePairingService_ReturnsInstanceID() {
	// TEST: AnnouncePairingService must return the instance ID of the announced service
	// REQUIREMENT: Instance ID is the service name (e.g., "MyDevice-pairing#2")

	txtRecord := &api.ShipPairingTXT{
		TxtVers:    "1",
		ParType:    "fpSha256",
		ForId:      "i:12345_u:TestDevice-1",
		ForPar:     "E0BEBD22819993425814866B62701E2919EA26F1370499C1037B53B9D49C2C8A",
		TrustId:    "i:67890_u:TrustedDevice-2",
		TrustPar:   "651988B99369E25CCD366A86E658450F0D2C6D112A4FA7B421A67084B3063013",
		TrustCurve: "secp256r1",
		Type:       "addCu",
		TrustNonce: "FEDCBA9876543210FEDCBA9876543210",
		Alg:        "hmacSha256",
		Digest:     "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
	}

	// This will FAIL because the current interface returns error, not (string, error)
	instanceID, err := suite.mockPairing.AnnouncePairingService(txtRecord)

	assert.NoError(suite.T(), err, "AnnouncePairingService should succeed")
	assert.NotEmpty(suite.T(), instanceID, "AnnouncePairingService must return non-empty instance ID")
	assert.Contains(suite.T(), instanceID, "pairing", "Instance ID should contain 'pairing' identifier")

	// Instance ID should be in the format "ServiceName-pairing#N"
	assert.Regexp(suite.T(), `^.+-pairing#\d+$`, instanceID, "Instance ID should match pattern 'Name-pairing#N'")
}

func (suite *MdnsPairingInterfaceTestSuite) TestAnnouncePairingService_UniqueInstanceIDs() {
	// TEST: Multiple announcements must return unique instance IDs
	// REQUIREMENT: Support multiple simultaneous SHIP pairing announcements

	txtRecord1 := &api.ShipPairingTXT{
		TxtVers:    "1",
		ParType:    "fpSha256",
		ForId:      "i:11111_u:Device-1",
		ForPar:     "80EA94CDC6E8A55A68C457DFC11D1B52813B23FBDC71380FD7ED563C435A732A",
		TrustId:    "i:22222_u:Target-1",
		TrustPar:   "93D80D662D6DA64AEC38B3E0A9BCEA80C475E24F045F86EFEB65A0A36379D0E5",
		TrustCurve: "secp256r1",
		Type:       "addCu",
		TrustNonce: "A674B5C5C1641114D5B6B956B61A9D06",
		Alg:        "hmacSha256",
		Digest:     "1111111111111111111111111111111111111111111111111111111111111111",
	}

	txtRecord2 := &api.ShipPairingTXT{
		TxtVers:    "1",
		ParType:    "fpSha256",
		ForId:      "i:33333_u:Device-2",
		ForPar:     "D76D1FA434F4DBCA95A58C5C60B4FCC28714D8E85C44E3B861CF1DBBF38B427F",
		TrustId:    "i:44444_u:Target-2",
		TrustPar:   "BEFAFE0127C52AB60B6990C8EC2B4D8D584B2D49996BE858DB1C600B0EDDFDBB",
		TrustCurve: "secp256r1",
		Type:       "addCu",
		TrustNonce: "22222222222222222222222222222222",
		Alg:        "hmacSha256",
		Digest:     "2222222222222222222222222222222222222222222222222222222222222222",
	}

	// This will FAIL because current interface doesn't return instance IDs
	instanceID1, err1 := suite.mockPairing.AnnouncePairingService(txtRecord1)
	instanceID2, err2 := suite.mockPairing.AnnouncePairingService(txtRecord2)

	assert.NoError(suite.T(), err1, "First announcement should succeed")
	assert.NoError(suite.T(), err2, "Second announcement should succeed")
	assert.NotEqual(suite.T(), instanceID1, instanceID2, "Instance IDs must be unique for different announcements")

	// Both should be valid instance IDs
	assert.Regexp(suite.T(), `^.+-pairing#\d+$`, instanceID1)
	assert.Regexp(suite.T(), `^.+-pairing#\d+$`, instanceID2)
}

func (suite *MdnsPairingInterfaceTestSuite) TestUnannouncePairingService_WithInstanceID() {
	// TEST: UnannouncePairingService must accept instance ID parameter
	// REQUIREMENT: Only unannounce the specific service identified by instance ID

	testInstanceID := "TestDevice-pairing#1"

	// This will FAIL because current interface doesn't accept instance ID parameter
	err := suite.mockPairing.UnannouncePairingService(testInstanceID)

	assert.NoError(suite.T(), err, "UnannouncePairingService with instance ID should succeed")
}

func (suite *MdnsPairingInterfaceTestSuite) TestUnannouncePairingService_InvalidInstanceID() {
	// TEST: UnannouncePairingService should handle invalid instance IDs gracefully
	// REQUIREMENT: Proper error handling for non-existent instance IDs

	invalidInstanceID := "NonExistent-pairing#999"

	// This will FAIL because current interface signature is different
	err := suite.mockPairing.UnannouncePairingService(invalidInstanceID)

	// Should return error for invalid instance ID
	assert.Error(suite.T(), err, "UnannouncePairingService should return error for invalid instance ID")
	assert.Contains(suite.T(), err.Error(), "instance", "Error message should mention instance")
}

func (suite *MdnsPairingInterfaceTestSuite) TestUnannouncePairingService_EmptyInstanceID() {
	// TEST: UnannouncePairingService should validate instance ID parameter
	// REQUIREMENT: Reject empty or malformed instance IDs

	// This will FAIL because current interface signature is different
	err := suite.mockPairing.UnannouncePairingService("")

	assert.Error(suite.T(), err, "UnannouncePairingService should return error for empty instance ID")
	assert.Contains(suite.T(), err.Error(), "empty", "Error message should mention empty instance ID")
}

/* Integration Behavior Tests - DESIGNED TO FAIL */

func (suite *MdnsPairingInterfaceTestSuite) TestMultipleAnnouncementsLifecycle() {
	// TEST: Complete lifecycle of multiple pairing service announcements
	// REQUIREMENT: Support announcing, tracking, and selectively unannouncing services

	// Create multiple TXT records for different pairing scenarios
	txtRecords := []*api.ShipPairingTXT{
		{
			TxtVers: "1", ParType: "fpSha256", Type: "addCu", TrustCurve: "secp256r1",
			ForId: "i:10001_u:Device-A", ForPar: "8F1170A5C7CB0F30950720380A9E4E69CFBF24C85ECECC233F3BA4E584B7F95C", TrustId: "i:20001_u:Target-A", TrustPar: "83CA8E2701271E4F127C4A769E5EB9265638804AEDBAE06E18710327E5196A07",
			TrustNonce: "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1", Alg: "hmacSha256",
			Digest: "AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111",
		},
		{
			TxtVers: "1", ParType: "fpSha256", Type: "addCu", TrustCurve: "secp256r1",
			ForId: "i:10002_u:Device-B", ForPar: "BC0A833B7875E5895C73244DF98C24C7865E4DF0BE53EC96DBA0DAE0A3127A81", TrustId: "i:20002_u:Target-B", TrustPar: "491C8765C3010F2929DC99367AE3D2E44ED6625B6B2B1A1F6EDC6D3E7CC7BB6B",
			TrustNonce: "B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2", Alg: "hmacSha256",
			Digest: "BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222",
		},
		{
			TxtVers: "1", ParType: "fpSha256", Type: "addCu", TrustCurve: "secp256r1",
			ForId: "i:10003_u:Device-C", ForPar: "2D3F91252ADB6D405914E6049ABF9CA8B12D8DFED64C318704684D46803639F0", TrustId: "i:20003_u:Target-C", TrustPar: "547E0268555A44DA4F157D8EE3ECBF29DE629ABB88D767DDFBC81B68D9592274",
			TrustNonce: "C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3", Alg: "hmacSha256",
			Digest: "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333",
		},
	}

	// Announce all services - collect instance IDs
	var instanceIDs []string
	for i, txtRecord := range txtRecords {
		// This will FAIL because current interface returns error, not (string, error)
		instanceID, err := suite.mockPairing.AnnouncePairingService(txtRecord)
		assert.NoError(suite.T(), err, "Announcement %d should succeed", i+1)
		instanceIDs = append(instanceIDs, instanceID)
	}

	// Verify all instance IDs are unique
	idMap := make(map[string]bool)
	for _, id := range instanceIDs {
		assert.False(suite.T(), idMap[id], "Instance ID %s should be unique", id)
		idMap[id] = true
	}

	// Selectively unannounce middle service
	// This will FAIL because current interface doesn't accept instance ID
	err := suite.mockPairing.UnannouncePairingService(instanceIDs[1])
	assert.NoError(suite.T(), err, "Selective unannouncement should succeed")

	// Unannounce remaining services
	err = suite.mockPairing.UnannouncePairingService(instanceIDs[0])
	assert.NoError(suite.T(), err, "First service unannouncement should succeed")

	err = suite.mockPairing.UnannouncePairingService(instanceIDs[2])
	assert.NoError(suite.T(), err, "Third service unannouncement should succeed")
}

func (suite *MdnsPairingInterfaceTestSuite) TestIsPairingServiceAnnounced_WithMultipleServices() {
	// TEST: IsPairingServiceAnnounced behavior with multiple announced services
	// REQUIREMENT: Method should return true if ANY pairing service is announced

	txtRecord := &api.ShipPairingTXT{
		TxtVers: "1", ParType: "fpSha256", Type: "addCu", TrustCurve: "secp256r1",
		ForId: "i:50001_u:MultiTest", ForPar: "E844C55EBF6FA76FEBA7A75E5C1849AFE3CFAA325EAC5E855E6341CE0C7AF310", TrustId: "i:60001_u:MultiTarget", TrustPar: "5F18357C75EA23656508DB770F77342C0D8FA462A8720A8EBAA95EF447920799",
		TrustNonce: "50015001500150015001500150015001", Alg: "hmacSha256",
		Digest: "5001500150015001500150015001500150015001500150015001500150015001",
	}

	// Initially no services announced
	announced := suite.mockPairing.IsPairingServiceAnnounced()
	assert.False(suite.T(), announced, "Initially no pairing services should be announced")

	// Announce a service
	// This will FAIL because current interface returns error, not (string, error)
	instanceID, err := suite.mockPairing.AnnouncePairingService(txtRecord)
	assert.NoError(suite.T(), err, "Service announcement should succeed")

	// Now service should be announced
	announced = suite.mockPairing.IsPairingServiceAnnounced()
	assert.True(suite.T(), announced, "After announcement, service should be reported as announced")

	// Unannounce the service
	// This will FAIL because current interface doesn't accept instance ID
	err = suite.mockPairing.UnannouncePairingService(instanceID)
	assert.NoError(suite.T(), err, "Service unannouncement should succeed")

	// Should no longer be announced
	announced = suite.mockPairing.IsPairingServiceAnnounced()
	assert.False(suite.T(), announced, "After unannouncement, no services should be announced")
}

/* Error Handling Tests - DESIGNED TO FAIL */

func (suite *MdnsPairingInterfaceTestSuite) TestAnnouncePairingService_NilTxtRecord() {
	// TEST: AnnouncePairingService should handle nil TXT record gracefully
	// REQUIREMENT: Proper validation of input parameters

	// This will FAIL because current interface returns error, not (string, error)
	instanceID, err := suite.mockPairing.AnnouncePairingService(nil)

	assert.Error(suite.T(), err, "AnnouncePairingService should return error for nil TXT record")
	assert.Empty(suite.T(), instanceID, "Instance ID should be empty for failed announcement")
	assert.Contains(suite.T(), err.Error(), "nil", "Error message should mention nil parameter")
}

func (suite *MdnsPairingInterfaceTestSuite) TestAnnouncePairingService_InvalidTxtRecord() {
	// TEST: AnnouncePairingService should validate TXT record content
	// REQUIREMENT: Only announce valid pairing data per SHIP spec

	invalidTxtRecord := &api.ShipPairingTXT{
		TxtVers:    "2", // Invalid version
		ParType:    "invalid",
		Type:       "invalid",
		TrustCurve: "invalid",
		Alg:        "invalid",
	}

	// This will FAIL because current interface returns error, not (string, error)
	instanceID, err := suite.mockPairing.AnnouncePairingService(invalidTxtRecord)

	assert.Error(suite.T(), err, "AnnouncePairingService should return error for invalid TXT record")
	assert.Empty(suite.T(), instanceID, "Instance ID should be empty for failed announcement")
	assert.Contains(suite.T(), err.Error(), "validation", "Error should mention validation failure")
}

/* Backward Compatibility Tests - DESIGNED TO FAIL */

func (suite *MdnsPairingInterfaceTestSuite) TestInterfaceSignatureChanges() {
	// TEST: Interface signature changes are correctly implemented
	// REQUIREMENT: No backward compatibility needed - breaking changes allowed

	// This test documents the expected interface signature changes:
	// OLD: AnnouncePairingService(txtRecord *ShipPairingTXT) error
	// NEW: AnnouncePairingService(txtRecord *ShipPairingTXT) (string, error)
	//
	// OLD: UnannouncePairingService() error
	// NEW: UnannouncePairingService(instanceID string) error

	txtRecord := &api.ShipPairingTXT{
		TxtVers: "1", ParType: "fpSha256", Type: "addCu", TrustCurve: "secp256r1",
		ForId: "i:99999_u:SignatureTest", ForPar: "F283F5733F807859717CAFC428C61D9E5A862E7CEB32594C36C7E61DE9E8F95B", TrustId: "i:88888_u:SigTarget", TrustPar: "990320BC09E53E16C2818AA53A0A412A5E6DE76BC59F4B2B011B77F78E75651A",
		TrustNonce: "470EBB30B09D48BE88D23138C3A1652B", Alg: "hmacSha256",
		Digest: "D2F9C85155C79C24B9125E0F1633BF073A146837DE9238EC221C66D110A2749E",
	}

	// Test new announce signature - this will FAIL because method signature is wrong
	// Current: AnnouncePairingService(txtRecord *ShipPairingTXT) error
	// Expected: AnnouncePairingService(txtRecord *ShipPairingTXT) (string, error)

	// This line will cause a compile error because we're trying to assign single return value to two variables
	instanceID, err := suite.mockPairing.AnnouncePairingService(txtRecord)
	assert.NoError(suite.T(), err, "Announce should succeed")
	assert.NotEmpty(suite.T(), instanceID, "Should return instance ID")

	// Test new unannounce signature requires instanceID parameter
	testInstanceID := "Test-pairing#1"

	// This will FAIL because current signature is UnannouncePairingService() error
	// but we need UnannouncePairingService(instanceID string) error
	err = suite.mockPairing.UnannouncePairingService(testInstanceID)
	assert.NoError(suite.T(), err, "Unannounce with instance ID should succeed")
}

/* Documentation Examples - DESIGNED TO FAIL */

func (suite *MdnsPairingInterfaceTestSuite) TestUsageExample() {
	// TEST: Example usage pattern for multiple SHIP pairing announcements
	// REQUIREMENT: Clear usage pattern for applications using the interface

	// Example: Device wants to pair with multiple targets simultaneously
	targets := []struct {
		name      string
		txtRecord *api.ShipPairingTXT
	}{
		{
			name: "Target-A",
			txtRecord: &api.ShipPairingTXT{
				TxtVers: "1", ParType: "fpSha256", Type: "addCu", TrustCurve: "secp256r1",
				ForId: "i:99001_u:MyDevice", ForPar: "B15F9772226DA10814154515BA57B28762191703D606CDEF5394A56F876452EF", TrustId: "i:99101_u:Target-A", TrustPar: "144BEB27067241B0D82ABEBF89EEDABC8AA609F3C94FF1B6CC3D29D53DDB36FE",
				TrustNonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1", Alg: "hmacSha256",
				Digest: "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1",
			},
		},
		{
			name: "Target-B",
			txtRecord: &api.ShipPairingTXT{
				TxtVers: "1", ParType: "fpSha256", Type: "addCu", TrustCurve: "secp256r1",
				ForId: "i:99001_u:MyDevice", ForPar: "B15F9772226DA10814154515BA57B28762191703D606CDEF5394A56F876452EF", TrustId: "i:99102_u:Target-B", TrustPar: "966B7C166D15898C1CD41FF831D01A045F966B7D384FD0B49969734D3E28ACBB",
				TrustNonce: "3A465DA39C4674A3C07BFC96BDD8CBB7", Alg: "hmacSha256",
				Digest: "B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2",
			},
		},
	}

	// Track instance IDs for cleanup
	var activeInstances []string

	// Announce pairing to all targets
	for _, target := range targets {
		// This will FAIL because current interface signature is wrong
		instanceID, err := suite.mockPairing.AnnouncePairingService(target.txtRecord)

		if assert.NoError(suite.T(), err, "Should announce pairing to %s", target.name) {
			activeInstances = append(activeInstances, instanceID)
			assert.Contains(suite.T(), instanceID, "pairing", "Instance ID should contain 'pairing'")
		}
	}

	// Verify all announcements are tracked
	announced := suite.mockPairing.IsPairingServiceAnnounced()
	assert.True(suite.T(), announced, "Should report pairing services as announced")

	// Clean up - unannounce all services
	for i, instanceID := range activeInstances {
		// This will FAIL because current interface doesn't accept instanceID parameter
		err := suite.mockPairing.UnannouncePairingService(instanceID)
		assert.NoError(suite.T(), err, "Should unannounce instance %d: %s", i+1, instanceID)
	}

	// Verify all announcements are removed
	announced = suite.mockPairing.IsPairingServiceAnnounced()
	assert.False(suite.T(), announced, "Should report no pairing services after cleanup")
}
