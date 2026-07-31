package mdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/mocks"
)

// ProviderExtensionTestSuite tests mDNS provider extensions through MdnsManager
// Uses proper mock-based testing following existing ship-go patterns
type ProviderExtensionTestSuite struct {
	suite.Suite

	// Mock provider and manager following existing patterns
	mockProvider *mocks.MdnsProviderInterface
	mockReporter *mocks.MdnsReportInterface
	manager      *MdnsManager
}

func TestProviderExtensionTestSuite(t *testing.T) {
	suite.Run(t, new(ProviderExtensionTestSuite))
}

func (suite *ProviderExtensionTestSuite) SetupTest() {
	// Setup mocks following existing mdns_test.go pattern
	suite.mockProvider = mocks.NewMdnsProviderInterface(suite.T())
	suite.mockReporter = mocks.NewMdnsReportInterface(suite.T())

	// Set up mock expectations following existing patterns
	suite.mockProvider.EXPECT().Start(mock.Anything, mock.Anything, mock.Anything).Return(true).Maybe()
	suite.mockProvider.EXPECT().Shutdown().Return().Maybe()

	// Create MdnsManager with correct parameter order
	suite.manager = NewMDNS(
		"test",                   // ski
		"brand",                  // deviceBrand
		"model",                  // deviceModel
		"EnergyManagementSystem", // deviceType
		"12345",                  // deviceSerial
		[]api.DeviceCategoryType{api.DeviceCategoryTypeEnergyManagementSystem}, // deviceCategories
		"shipid",                       // shipIdentifier
		"serviceName",                  // serviceName
		4729,                           // port
		nil,                            // ifaces
		MdnsProviderSelectionTestSetup, // providerSelection
	)

	// Set provider directly using your new cleaner method
	suite.manager.SetMdnsProvider(suite.mockProvider)
}

/* TDD Tests for Direct Provider Extension */

func (suite *ProviderExtensionTestSuite) TestMdnsManagerDualServiceSupport() {
	// Test that MdnsManager properly supports both _ship._tcp and _shippairing._tcp

	// Set up specific expectations for this test (instead of relying on .Maybe() from setup)
	// Expect _ship._tcp service call from AnnounceMdnsEntry()
	suite.mockProvider.EXPECT().AnnounceService(shipZeroConfServiceType, mock.AnythingOfType("string"), mock.AnythingOfType("int"), mock.AnythingOfType("[]string")).Return("1", nil).Once()

	// Expect _shippairing._tcp service call from AnnouncePairingService()
	suite.mockProvider.EXPECT().AnnounceService(shipPairingZeroConfServiceType, mock.AnythingOfType("string"), mock.AnythingOfType("int"), mock.AnythingOfType("[]string")).Return("1", nil).Once()

	// Test existing _ship._tcp functionality (should work as before)
	err := suite.manager.AnnounceMdnsEntry()
	assert.NoError(suite.T(), err, "AnnounceMdnsEntry should work with proper setup")

	// Test that pairing service methods exist and can be called
	txtRecord := &api.ShipPairingTXT{
		TxtVers:    "1",
		ParType:    api.ParTypeFPSHA256,
		ForId:      "test-device",
		TrustId:    "test-announcer",
		TrustCurve: api.CurveSecp256r1,
		Type:       api.CommandTypeAddCU,
		Alg:        api.AlgorithmHMACSHA256,
		Digest:     "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
		ForPar:     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		TrustPar:   "2CC72E781F7A7D2A08D50196C50FEDF0F7BA583F43F76C8C0DDEC9EEF0D005B4",
		TrustNonce: "BDCEE427FA7208DF3C1F2A749BA6F4D4",
	}

	// With mock provider, should delegate correctly
	_, err = suite.manager.AnnouncePairingService(txtRecord)
	assert.NoError(suite.T(), err, "MdnsManager should delegate to mock provider")
}

func (suite *ProviderExtensionTestSuite) TestProviderMethodDelegation() {
	// Test that enhanced provider methods are called correctly

	// Set specific expectation for pairing service delegation - use On() to avoid conflicts
	suite.mockProvider.EXPECT().AnnounceService(shipPairingZeroConfServiceType, mock.AnythingOfType("string"), mock.AnythingOfType("int"), mock.AnythingOfType("[]string")).Return("1", nil).Once()

	txtRecord := &api.ShipPairingTXT{
		TxtVers:    "1",
		ParType:    api.ParTypeFPSHA256,
		ForId:      "test-device",
		ForPar:     "52CEAF55186DAB7E93F7D385E66819C16EEE47DE14DDFF0FEFFFA3D5A2EF18F2",
		TrustId:    "test-announcer",
		TrustPar:   "1E1BD0093E1F68FE59AA85E8B10842EAAB63177B81C835BA4EC69C8A8B6E4018",
		TrustCurve: api.CurveSecp256r1,
		Type:       api.CommandTypeAddCU,
		TrustNonce: "ED04C4E9EA6C49CF9CEB39098787C5B9",
		Alg:        api.AlgorithmHMACSHA256,
		Digest:     "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
	}

	// Test that MdnsManager delegates to provider
	instanceID, err := suite.manager.AnnouncePairingService(txtRecord)
	if err != nil {
		suite.T().Logf("AnnouncePairingService failed: %v", err)
	}
	assert.NoError(suite.T(), err, "Should delegate to provider.AnnounceService")
	assert.NotEmpty(suite.T(), instanceID, "Should return non-empty instance ID")

	// Test unannouncement delegation - use On() to avoid conflicts
	suite.mockProvider.EXPECT().UnannounceService(mock.Anything).Return(nil).Once()
	err = suite.manager.UnannouncePairingService(instanceID)
	if err != nil {
		suite.T().Logf("UnannouncePairingService failed: %v", err)
	}
	assert.NoError(suite.T(), err, "Should delegate to provider.UnannounceService")
}

/* Backward Compatibility Tests */

func (suite *ProviderExtensionTestSuite) TestBackwardCompatibility_ExistingMethods() {
	// Test that existing _ship._tcp functionality continues working unchanged

	// Set up expectation for the AnnounceMdnsEntry call
	suite.mockProvider.EXPECT().AnnounceService(shipZeroConfServiceType, mock.AnythingOfType("string"), mock.AnythingOfType("int"), mock.AnythingOfType("[]string")).Return("1", nil).Once()

	// Test existing functionality through MdnsManager
	err := suite.manager.AnnounceMdnsEntry()
	assert.NoError(suite.T(), err, "AnnounceMdnsEntry should work with proper setup")

	// Set up expectation for the UnannounceMdnsEntry call
	suite.mockProvider.EXPECT().UnannounceService(mock.Anything).Return(nil).Once()

	// Test cleanup
	suite.manager.UnannounceMdnsEntry()
	// Should not crash - validates backward compatibility
}

func (suite *ProviderExtensionTestSuite) TestInterfaceCompliance() {
	// Test that MdnsManager implements both interfaces

	var _ api.MdnsInterface = suite.manager
	var _ api.MdnsPairingInterface = suite.manager

	// This test passing proves interface compliance is maintained
	assert.NotNil(suite.T(), suite.manager)
}
