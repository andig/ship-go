package mdns

import (
	"testing"

	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

func TestSearchPairingServicesSuite(t *testing.T) {
	suite.Run(t, new(SearchPairingServicesSuite))
}

type SearchPairingServicesSuite struct {
	suite.Suite

	sut          *MdnsManager
	mockProvider *mocks.MdnsProviderInterface
}

func (s *SearchPairingServicesSuite) SetupTest() {
	s.mockProvider = mocks.NewMdnsProviderInterface(s.T())

	s.sut = NewMDNS("test", "brand", "model", "EnergyManagementSystem",
		"12345",
		nil,
		"shipid", "serviceName",
		4729, nil, MdnsProviderSelectionTestSetup)

	// Set the mock provider
	s.sut.SetMdnsProvider(s.mockProvider)
}

func (s *SearchPairingServicesSuite) Test_SearchPairingServices_Success() {
	callbackCalled := false
	var receivedData *api.ShipPairingTXT

	callback := func(data *api.ShipPairingTXT) bool {
		callbackCalled = true
		receivedData = data
		return true
	}

	// Mock provider Start
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()

	// Start the mDNS manager first
	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Call SearchPairingServices
	err = s.sut.SearchPairingServices(callback)
	assert.NoError(s.T(), err)

	// Verify callback was registered
	s.sut.mux.Lock()
	assert.NotNil(s.T(), s.sut.pairingCallback)
	s.sut.mux.Unlock()

	// Simulate a pairing service discovery via the routing mechanism
	pairingElements := map[string]string{
		"txtvers":    "1",
		"parType":    "fpSha256",
		"forId":      "target-id",
		"forPar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustId":    "source-id",
		"trustPar":   "2CC72E781F7A7D2A08D50196C50FEDF0F7BA583F43F76C8C0DDEC9EEF0D005B4",
		"trustCurve": "secp256r1",
		"type":       "addCu",
		"trustNonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	// This simulates what happens when provider discovers a _shippairing._tcp service
	s.sut.processShipPairingMdnsEntry(pairingElements, "servicename", false)

	// Verify callback was called
	assert.True(s.T(), callbackCalled)
	assert.NotNil(s.T(), receivedData)
	assert.Equal(s.T(), "1", receivedData.TxtVers)
	assert.Equal(s.T(), "target-id", receivedData.ForId)
}

func (s *SearchPairingServicesSuite) Test_SearchPairingServices_NoProvider() {
	// Remove provider
	s.sut.mdnsProvider = nil

	callback := func(data *api.ShipPairingTXT) bool {
		return true
	}

	// Should fail without provider
	err := s.sut.SearchPairingServices(callback)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "not started")
}

func (s *SearchPairingServicesSuite) Test_SearchPairingServices_NotStarted() {
	// Test that SearchPairingServices fails if Start() hasn't been called
	callback := func(data *api.ShipPairingTXT) bool {
		return true
	}

	// Should fail if manager not started
	err := s.sut.SearchPairingServices(callback)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "not started")
}

func (s *SearchPairingServicesSuite) Test_SearchPairingServices_NilCallback() {
	// Should fail with nil callback
	err := s.sut.SearchPairingServices(nil)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "callback cannot be nil")
}

func (s *SearchPairingServicesSuite) Test_SearchPairingServices_MultipleCallbacks() {
	// Test that registering a new callback replaces the old one
	firstCallbackCalled := false
	secondCallbackCalled := false

	firstCallback := func(data *api.ShipPairingTXT) bool {
		firstCallbackCalled = true
		return true
	}

	secondCallback := func(data *api.ShipPairingTXT) bool {
		secondCallbackCalled = true
		return true
	}

	// Set provider selection to test setup mode
	s.sut.providerSelection = MdnsProviderSelectionTestSetup

	// Start the manager first
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()
	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Register first callback
	err = s.sut.SearchPairingServices(firstCallback)
	assert.NoError(s.T(), err)

	// Register second callback (should replace first)
	err = s.sut.SearchPairingServices(secondCallback)
	assert.NoError(s.T(), err)

	// Simulate pairing service discovery
	pairingElements := map[string]string{
		"txtvers":    "1",
		"parType":    "fpSha256",
		"forId":      "test",
		"forPar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustId":    "test",
		"trustPar":   "2CC72E781F7A7D2A08D50196C50FEDF0F7BA583F43F76C8C0DDEC9EEF0D005B4",
		"trustCurve": "secp256r1",
		"type":       "addCu",
		"trustNonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	s.sut.processShipPairingMdnsEntry(pairingElements, "servicename", false)

	// Only second callback should be called
	assert.False(s.T(), firstCallbackCalled)
	assert.True(s.T(), secondCallbackCalled)
}

func (s *SearchPairingServicesSuite) Test_IntegrationWithRouting() {
	// Test that the routing mechanism correctly routes pairing services
	pairingCallbackCalled := false

	pairingCallback := func(data *api.ShipPairingTXT) bool {
		pairingCallbackCalled = true
		return true
	}

	// Set provider selection to test setup mode
	s.sut.providerSelection = MdnsProviderSelectionTestSetup

	// Start the manager first
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()
	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Register pairing callback
	err = s.sut.SearchPairingServices(pairingCallback)
	assert.NoError(s.T(), err)

	// Test data for different service types
	shipElements := map[string]string{
		"txtvers":  "1",
		"id":       "ship-id",
		"path":     "/ship/",
		"ski":      "shipski",
		"register": "true",
	}

	pairingElements := map[string]string{
		"txtvers":    "1",
		"parType":    "fpSha256",
		"forId":      "target",
		"forPar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustId":    "source",
		"trustPar":   "2CC72E781F7A7D2A08D50196C50FEDF0F7BA583F43F76C8C0DDEC9EEF0D005B4",
		"trustCurve": "secp256r1",
		"type":       "addCu",
		"trustNonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	// Process a regular SHIP entry through the main entry point
	s.sut.processMdnsEntry(shipElements, "ship-service", "host", "_ship._tcp", nil, 4729, false)

	// Pairing callback should NOT be called for regular SHIP services
	assert.False(s.T(), pairingCallbackCalled)

	// Process a pairing entry through the main entry point
	s.sut.processMdnsEntry(pairingElements, "pairing-service", "host", "_shippairing._tcp", nil, 0, false)

	// Pairing callback SHOULD be called for pairing services
	assert.True(s.T(), pairingCallbackCalled)
}

func (s *SearchPairingServicesSuite) Test_UnregisterStopsCallbacks() {
	callbackCalled := false

	callback := func(data *api.ShipPairingTXT) bool {
		callbackCalled = true
		return true
	}

	// Set provider selection to test setup mode
	s.sut.providerSelection = MdnsProviderSelectionTestSetup

	// Start the manager first
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()
	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Register callback
	err = s.sut.SearchPairingServices(callback)
	assert.NoError(s.T(), err)

	// Unregister callback
	s.sut.UnregisterPairingCallback()

	// Simulate pairing service discovery
	pairingElements := map[string]string{
		"txtvers":    "1",
		"parType":    "fpSha256",
		"forId":      "test",
		"forPar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustId":    "test",
		"trustPar":   "2CC72E781F7A7D2A08D50196C50FEDF0F7BA583F43F76C8C0DDEC9EEF0D005B4",
		"trustCurve": "secp256r1",
		"type":       "addCu",
		"trustNonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	s.sut.processShipPairingMdnsEntry(pairingElements, "servicename", false)

	// Callback should NOT be called after unregistering
	assert.False(s.T(), callbackCalled)
}
