package mdns

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

func TestSearchPairingIntegrationSuite(t *testing.T) {
	suite.Run(t, new(SearchPairingIntegrationSuite))
}

type SearchPairingIntegrationSuite struct {
	suite.Suite

	sut          *MdnsManager
	mockProvider *mocks.MdnsProviderInterface
}

func (s *SearchPairingIntegrationSuite) SetupTest() {
	s.mockProvider = mocks.NewMdnsProviderInterface(s.T())

	s.sut = NewMDNS("test", "brand", "model", "EnergyManagementSystem",
		"12345",
		nil,
		"testski", "serviceName",
		4729, nil, MdnsProviderSelectionTestSetup)

	// Set the mock provider
	s.sut.SetMdnsProvider(s.mockProvider)
}

func (s *SearchPairingIntegrationSuite) Test_SearchPairingServices_ActiveDiscovery() {
	// SearchPairingServices should ensure the provider is actively browsing for pairing services
	// This test validates that the callback is properly registered and invoked when
	// pairing services are discovered through the provider

	var discoveredServices []*api.ShipPairingTXT
	var mu sync.Mutex

	callback := func(data *api.ShipPairingTXT) bool {
		mu.Lock()
		discoveredServices = append(discoveredServices, data)
		mu.Unlock()
		return true
	}

	// Mock provider Start and Announce
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).
		RunAndReturn(func(pairingMode api.PairingMode, browsing bool, cb api.MdnsResolveCB) bool {
			// Simulate the provider discovering pairing services

			// Simulate discovery of a pairing service after a short delay
			go func() {
				time.Sleep(10 * time.Millisecond)

				// Simulate SMGW announcing pairing for heat pump
				pairingElements := map[string]string{
					"txtvers":    "1",
					"partype":    "fpSha256",
					"forid":      "HeatPump-X",
					"forpar":     "BB01A0569C9433A5C10D8D60A5ACAB1DD9BCB56AB61AA49CCDB5CAD1D49A5981",
					"trustid":    "SMGW-Pro",
					"trustpar":   "5EA9D61CB7BD29BD247D3978D9D7171D9FC22E98E059378B0CCB810E216E123E",
					"trustcurve": "secp256r1",
					"type":       "addCu",
					"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
					"alg":        "hmacSha256",
					"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
				}
				cb(pairingElements, "smgw-pairing", "smgw.local", "_shippairing._tcp", []net.IP{}, 0, false)
			}()
			return true
		}).
		Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()

	// Start the manager first
	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Now call SearchPairingServices
	err = s.sut.SearchPairingServices(callback)
	assert.NoError(s.T(), err)

	// Wait for discovery
	time.Sleep(50 * time.Millisecond)

	// Verify service was discovered
	mu.Lock()
	assert.Len(s.T(), discoveredServices, 1)
	if len(discoveredServices) > 0 {
		service := discoveredServices[0]
		assert.Equal(s.T(), "HeatPump-X", service.ForId)
		assert.Equal(s.T(), "BB01A0569C9433A5C10D8D60A5ACAB1DD9BCB56AB61AA49CCDB5CAD1D49A5981", service.ForPar)
		assert.Equal(s.T(), "SMGW-Pro", service.TrustId)
		assert.Equal(s.T(), "5EA9D61CB7BD29BD247D3978D9D7171D9FC22E98E059378B0CCB810E216E123E", service.TrustPar)
		assert.Equal(s.T(), "addCu", service.Type)
	}
	mu.Unlock()
}

func (s *SearchPairingIntegrationSuite) Test_SearchPairingServices_FiltersBySKI() {
	// Test that SearchPairingServices can filter pairing offers by target SKI
	// This simulates a heat pump only accepting pairing offers meant for it

	heatPumpPAR := "5242032C6E1499BECD5772673847C3465E339B8C3B375645BE3894B321FD3521"
	var receivedOffer *api.ShipPairingTXT

	// Callback that only accepts offers for this specific heat pump
	callback := func(data *api.ShipPairingTXT) bool {
		if data.ForPar == heatPumpPAR {
			receivedOffer = data
			return true
		}
		return false
	}

	// Start the provider and manager
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()

	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Register the callback
	err = s.sut.SearchPairingServices(callback)
	assert.NoError(s.T(), err)

	// Simulate multiple pairing announcements
	pairingForOther := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "OtherDevice",
		"forpar":     "E5635F4F84E95DC5B157270FFFEBD3F5C51495ACF7F76873DD934AE3BE3A7195", // Different PAR
		"trustid":    "SMGW-1",
		"trustpar":   "05E1FE249857D0E94DC9FBFFBFD8D7A5430788A89E83F1C884398189B6A8E768",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	pairingForUs := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "HeatPump",
		"forpar":     heatPumpPAR, // Our PAR
		"trustid":    "SMGW-2",
		"trustpar":   "A96AC97A999CC5AFB8A908F2515E6657E65CF25A486B9C19DC165F3BAD374A47",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	// Process both entries
	s.sut.processShipPairingMdnsEntry(pairingForOther, "servicename1", false)
	s.sut.processShipPairingMdnsEntry(pairingForUs, "servicename2", false)

	// Only the offer for our PAR should be accepted
	assert.NotNil(s.T(), receivedOffer)
	assert.Equal(s.T(), heatPumpPAR, receivedOffer.ForPar)
	assert.Equal(s.T(), "SMGW-2", receivedOffer.TrustId)
}

func (s *SearchPairingIntegrationSuite) Test_SearchPairingServices_HandlesRemoval() {
	// Test that pairing service removals are handled correctly

	var callbackCount int
	var mu sync.Mutex

	callback := func(data *api.ShipPairingTXT) bool {
		mu.Lock()
		defer mu.Unlock()
		// In a real implementation, we might track whether this is an add or remove
		// For now, we just count callbacks
		callbackCount++
		return true
	}

	// Start the provider and manager
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()

	// Start the manager first
	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	err = s.sut.SearchPairingServices(callback)
	assert.NoError(s.T(), err)

	pairingElements := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "Device",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "SMGW",
		"trustpar":   "169CC063AAF7299B9718BA3DFDC223BF6A037DDD97582B79A07CF20B9D346027",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	// Add the service
	s.sut.processShipPairingMdnsEntry(pairingElements, "servicename", false)

	// Remove the service
	s.sut.processShipPairingMdnsEntry(pairingElements, "servicename", true)

	mu.Lock()
	// Only add should trigger callbacks
	assert.Equal(s.T(), 1, callbackCount)
	mu.Unlock()
}

func (s *SearchPairingIntegrationSuite) Test_SearchPairingServices_ReplaceCallback() {
	// Test that calling SearchPairingServices multiple times replaces the callback

	var firstCalled, secondCalled bool

	firstCallback := func(data *api.ShipPairingTXT) bool {
		firstCalled = true
		return true
	}

	secondCallback := func(data *api.ShipPairingTXT) bool {
		secondCalled = true
		return true
	}

	// Start the provider and manager
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()

	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Register first callback
	err = s.sut.SearchPairingServices(firstCallback)
	assert.NoError(s.T(), err)

	// Replace with second callback
	err = s.sut.SearchPairingServices(secondCallback)
	assert.NoError(s.T(), err)

	// Trigger a discovery
	pairingElements := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "Device",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "SMGW",
		"trustpar":   "169CC063AAF7299B9718BA3DFDC223BF6A037DDD97582B79A07CF20B9D346027",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	s.sut.processShipPairingMdnsEntry(pairingElements, "servicename", false)

	// Only second callback should be called
	assert.False(s.T(), firstCalled)
	assert.True(s.T(), secondCalled)
}

func (s *SearchPairingIntegrationSuite) Test_SearchPairingServices_WithProviderRestart() {
	// Test that SearchPairingServices works correctly when provider needs to be started

	callback := func(data *api.ShipPairingTXT) bool {
		return true
	}

	// Start the provider and manager
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()

	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// SearchPairingServices should work after manager is started
	err = s.sut.SearchPairingServices(callback)
	assert.NoError(s.T(), err)

	// Verify callback is registered
	s.sut.mux.Lock()
	assert.NotNil(s.T(), s.sut.pairingCallback)
	s.sut.mux.Unlock()
}

func (s *SearchPairingIntegrationSuite) Test_SearchPairingServices_ValidationErrors() {
	// Test error cases

	// Nil callback
	err := s.sut.SearchPairingServices(nil)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "callback cannot be nil")

	// Manager not started
	err = s.sut.SearchPairingServices(func(*api.ShipPairingTXT) bool { return true })
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "not started")

	// Start the manager first
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()

	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err = s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Now test with no provider
	s.sut.mdnsProvider = nil
	err = s.sut.SearchPairingServices(func(*api.ShipPairingTXT) bool { return true })
	assert.Error(s.T(), err)
	assert.Equal(s.T(), api.ErrMDNSSearchFailed, err)
}

func (s *SearchPairingIntegrationSuite) Test_SearchPairingServices_RealWorldScenario() {
	// Simulate a real-world heat pump listening for SMGW pairing announcements

	heatPumpPAR := "1F6522C41DA6D4EAEB5136453D4DEC6B4DE30710F9C5E494F3B8D9D67645A760"
	smgwPAR := "85C00706029A6B6226511F3D3599A6A087823F0B226E94A1785C800BE619BCE9"

	// Track all discovered pairing offers
	var offers []*api.ShipPairingTXT
	var acceptedOffer *api.ShipPairingTXT
	var mu sync.Mutex

	// Heat pump's pairing callback
	heatPumpCallback := func(data *api.ShipPairingTXT) bool {
		mu.Lock()
		defer mu.Unlock()

		offers = append(offers, data)

		// Accept only offers targeting this heat pump
		if data.ForPar == heatPumpPAR {
			// Validate the offer (in real implementation, would check digest, etc.)
			if data.Type == "addCu" && data.TrustPar != "" {
				acceptedOffer = data
				return true
			}
		}
		return false
	}

	// Start the provider and manager
	s.mockProvider.EXPECT().Start(api.PairingModeBoth, true, mock.AnythingOfType("api.MdnsResolveCB")).Return(true).Once()
	s.mockProvider.EXPECT().AnnounceService(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("1", nil).Once()

	mockReport := mocks.NewMdnsReportInterface(s.T())
	mockReport.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe().Return()
	err := s.sut.Start(api.PairingModeBoth, mockReport)
	assert.NoError(s.T(), err)

	// Heat pump starts listening
	err = s.sut.SearchPairingServices(heatPumpCallback)
	assert.NoError(s.T(), err)

	// Simulate SMGW broadcasting pairing offers
	// First, an offer for a different device
	otherOffer := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "WashingMachine-Model-Z",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "SMGW-Pro-2000",
		"trustpar":   smgwPAR,
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	s.sut.processShipPairingMdnsEntry(otherOffer, "servicename1", false)

	// Then, an offer for our heat pump
	ourOffer := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "HeatPump-Model-X",
		"forpar":     heatPumpPAR,
		"trustid":    "SMGW-Pro-2000",
		"trustpar":   smgwPAR,
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	s.sut.processShipPairingMdnsEntry(ourOffer, "servicename2", false)

	// Verify results
	mu.Lock()
	assert.Len(s.T(), offers, 2, "Should have seen both offers")
	assert.NotNil(s.T(), acceptedOffer, "Should have accepted the offer for our heat pump")
	if acceptedOffer != nil {
		assert.Equal(s.T(), heatPumpPAR, acceptedOffer.ForPar)
		assert.Equal(s.T(), smgwPAR, acceptedOffer.TrustPar)
		assert.Equal(s.T(), "HeatPump-Model-X", acceptedOffer.ForId)
	}
	mu.Unlock()
}
