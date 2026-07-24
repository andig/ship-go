package mdns

import (
	"testing"

	"github.com/enbility/ship-go/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestPairingProcessorSuite(t *testing.T) {
	suite.Run(t, new(PairingProcessorSuite))
}

type PairingProcessorSuite struct {
	suite.Suite

	sut                 *MdnsManager
	pairingCallback     func(*api.ShipPairingTXT) bool
	receivedPairingData *api.ShipPairingTXT
}

func (s *PairingProcessorSuite) SetupTest() {
	s.sut = NewMDNS("test", "brand", "model", "EnergyManagementSystem",
		"12345",
		nil,
		"shipid", "serviceName",
		4729, nil, MdnsProviderSelectionAll)

	// Reset callback tracking
	s.receivedPairingData = nil
	s.pairingCallback = func(data *api.ShipPairingTXT) bool {
		s.receivedPairingData = data
		return true
	}
}

func (s *PairingProcessorSuite) Test_processPairingEntry_ValidEntry() {
	// Prepare valid pairing TXT elements
	elements := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "target-device-id",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "source-device-id",
		"trustpar":   "5D41CB9A91494591C5ED24F7FE764E05F7381EE277F2F783841087621CD606D5",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	remove := false

	// Register callback
	s.sut.RegisterPairingCallback(s.pairingCallback)

	// Process the pairing entry
	s.sut.processShipPairingMdnsEntry(elements, "servicename", remove)

	// Verify callback was called with correct data
	assert.NotNil(s.T(), s.receivedPairingData)
	assert.Equal(s.T(), "1", s.receivedPairingData.TxtVers)
	assert.Equal(s.T(), "fpSha256", s.receivedPairingData.ParType)
	assert.Equal(s.T(), "target-device-id", s.receivedPairingData.ForId)
	assert.Equal(s.T(), "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943", s.receivedPairingData.ForPar)
	assert.Equal(s.T(), "source-device-id", s.receivedPairingData.TrustId)
	assert.Equal(s.T(), "5D41CB9A91494591C5ED24F7FE764E05F7381EE277F2F783841087621CD606D5", s.receivedPairingData.TrustPar)
	assert.Equal(s.T(), "secp256r1", s.receivedPairingData.TrustCurve)
	assert.Equal(s.T(), "addCu", s.receivedPairingData.Type)
	assert.Equal(s.T(), "BDCEE427FA7208DF3C1F2A749BA6F4D4", s.receivedPairingData.TrustNonce)
	assert.Equal(s.T(), "hmacSha256", s.receivedPairingData.Alg)
	assert.Equal(s.T(), "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25", s.receivedPairingData.Digest)
}

func (s *PairingProcessorSuite) Test_processPairingEntry_MissingMandatoryField() {
	// Missing txtvers (mandatory field)
	elements := map[string]string{
		"partype": "fpSha256",
		"forid":   "target-device-id",
		"trustid": "source-device-id",
	}

	remove := false

	// Register callback
	s.sut.RegisterPairingCallback(s.pairingCallback)

	// Process the pairing entry
	s.sut.processShipPairingMdnsEntry(elements, "servicename", remove)

	// Verify callback was NOT called due to missing mandatory field
	assert.Nil(s.T(), s.receivedPairingData)
}

func (s *PairingProcessorSuite) Test_processPairingEntry_InvalidTxtVers() {
	// Invalid txtvers value (must be "1")
	elements := map[string]string{
		"txtvers": "2",
		"partype": "fpSha256",
		"forid":   "target-device-id",
		"trustid": "source-device-id",
	}

	remove := false

	// Register callback
	s.sut.RegisterPairingCallback(s.pairingCallback)

	// Process the pairing entry
	s.sut.processShipPairingMdnsEntry(elements, "servicename", remove)

	// Verify callback was NOT called due to invalid txtvers
	assert.Nil(s.T(), s.receivedPairingData)
}

func (s *PairingProcessorSuite) Test_processPairingEntry_NoCallback() {
	// Valid pairing data but no callback registered
	elements := map[string]string{
		"txtvers": "1",
		"partype": "fpSha256",
		"forid":   "target-device-id",
		"trustid": "source-device-id",
	}

	remove := false

	// Don't register callback

	// Process the pairing entry - should not panic
	s.sut.processShipPairingMdnsEntry(elements, "servicename", remove)

	// No callback to verify, just ensure no panic
	assert.Nil(s.T(), s.receivedPairingData)
}

func (s *PairingProcessorSuite) Test_processPairingEntry_RemoveEntry() {
	// Test removal of pairing entry
	elements := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "target-device-id",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "source-device-id",
		"trustpar":   "5D41CB9A91494591C5ED24F7FE764E05F7381EE277F2F783841087621CD606D5",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	remove := true // Set remove flag

	// Register callback
	s.sut.RegisterPairingCallback(s.pairingCallback)

	// First add an entry so we can remove it
	s.sut.processShipPairingMdnsEntry(elements, "servicename", false) // Add the entry first
	assert.NotNil(s.T(), s.receivedPairingData)                       // Should be called for addition

	// Reset tracking
	s.receivedPairingData = nil

	// Process the pairing entry with remove flag
	s.sut.processShipPairingMdnsEntry(elements, "servicename", remove)

	// For removals, callback should be NOT called (new behavior)
	assert.Nil(s.T(), s.receivedPairingData)
}

func (s *PairingProcessorSuite) Test_processPairingEntry_RemoveWithoutTxtElements() {
	// mDNS remove events frequently carry no TXT data: avahi only echoes
	// elements it stored at add time (lookup can miss across interfaces or
	// daemon restarts) and zeroconf reports incomplete records. A remove is
	// identified by its service instance name alone — it must clear the
	// cached entry even when the TXT elements are absent, otherwise the
	// withdrawn request is replayed to the listener on the next reactivation.
	elements := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "target-device-id",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "sps-test-2",
		"trustpar":   "78C29464504DCF78E79E9D4F0B9C542A311C99EEE782E27C05ABF9B9A8BD15FE",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	s.sut.processShipPairingMdnsEntry(elements, "servicename", false)
	_, exists := s.sut.pairingMdnsEntry("servicename")
	s.Require().True(exists, "Entry should be cached after add")

	// Remove arrives without TXT data
	s.sut.processShipPairingMdnsEntry(map[string]string{}, "servicename", true)

	_, exists = s.sut.pairingMdnsEntry("servicename")
	assert.False(s.T(), exists,
		"A remove event must clear the cached entry even without TXT elements")
}

func (s *PairingProcessorSuite) Test_RegisterPairingCallback() {
	// Test callback registration
	callbackCalled := false
	callback := func(data *api.ShipPairingTXT) bool {
		callbackCalled = true
		return true
	}

	// Register callback
	s.sut.RegisterPairingCallback(callback)

	// Process valid pairing entry
	elements := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "target-device-id",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "source-device-id",
		"trustpar":   "5D41CB9A91494591C5ED24F7FE764E05F7381EE277F2F783841087621CD606D5",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	s.sut.processShipPairingMdnsEntry(elements, "servicename", false)

	// Verify callback was called
	assert.True(s.T(), callbackCalled)
}

func (s *PairingProcessorSuite) Test_UnregisterPairingCallback() {
	// Test callback unregistration
	callbackCalled := false
	callback := func(data *api.ShipPairingTXT) bool {
		callbackCalled = true
		return true
	}

	// Register then unregister callback
	s.sut.RegisterPairingCallback(callback)
	s.sut.UnregisterPairingCallback()

	// Process valid pairing entry
	elements := map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "target-device-id",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "source-device-id",
		"trustpar":   "5D41CB9A91494591C5ED24F7FE764E05F7381EE277F2F783841087621CD606D5",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}

	s.sut.processShipPairingMdnsEntry(elements, "servicename", false)

	// Verify callback was NOT called after unregistration
	assert.False(s.T(), callbackCalled)
}

/* Re-report and eviction semantics */

// validPairingElements returns a complete, valid TXT element set for tests
// that exercise cache semantics rather than field validation.
func validPairingElements() map[string]string {
	return map[string]string{
		"txtvers":    "1",
		"partype":    "fpSha256",
		"forid":      "target-device-id",
		"forpar":     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		"trustid":    "source-device-id",
		"trustpar":   "source-device-par",
		"trustcurve": "secp256r1",
		"type":       "addCu",
		"trustnonce": "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		"alg":        "hmacSha256",
		"digest":     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}
}

func (s *PairingProcessorSuite) Test_processPairingEntry_SameNameChangedContent_ReDelivers() {
	// Pairing spec §4.2 devA rule 2 note / §5.5 option 2: devZ may correct a
	// request by reusing the same service instance name (e.g. after a missed
	// goodbye). Changed content must be re-delivered, not treated as a
	// TTL refresh.
	callbackCount := 0
	s.sut.RegisterPairingCallback(func(data *api.ShipPairingTXT) bool {
		callbackCount++
		s.receivedPairingData = data
		return true
	})

	s.sut.processShipPairingMdnsEntry(validPairingElements(), "corrected-service", false)
	assert.Equal(s.T(), 1, callbackCount)

	corrected := validPairingElements()
	corrected["trustnonce"] = "0102030405060708090A0B0C0D0E0F10"
	corrected["digest"] = "AAAA62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25"
	s.sut.processShipPairingMdnsEntry(corrected, "corrected-service", false)

	assert.Equal(s.T(), 2, callbackCount, "changed content under a known instance name must be re-delivered")
	assert.Equal(s.T(), corrected["digest"], s.receivedPairingData.Digest)

	cached, exists := s.sut.pairingMdnsEntry("corrected-service")
	assert.True(s.T(), exists)
	assert.Equal(s.T(), corrected["digest"], cached.Digest, "cache must hold the corrected content")
}

func (s *PairingProcessorSuite) Test_processPairingEntry_SameNameIdenticalContent_Suppressed() {
	// A byte-identical re-report is TTL-refresh noise and must not be
	// re-delivered to the callback.
	callbackCount := 0
	s.sut.RegisterPairingCallback(func(data *api.ShipPairingTXT) bool {
		callbackCount++
		return true
	})

	s.sut.processShipPairingMdnsEntry(validPairingElements(), "refresh-service", false)
	s.sut.processShipPairingMdnsEntry(validPairingElements(), "refresh-service", false)

	assert.Equal(s.T(), 1, callbackCount, "identical re-report must stay suppressed")
}

func (s *PairingProcessorSuite) Test_processPairingEntry_RemoveEvictsOnlyMatchingEntry() {
	// A goodbye is identified by the service instance name alone and must
	// evict exactly that entry, leaving other live records untouched.
	s.sut.RegisterPairingCallback(func(data *api.ShipPairingTXT) bool { return true })

	s.sut.processShipPairingMdnsEntry(validPairingElements(), "device-x", false)
	s.sut.processShipPairingMdnsEntry(validPairingElements(), "device-y", false)

	// Goodbye events often carry no TXT data
	s.sut.processShipPairingMdnsEntry(map[string]string{}, "device-x", true)

	_, existsX := s.sut.pairingMdnsEntry("device-x")
	_, existsY := s.sut.pairingMdnsEntry("device-y")
	assert.False(s.T(), existsX, "removed entry must be evicted")
	assert.True(s.T(), existsY, "unrelated live entry must survive the removal")
}
