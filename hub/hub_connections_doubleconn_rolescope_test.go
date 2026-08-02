package hub

import (
	"testing"
	"time"

	"github.com/enbility/ship-go/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// S8 — role polymorphism (TC_SHIP_ROLE_003, SHIP-TS-ROLE-01, mandatory).
//
// Two distinct peers with distinct SKIs connect at the same time, one inbound and one
// outbound. Both connections must survive: double-connection handling is per-SKI and
// must never touch a connection to a different peer. Passes today; it exists so that a
// handshake-time duplicate check added for #96 cannot regress it by keying on anything
// coarser than the SKI.
func TestDoubleConn_DistinctPeersBothSurvive(t *testing.T) {
	logOut := newDcEventLog()
	logIn := newDcEventLog()

	dutCert, peerOutCert := certsBySkiOrder(t)
	peerInCert, err := cert.CreateCertificate("unit", "org", "DE", "peer-in")
	require.NoError(t, err)

	dut := newDUT(t, dutCert)

	// peer 1: the DUT dials it (DUT is SHIP client)
	peerOut := newTestTool(t, logOut, peerOutCert, policyPassive)
	serviceOut := dut.trust(t, peerOut.ski)

	// peer 2: dials the DUT (DUT is SHIP server)
	peerIn := newTestTool(t, logIn, peerInCert, policyPassive)
	dut.trust(t, peerIn.ski)

	host, port := peerOut.address()
	dialDone := dut.dial(serviceOut, host, port)

	connIn, err := peerIn.dialDUT(dut.port, 0)
	require.NoError(t, err, "the inbound peer must be accepted\n%s", logIn.dump())
	require.NoError(t, peerIn.sendCMI(connIn))

	require.NoError(t, <-dialDone, "the outbound connection must be established\n%s", logOut.dump())
	logOut.waitFor(t, evACmiRx, 5*time.Second)
	logIn.waitFor(t, evBCmiRx, 5*time.Second)

	logOut.settle(500 * time.Millisecond)

	assert.False(t, logOut.has(evAClosed),
		"the outbound connection to a different SKI must not be closed\n%s", logOut.dump())
	assert.False(t, logIn.has(evBClosed),
		"the inbound connection from a different SKI must not be closed\n%s", logIn.dump())
	assert.Equal(t, 2, dut.connectionCount(),
		"both peers must stay connected\noutbound %s\ninbound %s", logOut.dump(), logIn.dump())
}
