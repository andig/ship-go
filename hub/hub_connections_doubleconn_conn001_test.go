package hub

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TC_SHIP_CONN_001 (SHIP TestSpecification V1.0.0 §4.2.1, requirement SHIP-TS-CONN-01,
// SHIP TS §12.2.2), DUT roles: server & client, status: mandatory.
//
// Preconditions modelled here:
//   - PRE_SHIP_ServerPort            → the DUT runs a real websocket server
//   - PRE_SHIP_TestTool_Smaller_SKI  → certsBySkiOrder gives the DUT the larger SKI
//   - PRE_SHIP_Mutual_Trust          → dut.trust()
//   - PRE_SHIP_TestTool_ServerAndClient → the scripted peer serves and dials
//
// Step 1: the peer waits for the DUT to initiate connection A.
// Step 2: as soon as the peer receives the incoming TCP stream for A, it immediately
//         establishes connection B with the exact same certificate.
// Expected: the DUT keeps B, continues the SME phases on it, and actively closes A.

// S1 — the ordering the test spec describes: B arrives while A is still an in-flight
// dial on the DUT. A's TLS handshake is held at the peer's accept so the in-flight
// window is deterministic rather than a race.
func TestDoubleConn_TC_SHIP_CONN_001_IncomingDuringInflightDial(t *testing.T) {
	log := newDcEventLog()
	dutCert, toolCert := certsBySkiOrder(t) // DUT = larger SKI

	tool := newTestTool(t, log, toolCert, policyPassive)
	dut := newDUT(t, dutCert)
	peer := dut.trust(t, tool.ski)

	// stall connection A before its websocket upgrade, so it is still an unfinished
	// dial on the DUT when B arrives
	release := tool.holdInbound()

	host, port := tool.address()
	dialDone := dut.dial(peer, host, port)

	// step 1
	log.waitFor(t, evAAccepted, 5*time.Second)

	// step 2 — same certificate, immediately
	connB, err := tool.dialDUT(dut.port, 0)
	require.NoError(t, err, "connection B must be accepted\n%s", log.dump())
	log.waitFor(t, evBUpgraded, 5*time.Second)
	require.NoError(t, tool.sendCMI(connB))

	// let A finish whatever it is going to do
	release()
	<-dialDone
	log.settle(750 * time.Millisecond)

	assert.True(t, log.has(evAClosed),
		"SHIP 12.2.2: the DUT (larger SKI) must actively close the older connection A\n%s", log.dump())
	assert.False(t, log.has(evBClosed),
		"the most recent connection B must be kept open\n%s", log.dump())
	assert.True(t, log.has(evBCmiRx),
		"the DUT must reply to CMI on connection B\n%s", log.dump())
	assert.True(t, log.has(evBHelloRx),
		"the DUT must continue the SME phases on connection B; per TC_SHIP_ROLE_001 the SME "+
			"\"hello\" message is what shows the CMI phase completed\n%s", log.dump())
	assert.Equal(t, 1, dut.connectionCount(),
		"exactly one connection must remain registered\n%s", log.dump())

	t.Log(log.dump())
}

// S2 — the ordering described in the ticket: A is fully established (SME already
// running) when B arrives. Fails through a different code path than S1: rejection in
// ServeHTTP rather than teardown by the late-completing dial.
func TestDoubleConn_TC_SHIP_CONN_001_IncomingAfterEstablished(t *testing.T) {
	log := newDcEventLog()
	dutCert, toolCert := certsBySkiOrder(t) // DUT = larger SKI

	tool := newTestTool(t, log, toolCert, policyPassive)
	dut := newDUT(t, dutCert)
	peer := dut.trust(t, tool.ski)

	host, port := tool.address()
	dialDone := dut.dial(peer, host, port)
	require.NoError(t, <-dialDone, "connection A must be established\n%s", log.dump())

	// the DUT is SHIP client on A, so it sends CMI unprompted — proof A is live
	log.waitFor(t, evACmiRx, 5*time.Second)

	connB, err := tool.dialDUT(dut.port, 0)
	require.NoError(t, err, "connection B must be accepted\n%s", log.dump())
	log.waitFor(t, evBUpgraded, 5*time.Second)
	require.NoError(t, tool.sendCMI(connB))

	log.settle(750 * time.Millisecond)

	assert.True(t, log.has(evAClosed),
		"SHIP 12.2.2: the DUT (larger SKI) must actively close the older connection A\n%s", log.dump())
	assert.False(t, log.has(evBClosed),
		"the most recent connection B must be kept open\n%s", log.dump())
	assert.True(t, log.has(evBCmiRx),
		"the DUT must reply to CMI on connection B\n%s", log.dump())
	assert.True(t, log.has(evBHelloRx),
		"the DUT must continue the SME phases on connection B; per TC_SHIP_ROLE_001 the SME "+
			"\"hello\" message is what shows the CMI phase completed\n%s", log.dump())
	assert.Equal(t, 1, dut.connectionCount(),
		"exactly one connection must remain registered\n%s", log.dump())
}

// S3 — the deadline. TC_SHIP_CONN_001 expects A closed "within 30s (latest before the
// TLS handshake of connection B completes)". B's handshake is stretched so the
// ordering assertion is deterministic; satisfying it requires the double-connection
// check to run inside the TLS handshake (SHIP 12.2.2: "The SHIP node with the greater
// SKI SHOULD check for double connections directly during the TLS handshake").
func TestDoubleConn_TC_SHIP_CONN_001_ClosesBeforeHandshakeCompletes(t *testing.T) {
	// A test instrument, not a figure from the spec and not what a certification tool
	// does. Under TLS 1.2 the ordering is already guaranteed by the flight structure —
	// the server processes the client certificate before sending its own Finished — and
	// measured undelayed on loopback the DUT closes A 260µs to 1.7ms before B's
	// handshake completes. Stretching B's handshake only widens that gap so the test
	// stays a decisive detector: a regression that moved the close out of
	// verifyPeerCertificate and into ServeHTTP would otherwise fail by about a
	// millisecond, which is the same order as scheduling noise on a loaded machine.
	const handshakeDelay = 300 * time.Millisecond

	log := newDcEventLog()
	dutCert, toolCert := certsBySkiOrder(t) // DUT = larger SKI

	tool := newTestTool(t, log, toolCert, policyPassive)
	dut := newDUT(t, dutCert)
	peer := dut.trust(t, tool.ski)

	release := tool.holdInbound()
	defer release()

	host, port := tool.address()
	dialDone := dut.dial(peer, host, port)
	log.waitFor(t, evAAccepted, 5*time.Second)

	connB, err := tool.dialDUT(dut.port, handshakeDelay)
	require.NoError(t, err, "connection B must be accepted\n%s", log.dump())
	require.NoError(t, tool.sendCMI(connB))

	closedA, ok := log.first(evAClosed)
	require.True(t, ok,
		"the DUT must have closed connection A before B's TLS handshake completed\n%s", log.dump())

	handshakeB, ok := log.first(evBTLSDone)
	require.True(t, ok, "connection B's TLS handshake must complete\n%s", log.dump())

	assert.True(t, closedA.at.Before(handshakeB.at),
		"A was closed %s after B's TLS handshake completed; TC_SHIP_CONN_001 requires it before\n%s",
		handshakeB.at.Sub(closedA.at), log.dump())
	t.Logf("A closed %s before B's TLS handshake completed\n%s",
		handshakeB.at.Sub(closedA.at), log.dump())

	release()
	<-dialDone
}

// S5 — replacing a connection must not report the peer as disconnected. The
// application layer keys devices by SKI, so a disconnect callback fired while
// another connection for that SKI is live tears down the surviving connection's
// device (hub_shipconnection.go HandleConnectionClosed).
func TestDoubleConn_ReplacementDoesNotReportDisconnect(t *testing.T) {
	log := newDcEventLog()
	dutCert, toolCert := certsBySkiOrder(t) // DUT = larger SKI

	tool := newTestTool(t, log, toolCert, policyPassive)
	dut := newDUT(t, dutCert)
	peer := dut.trust(t, tool.ski)

	// the in-flight shape, because that is the one where the DUT actually replaces a
	// registered connection rather than rejecting the new one outright
	release := tool.holdInbound()

	host, port := tool.address()
	dialDone := dut.dial(peer, host, port)
	log.waitFor(t, evAAccepted, 5*time.Second)

	connB, err := tool.dialDUT(dut.port, 0)
	require.NoError(t, err)
	log.waitFor(t, evBUpgraded, 5*time.Second)
	require.NoError(t, tool.sendCMI(connB))

	release()
	<-dialDone
	log.settle(750 * time.Millisecond)

	require.Positive(t, dut.connectionCount(),
		"a connection to the peer must remain registered\n%s", log.dump())
	assert.Zero(t, dut.disconnect.count(tool.ski),
		"RemoteServiceDisconnected must not fire while a connection for that SKI is registered\n%s",
		log.dump())
}
