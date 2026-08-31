package hub

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/mocks"
	"github.com/enbility/ship-go/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// S6 — SHIP 12.2.2: "If an older connection is already in the SME 'connection data
// exchange' state, the SHIP node with the bigger SKI value SHOULD initiate a connection
// termination as described in section 13.4.7." That means the close announce, not a
// socket-level close.
//
// Driving a scripted peer all the way to SmeStateComplete would mean implementing the
// full SME handshake, so this is pinned at the seam instead: what does the registry ask
// the superseded connection to do?
//
// Reason per SHIP 13.4.7.1.1: "unspecific" — a temporary disconnection where a
// reconnect is expected. "removedConnection" means the peer was dropped from the known
// devices list, which is not the case here.
func TestDoubleConn_SupersededConnectionInDataExchangeIsAnnounced(t *testing.T) {
	hub := setupTestHubForTimer(t)
	hub.localService, _ = api.NewServiceDetails("ffffffffffffffffffffffffffffffffffffffff", "", "")

	remoteService, err := api.NewServiceDetails("00000000000000000000000000000000000000ff", "", "")
	require.NoError(t, err)

	var (
		mux    sync.Mutex
		calls  int
		safe   bool
		code   int
		reason string
	)

	existing := mocks.NewShipConnectionInterface(t)
	existing.EXPECT().RemoteSKI().Return(remoteService.SKI()).Maybe()
	existing.EXPECT().ShipHandshakeState().Return(model.SmeStateComplete, nil).Maybe()
	existing.EXPECT().CloseConnection(mock.Anything, mock.Anything, mock.Anything).
		Run(func(s bool, c int, r string) {
			mux.Lock()
			defer mux.Unlock()
			calls++
			safe, code, reason = s, c, r
		}).Maybe()

	hub.muxCon.Lock()
	hub.connections[remoteService.SKI()] = existing
	hub.muxCon.Unlock()

	require.Equal(t, dcAdopt, hub.doubleConnectionAction(remoteService.SKI()),
		"the larger-SKI node keeps the most recent connection")

	// registering the more recent connection displaces the one in data exchange
	replacement := mocks.NewShipConnectionInterface(t)
	replacement.EXPECT().RemoteSKI().Return(remoteService.SKI()).Maybe()
	replacement.EXPECT().CloseConnection(mock.Anything, mock.Anything, mock.Anything).Maybe()
	hub.registerConnection(replacement)

	require.Eventually(t, func() bool {
		mux.Lock()
		defer mux.Unlock()
		return calls > 0
	}, 2*time.Second, 10*time.Millisecond, "the superseded connection must be closed")

	mux.Lock()
	defer mux.Unlock()
	assert.True(t, safe,
		"SHIP 13.4.7: a connection in data exchange must be closed with a termination announce")
	assert.Equal(t, string(model.ConnectionCloseReasonTypeUnspecific), reason,
		"SHIP 13.4.7.1.1: the reason for a double connection is 'unspecific'")
	assert.Zero(t, code, "the announce path picks its own close code")
}

// A peer that negotiates TLS 1.3 still gets its double connection resolved, but not
// within TC_SHIP_CONN_001's tight bound — and this test documents exactly that split.
//
// The reason is TLS message ordering, not an implementation detail. In TLS 1.2 the
// server processes the client certificate in flight 3 and only then sends its own
// Finished, so verifyPeerCertificate runs before the client's handshake completes. In
// TLS 1.3 client authentication moved after the server's Finished: the client is done
// as soon as it has sent its own Certificate/Finished, and the server processes that
// certificate afterwards. A server therefore cannot learn who the peer is before the
// peer considers its handshake complete.
//
// ship-go does not pin MaxVersion, so this is the behaviour against any peer that
// offers TLS 1.3. The certification tool offers TLS 1.2 (SHIP 9 makes it mandatory),
// where TestDoubleConn_TC_SHIP_CONN_001_ClosesBeforeHandshakeCompletes applies instead.
func TestDoubleConn_TLS13PeerResolvesLateButCorrectly(t *testing.T) {
	log := newDcEventLog()
	dutCert, toolCert := certsBySkiOrder(t) // DUT = larger SKI

	tool := newTestTool(t, log, toolCert, policyPassive)
	tool.clientMaxTLSVersion = tls.VersionTLS13
	dut := newDUT(t, dutCert)
	peer := dut.trust(t, tool.ski)

	release := tool.holdInbound()

	host, port := tool.address()
	dialDone := dut.dial(peer, host, port)
	log.waitFor(t, evAAccepted, 5*time.Second)

	connB, err := tool.dialDUT(dut.port, 0)
	require.NoError(t, err, "connection B must be accepted\n%s", log.dump())
	log.waitFor(t, evBUpgraded, 5*time.Second)
	require.NoError(t, tool.sendCMI(connB))

	release()
	<-dialDone
	log.settle(750 * time.Millisecond)

	// the outcome is still correct: the older connection goes, the most recent stays
	assert.True(t, log.has(evAClosed),
		"the older connection must still be closed\n%s", log.dump())
	assert.False(t, log.has(evBClosed),
		"the most recent connection must be kept\n%s", log.dump())
	assert.Equal(t, 1, dut.connectionCount(),
		"exactly one connection must remain registered\n%s", log.dump())

	// ...but the tight bound cannot hold, because the DUT only learns the peer identity
	// after the peer's handshake has completed
	closedA, _ := log.first(evAClosed)
	handshakeB, ok := log.first(evBTLSDone)
	require.True(t, ok)
	t.Logf("TLS 1.3: A closed %s relative to B's handshake completion (negative = after)\n%s",
		handshakeB.at.Sub(closedA.at), log.dump())
}
