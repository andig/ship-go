package hub

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// S10 — retiring an outgoing dial is decided during the TLS handshake of the incoming
// connection, before that connection has proven it can get any further. If it never
// does, the SKI is left with nothing connected, so the dial has to report a failure
// rather than a success — otherwise the retry path never picks the SKI back up and
// recovery waits for the next mDNS update.
//
// The peer here completes a TLS handshake with the DUT and then drops it, which is what
// any of the ServeHTTP rejection paths look like from the outside.
func TestDoubleConn_SupersededDialFailsIfIncomingNeverEstablishes(t *testing.T) {
	log := newDcEventLog()
	dutCert, toolCert := certsBySkiOrder(t) // DUT = larger SKI, so it retires its own dial

	tool := newTestTool(t, log, toolCert, policyPassive)
	dut := newDUT(t, dutCert)
	peer := dut.trust(t, tool.ski)

	// stall connection A before its websocket upgrade so it is still an in-flight dial
	release := tool.holdInbound()
	defer release()

	host, port := tool.address()
	dialDone := dut.dial(peer, host, port)
	log.waitFor(t, evAAccepted, 5*time.Second)

	require.NoError(t, tool.tlsProbeDUT(dut.port),
		"the TLS handshake must complete, that is what triggers the check\n%s", log.dump())

	release()

	select {
	case err := <-dialDone:
		assert.Error(t, err,
			"a dial retired for an incoming connection that never established must be "+
				"reported as failed, so the SKI is retried\n%s", log.dump())
	case <-time.After(10 * time.Second):
		t.Fatalf("the outgoing dial never returned\n%s", log.dump())
	}

	assert.Zero(t, dut.connectionCount(),
		"neither connection survives this scenario\n%s", log.dump())
}
