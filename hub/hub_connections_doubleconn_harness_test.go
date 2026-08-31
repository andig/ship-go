// SHIP double-connection compliance scenarios — see enbility/ship-go#96.
//
// These tests drive a real Hub over real TLS sockets against a scripted SHIP peer, so
// the double-connection behaviour of SHIP 12.2.2 is observed the way the certification
// test tool observes it: which socket died, with which close code, and in which order
// relative to the TLS handshake.
//
//	go test -race -count=1 -run TestDoubleConn_ ./hub/
//
// TLS version note: SHIP 1.0.1 §9 makes TLS 1.2 mandatory, and TC_SHIP_CONN_001's
// deadline depends on it. Under TLS 1.3 the client considers the handshake complete
// before the server has processed the client certificate, so a server cannot close an
// older connection "before the TLS handshake of connection B completes". The scripted
// peer pins MaxVersion to TLS 1.2, matching the certification environment; ship-go
// itself does not pin it, so against a TLS 1.3 capable peer only the 30s bound holds.
package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/cert"
	"github.com/enbility/ship-go/mocks"
	"github.com/enbility/ship-go/model"
	"github.com/enbility/ship-go/util"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// event log
// ---------------------------------------------------------------------------

type dcEventKind string

const (
	// connection A: the DUT dials the peer (DUT is SHIP client)
	evAAccepted   dcEventKind = "A_TCP_ACCEPTED"
	evATLSDone    dcEventKind = "A_TLS_DONE"
	evAUpgraded   dcEventKind = "A_WS_UPGRADED"
	evACmiRx      dcEventKind = "A_CMI_RX"
	evAMessageRx  dcEventKind = "A_MESSAGE_RX"
	evAClosed     dcEventKind = "A_CLOSED"
	evACloseAnnce dcEventKind = "A_CLOSE_ANNOUNCE_RX"

	// connection B: the peer dials the DUT (DUT is SHIP server)
	evBTLSDone    dcEventKind = "B_TLS_DONE"
	evBUpgraded   dcEventKind = "B_WS_UPGRADED"
	evBCmiRx      dcEventKind = "B_CMI_RX"
	evBHelloRx    dcEventKind = "B_HELLO_RX"
	evBMessageRx  dcEventKind = "B_MESSAGE_RX"
	evBClosed     dcEventKind = "B_CLOSED"
	evBCloseAnnce dcEventKind = "B_CLOSE_ANNOUNCE_RX"
)

type dcEvent struct {
	kind   dcEventKind
	at     time.Time
	detail string
}

type dcEventLog struct {
	mux    sync.Mutex
	events []dcEvent
	start  time.Time
}

func newDcEventLog() *dcEventLog {
	return &dcEventLog{start: time.Now()}
}

func (l *dcEventLog) emit(kind dcEventKind, detail string) {
	l.mux.Lock()
	defer l.mux.Unlock()
	l.events = append(l.events, dcEvent{kind: kind, at: time.Now(), detail: detail})
}

func (l *dcEventLog) first(kind dcEventKind) (dcEvent, bool) {
	l.mux.Lock()
	defer l.mux.Unlock()
	for _, e := range l.events {
		if e.kind == kind {
			return e, true
		}
	}
	return dcEvent{}, false
}

func (l *dcEventLog) has(kind dcEventKind) bool {
	_, ok := l.first(kind)
	return ok
}

// waitFor blocks until the event was emitted or the timeout expires.
func (l *dcEventLog) waitFor(t *testing.T, kind dcEventKind, timeout time.Duration) dcEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if e, ok := l.first(kind); ok {
			return e
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s\n%s", timeout, kind, l.dump())
	return dcEvent{}
}

// settle gives the stack time to act, then returns. Used where the assertion is
// about something NOT happening, so there is nothing to wait for.
func (l *dcEventLog) settle(d time.Duration) { time.Sleep(d) }

func (l *dcEventLog) dump() string {
	l.mux.Lock()
	defer l.mux.Unlock()
	out := "event log:\n"
	for _, e := range l.events {
		out += fmt.Sprintf("  %8.1fms  %-22s %s\n",
			float64(e.at.Sub(l.start).Microseconds())/1000.0, e.kind, e.detail)
	}
	if len(l.events) == 0 {
		out += "  (empty)\n"
	}
	return out
}

// ---------------------------------------------------------------------------
// certificates / SKI ordering
// ---------------------------------------------------------------------------

func skiOfCertificate(t *testing.T, c tls.Certificate) string {
	t.Helper()
	parsed, err := x509.ParseCertificate(c.Certificate[0])
	require.NoError(t, err)
	ski, err := cert.SkiFromCertificate(parsed)
	require.NoError(t, err)
	return util.NormalizeSKI(ski)
}

// certsBySkiOrder returns two SHIP certificates ordered by their SKI value.
// This is the deterministic version of PRE_SHIP_TestTool_Smaller_SKI ("repeated
// generation of key pairs until a public key with this property is found").
func certsBySkiOrder(t *testing.T) (higher tls.Certificate, lower tls.Certificate) {
	t.Helper()
	c1, err := cert.CreateCertificate("unit", "org", "DE", "dut")
	require.NoError(t, err)
	c2, err := cert.CreateCertificate("unit", "org", "DE", "tool")
	require.NoError(t, err)

	if skiOfCertificate(t, c1) > skiOfCertificate(t, c2) {
		return c1, c2
	}
	return c2, c1
}

// ---------------------------------------------------------------------------
// net helpers
// ---------------------------------------------------------------------------

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// delayConn slows down reads while enabled. Applied to the peer's outgoing TLS
// connection it widens the window between "the DUT has seen our client certificate"
// and "our TLS handshake completed", which is what TC_SHIP_CONN_001's deadline is
// measured against. Without it the two events are microseconds apart and the
// assertion would be a coin flip.
type delayConn struct {
	net.Conn
	delay   time.Duration
	enabled atomic.Bool
}

func (d *delayConn) Read(b []byte) (int, error) {
	if d.enabled.Load() && d.delay > 0 {
		time.Sleep(d.delay)
	}
	return d.Conn.Read(b)
}

// notifyListener reports every accepted TCP connection before any TLS handshake runs.
// That is the trigger point TC_SHIP_CONN_001 uses: "as soon as the test tool receives
// the incoming TCP stream for connection A".
type notifyListener struct {
	net.Listener
	onAccept func()
	onClose  func(detail string)
}

func (l *notifyListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.onAccept != nil {
		l.onAccept()
	}
	return &closeWatchConn{Conn: conn, onClose: l.onClose}, nil
}

// closeWatchConn reports the moment the peer's socket dies, at TCP level. This is
// how a connection that never finished its TLS handshake — an in-flight outgoing
// dial aborted by the DUT — becomes observable.
type closeWatchConn struct {
	net.Conn
	onClose func(detail string)
	once    sync.Once
}

func (c *closeWatchConn) report(detail string) {
	if c.onClose == nil {
		return
	}
	c.once.Do(func() { c.onClose(detail) })
}

func (c *closeWatchConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		// net/http arms a read deadline for its background read and cancels it on
		// hijack, so a timeout here is routine and must not be read as a close.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return n, err
		}
		c.report("tcp: " + err.Error())
	}
	return n, err
}

func (c *closeWatchConn) Close() error {
	c.report("tcp: closed locally")
	return c.Conn.Close()
}

// ---------------------------------------------------------------------------
// scripted SHIP peer ("test tool")
// ---------------------------------------------------------------------------

// arbiterPolicy describes how the scripted peer resolves a double connection.
type arbiterPolicy int

const (
	// policyPassive: never close anything on its own (default; the peer is the
	// smaller-SKI node in TC_SHIP_CONN_001 and must let the DUT decide).
	policyPassive arbiterPolicy = iota
	// policyKeepMostRecent: SHIP 12.2.2 arbiter behaviour — used when the peer is
	// the larger-SKI node, to model a spec-compliant remote.
	policyKeepMostRecent
)

type toolConn struct {
	ws     *websocket.Conn
	label  string // "A" or "B"
	opened time.Time
}

// testTool is a scripted SHIP peer: a TLS/WebSocket server the DUT can dial
// (connection A) plus a client that can dial the DUT (connection B). It speaks
// just enough SHIP to make the SME phases observable.
type testTool struct {
	t      *testing.T
	log    *dcEventLog
	cert   tls.Certificate
	ski    string
	policy arbiterPolicy

	listener *notifyListener
	server   *http.Server
	port     int

	// gate held before the websocket upgrade of an inbound connection
	inboundGate atomic.Pointer[chan struct{}]

	// highest TLS version this peer offers when dialling the DUT. SHIP 9 makes TLS 1.2
	// mandatory and the certification tool uses it; raising this to 1.3 models a peer
	// that offers more, which changes when the DUT can observe the peer identity.
	clientMaxTLSVersion uint16

	mux   sync.Mutex
	conns []*toolConn
}

func newTestTool(t *testing.T, log *dcEventLog, certificate tls.Certificate, policy arbiterPolicy) *testTool {
	t.Helper()
	tool := &testTool{
		t:                   t,
		log:                 log,
		cert:                certificate,
		ski:                 skiOfCertificate(t, certificate),
		policy:              policy,
		clientMaxTLSVersion: tls.VersionTLS12, // SHIP 9: TLS 1.2 is mandatory
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tool.port = raw.Addr().(*net.TCPAddr).Port
	tool.listener = &notifyListener{
		Listener: raw,
		onAccept: func() { log.emit(evAAccepted, "") },
		onClose:  func(detail string) { log.emit(evAClosed, detail) },
	}

	tool.server = &http.Server{
		Handler:           http.HandlerFunc(tool.serveInbound),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tool.tlsServerConfig(),
	}
	go func() {
		_ = tool.server.ServeTLS(tool.listener, "", "")
	}()

	t.Cleanup(tool.shutdown)
	return tool
}

// holdInbound stalls inbound connections just before the websocket upgrade, leaving the
// DUT's outgoing dial unfinished so the in-flight window is deterministic.
//
// The gate sits in the handler rather than at accept time on purpose: net/http runs a
// background read on the connection while a handler is active, so a close by the DUT is
// observed the moment it happens. Gating at accept leaves nobody reading the socket, and
// the close would only surface later — with a timestamp too late to assert against.
func (tt *testTool) holdInbound() (release func()) {
	gate := make(chan struct{})
	tt.inboundGate.Store(&gate)
	var once sync.Once
	return func() {
		once.Do(func() {
			tt.inboundGate.Store(nil)
			close(gate)
		})
	}
}

func (tt *testTool) tlsServerConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{tt.cert},
		ClientAuth:   tls.RequireAnyClientCert,
		CipherSuites: cert.CipherSuites,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // SHIP 9: TLS 1.2 is mandatory
	}
}

func (tt *testTool) tlsClientConfig() *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{tt.cert},
		InsecureSkipVerify: true, // #nosec G402 // SHIP 12.1: certificates are locally signed
		CipherSuites:       cert.CipherSuites,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tt.clientMaxTLSVersion,
	}
}

func (tt *testTool) address() (host string, port string) {
	return "127.0.0.1", strconv.Itoa(tt.port)
}

func (tt *testTool) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tt.server.Shutdown(ctx)

	tt.mux.Lock()
	conns := append([]*toolConn(nil), tt.conns...)
	tt.mux.Unlock()
	for _, c := range conns {
		_ = c.ws.Close()
	}
}

func (tt *testTool) track(c *toolConn) {
	tt.mux.Lock()
	tt.conns = append(tt.conns, c)
	others := len(tt.conns)
	tt.mux.Unlock()

	if others > 1 && tt.policy == policyKeepMostRecent {
		tt.closeAllButMostRecent()
	}
}

func (tt *testTool) untrack(c *toolConn) {
	tt.mux.Lock()
	defer tt.mux.Unlock()
	for i, existing := range tt.conns {
		if existing == c {
			tt.conns = append(tt.conns[:i], tt.conns[i+1:]...)
			return
		}
	}
}

// closeAllButMostRecent models the SHIP 12.2.2 obligation of the larger-SKI node.
func (tt *testTool) closeAllButMostRecent() {
	tt.mux.Lock()
	if len(tt.conns) < 2 {
		tt.mux.Unlock()
		return
	}
	newest := tt.conns[0]
	for _, c := range tt.conns {
		if c.opened.After(newest.opened) {
			newest = c
		}
	}
	var doomed []*toolConn
	for _, c := range tt.conns {
		if c != newest {
			doomed = append(doomed, c)
		}
	}
	tt.conns = []*toolConn{newest}
	tt.mux.Unlock()

	for _, c := range doomed {
		_ = c.ws.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "double connection"),
			time.Now().Add(time.Second))
		_ = c.ws.Close()
	}
}

// liveConnections returns how many connections the peer still holds.
func (tt *testTool) liveConnections() int {
	tt.mux.Lock()
	defer tt.mux.Unlock()
	return len(tt.conns)
}

// serveInbound handles connection A — the DUT dialing the peer.
func (tt *testTool) serveInbound(w http.ResponseWriter, r *http.Request) {
	tt.log.emit(evATLSDone, "")

	if gate := tt.inboundGate.Load(); gate != nil {
		<-*gate
	}

	upgrader := websocket.Upgrader{
		CheckOrigin:  func(r *http.Request) bool { return true },
		Subprotocols: []string{api.ShipWebsocketSubProtocol},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		tt.log.emit(evAClosed, "upgrade failed: "+err.Error())
		return
	}
	tt.log.emit(evAUpgraded, "")

	c := &toolConn{ws: conn, label: "A", opened: time.Now()}
	tt.track(c)
	tt.readLoop(c, evACmiRx, evAMessageRx, evACloseAnnce, evAClosed)
}

// dialDUT opens connection B — the peer dialing the DUT. handshakeDelay stretches
// B's TLS handshake so ordering assertions against it are deterministic.
func (tt *testTool) dialDUT(dutPort int, handshakeDelay time.Duration) (*toolConn, error) {
	var delayed *delayConn

	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		Subprotocols:     []string{api.ShipWebsocketSubProtocol},
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			delayed = &delayConn{Conn: raw, delay: handshakeDelay}
			delayed.enabled.Store(handshakeDelay > 0)

			tlsConn := tls.Client(delayed, tt.tlsClientConfig())
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			// the handshake is complete for us at this exact point — this is the
			// instant TC_SHIP_CONN_001's deadline is measured against
			tt.log.emit(evBTLSDone, "")
			delayed.enabled.Store(false)
			return tlsConn, nil
		},
	}

	u := url.URL{Scheme: "wss", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(dutPort)), Path: "/ship/"}
	conn, resp, err := dialer.Dial(u.String(), nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		tt.log.emit(evBClosed, "dial failed: "+err.Error())
		return nil, err
	}
	tt.log.emit(evBUpgraded, "")

	c := &toolConn{ws: conn, label: "B", opened: time.Now()}
	tt.track(c)
	go tt.readLoop(c, evBCmiRx, evBMessageRx, evBCloseAnnce, evBClosed)
	return c, nil
}

// tlsProbeDUT completes a TLS handshake with the DUT and then drops the connection
// without upgrading it to a websocket. That is enough to make the DUT run
// verifyPeerCertificate - and therefore its double connection check - for a connection
// that never becomes one.
func (tt *testTool) tlsProbeDUT(dutPort int) error {
	raw, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(dutPort)))
	if err != nil {
		return err
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, tt.tlsClientConfig())
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	tt.log.emit(evBTLSDone, "probe")

	return tlsConn.Close()
}

// sendCMI sends the SHIP CMI init message. The DUT is SHIP server on connection B
// and waits for it before replying (ship/hs_init.go: CMI_STATE_SERVER_WAIT).
func (tt *testTool) sendCMI(c *toolConn) error {
	return c.ws.WriteMessage(websocket.BinaryMessage, model.ShipInit)
}

func (tt *testTool) readLoop(c *toolConn, cmiEvent, msgEvent, announceEvent, closedEvent dcEventKind) {
	defer tt.untrack(c)

	for {
		_, msg, err := c.ws.ReadMessage()
		if err != nil {
			tt.log.emit(closedEvent, closeDetail(err))
			return
		}
		if len(msg) == 0 {
			continue
		}

		switch msg[0] {
		case model.MsgTypeInit:
			tt.log.emit(cmiEvent, fmt.Sprintf("% x", msg))
		case model.MsgTypeEnd:
			// SHIP 13.4.7 connection termination announce
			tt.log.emit(announceEvent, string(msg[1:]))
		default:
			detail := fmt.Sprintf("type=%d %s", msg[0], string(msg[1:]))
			tt.log.emit(msgEvent, detail)
			if c.label == "B" && isHelloMessage(msg) {
				tt.log.emit(evBHelloRx, string(msg[1:]))
			}
		}
	}
}

func isHelloMessage(msg []byte) bool {
	return len(msg) > 1 && msg[0] == model.MsgTypeControl &&
		strings.Contains(string(msg[1:]), "connectionHello")
}

func closeDetail(err error) string {
	if closeErr, ok := err.(*websocket.CloseError); ok {
		return fmt.Sprintf("code=%d text=%q", closeErr.Code, closeErr.Text)
	}
	return err.Error()
}

// ---------------------------------------------------------------------------
// device under test
// ---------------------------------------------------------------------------

type dutHub struct {
	*Hub
	ski        string
	port       int
	disconnect *stubHubReader
}

// stubHubReader is a hand-written api.HubReaderInterface rather than a generated
// mock. testify formats every call argument through fmt/reflect while matching, and
// the hub mutates *ConnectionStateDetail under its own lock while a handshake is in
// flight — so any testify-based reader makes -race fire inside the mock itself, not
// in the code under test. A plain stub keeps these scenarios race-clean.
type stubHubReader struct {
	mux           sync.Mutex
	disconnected  []string
	connected     []string
	payloadReader api.ShipConnectionDataReaderInterface
}

func newStubHubReader() *stubHubReader {
	return &stubHubReader{payloadReader: noopPayloadReader{}}
}

type noopPayloadReader struct{}

func (noopPayloadReader) HandleShipPayloadMessage(message []byte) {}

func (r *stubHubReader) RemoteServiceConnected(identity api.ServiceIdentity) {
	r.mux.Lock()
	defer r.mux.Unlock()
	r.connected = append(r.connected, identity.SKI)
}

func (r *stubHubReader) RemoteServiceDisconnected(identity api.ServiceIdentity) {
	r.mux.Lock()
	defer r.mux.Unlock()
	r.disconnected = append(r.disconnected, identity.SKI)
}

func (r *stubHubReader) SetupRemoteService(identity api.ServiceIdentity,
	writeI api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
	return r.payloadReader
}

func (r *stubHubReader) VisibleRemoteMdnsServicesUpdated(entries []api.RemoteMdnsService) {}

func (r *stubHubReader) ServiceUpdated(identity api.ServiceIdentity) {}

func (r *stubHubReader) ServicePairingDetailUpdate(identity api.ServiceIdentity,
	detail *api.ConnectionStateDetail) {
}

func (r *stubHubReader) AllowWaitingForTrust(identity api.ServiceIdentity) bool { return true }

// count reports how often the SKI was reported as disconnected.
func (r *stubHubReader) count(ski string) int {
	r.mux.Lock()
	defer r.mux.Unlock()
	n := 0
	for _, s := range r.disconnected {
		if s == ski {
			n++
		}
	}
	return n
}

// newDUT starts a real Hub with a real websocket server on a free port.
func newDUT(t *testing.T, certificate tls.Certificate) *dutHub {
	t.Helper()

	hubReader := newStubHubReader()

	mdnsService := mocks.NewMdnsInterface(t)
	mdnsService.EXPECT().Start(mock.Anything, mock.Anything).Return(nil).Maybe()
	mdnsService.EXPECT().AnnounceMdnsEntry().Return(nil).Maybe()
	mdnsService.EXPECT().UnannounceMdnsEntry().Maybe()
	mdnsService.EXPECT().RequestMdnsEntries().Maybe()
	mdnsService.EXPECT().Shutdown().Maybe()

	ski := skiOfCertificate(t, certificate)
	localService, err := api.NewServiceDetails(ski, "", "")
	require.NoError(t, err)
	localService.SetShipID("dut-ship-id")

	port := freePort(t)
	hub, err := newTestHub(hubReader, mdnsService, port, certificate, localService, nil)
	require.NoError(t, err)
	require.NoError(t, hub.Start())

	t.Cleanup(hub.Shutdown)

	return &dutHub{Hub: hub, ski: ski, port: port, disconnect: hubReader}
}

// trust establishes PRE_SHIP_Mutual_Trust for a peer SKI and returns the
// registry entry the DUT would use for an outgoing connection.
func (d *dutHub) trust(t *testing.T, peerSKI string) *api.ServiceDetails {
	t.Helper()
	d.RegisterRemoteService(api.SKIToServiceIdentity(peerSKI))
	service := d.ServiceForIdentifier(peerSKI, "")
	require.NotNil(t, service, "peer service must be registered")
	require.True(t, service.Trusted(), "peer must be trusted (PRE_SHIP_Mutual_Trust)")
	return service
}

// dial runs an outgoing connection attempt in the background, mirroring what the
// mDNS path does. The returned channel yields connectFoundService's error.
func (d *dutHub) dial(service *api.ServiceDetails, host, port string) <-chan error {
	done := make(chan error, 1)
	go func() {
		done <- d.connectFoundService(service, host, port, "/ship/")
	}()
	return done
}

func (d *dutHub) registeredConnection(ski string) (api.ShipConnectionInterface, bool) {
	d.muxCon.RLock()
	defer d.muxCon.RUnlock()
	conn, ok := d.connections[ski]
	return conn, ok
}

func (d *dutHub) connectionCount() int {
	d.muxCon.RLock()
	defer d.muxCon.RUnlock()
	return len(d.connections)
}
