package ws

import (
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/enbility/ship-go/mocks"
	util "github.com/enbility/ship-go/util"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestWebsocketSuite(t *testing.T) {
	suite.Run(t, new(WebsocketSuite))
}

type WebsocketSuite struct {
	suite.Suite

	sut *WebsocketConnection

	testServer   *httptest.Server
	testResponse *http.Response
	testWsConn   *websocket.Conn

	wsDataReader *mocks.WebsocketDataReaderInterface
}

func (s *WebsocketSuite) BeforeTest(suiteName, testName string) {
	s.wsDataReader = mocks.NewWebsocketDataReaderInterface(s.T())
	s.wsDataReader.EXPECT().ReportConnectionError(mock.Anything).Return().Maybe()
	s.wsDataReader.EXPECT().HandleIncomingWebsocketMessage(mock.Anything).Return().Maybe()

	ts := &testServer{}

	// body close is done in AfterTest
	//nolint:bodyclose
	s.testServer, s.testResponse, s.testWsConn = newWSServer(s.T(), ts)

	s.sut = NewWebsocketConnection(s.testWsConn, "remoteSki")
	s.sut.InitDataProcessing(s.wsDataReader)
}

func (s *WebsocketSuite) AfterTest(suiteName, testName string) {
	s.testResponse.Body.Close()
	_ = s.testWsConn.Close()
	s.testServer.Close()
}

func (s *WebsocketSuite) TestConnection() {
	isClosed := s.sut.isConnClosed()
	assert.Equal(s.T(), false, isClosed)

	msg := []byte{0, 0}
	err := s.sut.WriteMessageToWebsocketConnection(msg)
	assert.Nil(s.T(), err)

	// make sure we have enough time to read and write
	time.Sleep(time.Millisecond * 500)

	msg = []byte{1}
	msg = append(msg, []byte("message")...)
	err = s.sut.WriteMessageToWebsocketConnection(msg)
	assert.Nil(s.T(), err)

	// make sure we have enough time to read and write
	time.Sleep(time.Millisecond * 500)

	isConnClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), false, isConnClosed)
	assert.Nil(s.T(), err)

	s.sut.CloseDataConnection(450, "User Close")

	isConnClosed, err = s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), true, isConnClosed)
	assert.NotNil(s.T(), err)

	err = s.sut.WriteMessageToWebsocketConnection(msg)
	assert.NotNil(s.T(), err)
}

func (s *WebsocketSuite) TestConnectionInvalid() {
	msg := []byte{100}
	err := s.sut.WriteMessageToWebsocketConnection(msg)
	assert.Nil(s.T(), err)

	// make sure we have enough time to read and write
	time.Sleep(time.Millisecond * 500)

	isConnClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), true, isConnClosed)
	assert.NotNil(s.T(), err)

	err = s.sut.WriteMessageToWebsocketConnection(msg)
	assert.NotNil(s.T(), err)

	s.sut.CloseDataConnection(500, "test")

	result := s.sut.writeMessage(websocket.BinaryMessage, []byte{})
	assert.Equal(s.T(), false, result)

	err = s.sut.writeMessageWithoutErrorHandling(websocket.BinaryMessage, []byte{})
	assert.NotNil(s.T(), err)

	s.sut.conn = nil

	data, err := s.sut.readWebsocketMessage()
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), data)

	err = s.sut.checkWebsocketMessage(websocket.TextMessage, []byte{})
	assert.NotNil(s.T(), err)
}

func (s *WebsocketSuite) TestConnectionClose() {
	s.sut.close()

	isClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), true, isClosed)
	assert.NotNil(s.T(), err)
}

func (s *WebsocketSuite) TestWriteBufferFull() {
	amountNil := 0
	amountNotNil := 0
	for i := 0; i < 10000; i++ {
		msg := []byte{1}
		msg = append(msg, []byte("message")...)
		err := s.sut.WriteMessageToWebsocketConnection(msg)
		if err == nil {
			amountNil++
		} else {
			amountNotNil++
		}
	}
	assert.Greater(s.T(), amountNotNil, 0)
	assert.Greater(s.T(), amountNil, 0)
}

func (s *WebsocketSuite) TestPingPeriod() {
	isClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), false, isClosed)
	assert.Nil(s.T(), err)

	if !util.IsRunningOnCI() {
		// test if the function is triggered correctly via the timer
		time.Sleep(time.Second * 51)
	} else {
		// speed up the test by running the method directly
		s.sut.handlePing()
	}

	isClosed, err = s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), false, isClosed)
	assert.Nil(s.T(), err)
}

func (s *WebsocketSuite) TestCloseWithError() {
	isClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), false, isClosed)
	assert.Nil(s.T(), err)

	err = errors.New("test error")
	s.sut.closeWithError(err, "test error")

	isClosed, err = s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), true, isClosed)
	assert.NotNil(s.T(), err)
}

// A write deadline stays armed on the socket after the write it was set for, and only a
// SHIP message or the 50s keepalive ping refreshes it. An established connection idle for
// longer than writeWait therefore sits with an elapsed one - and a write under an elapsed
// deadline fails instantly, which gorilla latches, taking the connection down for good.
func (s *WebsocketSuite) TestWriteOnIdleConnection() {
	s.sut.muxConWrite.Lock()
	err := s.sut.conn.SetWriteDeadline(time.Now().Add(-time.Second))
	s.sut.muxConWrite.Unlock()
	assert.NoError(s.T(), err)

	assert.NoError(s.T(), s.sut.writeMessageWithoutErrorHandling(websocket.BinaryMessage, []byte{0, 0}),
		"a write must not fail just because the connection had been idle")
	assert.NoError(s.T(), s.sut.writeMessageWithoutErrorHandling(websocket.BinaryMessage, []byte{0, 0}),
		"and it must not have latched an error that breaks every write after it")

	isClosed, _ := s.sut.IsDataConnectionClosed()
	assert.False(s.T(), isClosed)
}

// The close frame is the write most exposed to an elapsed deadline: it is sent on a
// connection that has usually been quiet for a while. Losing it turns a clean close into
// an abnormal one, so the peer sees 1006 "unexpected EOF" instead of the code and reason
// it was given - which is the difference between a peer that knows why the connection
// went away and one that has to guess.
func TestCloseFrameOnIdleConnection(t *testing.T) {
	peerEnd := make(chan error, 1)

	server, resp, clientConn := newWSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader.CheckOrigin = func(r *http.Request) bool { return true }
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				peerEnd <- err
				return
			}
		}
	}))
	defer server.Close()
	defer resp.Body.Close()

	reader := mocks.NewWebsocketDataReaderInterface(t)
	reader.EXPECT().HandleIncomingWebsocketMessage(mock.Anything).Maybe()
	reader.EXPECT().ReportConnectionError(mock.Anything).Maybe()

	sut := NewWebsocketConnection(clientConn, "test-ski")
	sut.InitDataProcessing(reader)

	// what the socket looks like once writeWait has passed since the last write
	sut.muxConWrite.Lock()
	require.NoError(t, sut.conn.SetWriteDeadline(time.Now().Add(-time.Second)))
	sut.muxConWrite.Unlock()

	sut.CloseDataConnection(4001, "double connection")

	select {
	case err := <-peerEnd:
		var closeErr *websocket.CloseError
		require.ErrorAs(t, err, &closeErr, "the peer must receive the close frame, got: %v", err)
		assert.Equal(t, 4001, closeErr.Code)
		assert.Equal(t, "double connection", closeErr.Text)
	case <-time.After(5 * time.Second):
		t.Fatal("the peer never saw the connection end")
	}
}

var upgrader = websocket.Upgrader{}

func newWSServer(t *testing.T, h http.Handler) (*httptest.Server, *http.Response, *websocket.Conn) {
	t.Helper()

	s := httptest.NewServer(h)
	wsURL := strings.ReplaceAll(s.URL, "http://", "ws://")
	wsURL = strings.ReplaceAll(wsURL, "https://", "wss://")

	ws, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Close response body since it's not needed after WebSocket upgrade
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	return s, resp, ws
}

type testServer struct {
}

func (s *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer ws.Close()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			return
		}

		err = ws.WriteMessage(websocket.BinaryMessage, msg)
		if err != nil {
			continue
		}
	}
}
