package mdns

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	zapi "github.com/enbility/zeroconf/v3/api"
	zmocks "github.com/enbility/zeroconf/v3/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestZeroconf(t *testing.T) {
	suite.Run(t, new(ZeroconfSuite))
}

type ZeroconfSuite struct {
	suite.Suite

	sut *ZeroconfProvider

	mux sync.Mutex
}

func (z *ZeroconfSuite) BeforeTest(suiteName, testName string) {
	z.sut = NewZeroconfProvider([]net.Interface{}, nil, nil)
}

func (z *ZeroconfSuite) AfterTest(suiteName, testName string) {
	z.sut.Shutdown()
}

type mDNSEntry struct {
	elements   map[string]string
	name, host string
	addresses  []net.IP
	port       int
}

func searchElement(list []mDNSEntry, name string) (mDNSEntry, bool) {
	for _, item := range list {
		if item.name == name {
			return item, true
		}
	}
	return mDNSEntry{}, false
}

func (z *ZeroconfSuite) Test_Shutdown() {
	z.sut.Shutdown()
}

func (z *ZeroconfSuite) Test_ZeroConf() {
	var addedEntries, removedEntries []mDNSEntry

	cb := func(elements map[string]string, name, host string, addresses []net.IP, port int, remove bool) {
		// we expect at least one entry
		assert.NotEqual(z.T(), "", name)

		entry := mDNSEntry{
			elements:  elements,
			name:      name,
			host:      host,
			addresses: addresses,
			port:      port,
		}

		z.mux.Lock()
		if remove {
			removedEntries = append(removedEntries, entry)
		} else {
			addedEntries = append(addedEntries, entry)
		}
		z.mux.Unlock()
	}

	boolV := z.sut.Start(false, cb)
	assert.Equal(z.T(), true, boolV)

	err := z.sut.Announce("dummytest", 4289, []string{"more=more"})
	assert.Nil(z.T(), err)

	time.Sleep(time.Second * 2)

	z.mux.Lock()
	_, found := searchElement(addedEntries, "dummytest")
	z.mux.Unlock()
	assert.Equal(z.T(), true, found)

	z.sut.Unannounce()

	time.Sleep(time.Second * 2)

	z.mux.Lock()
	_, found = searchElement(removedEntries, "dummytest")
	z.mux.Unlock()
	assert.Equal(z.T(), true, found)

	err = z.sut.Announce("test", 4289, []string{"test=test"})
	assert.Nil(z.T(), err)

	time.Sleep(time.Second * 2)

	z.mux.Lock()
	_, found = searchElement(addedEntries, "test")
	z.mux.Unlock()
	assert.Equal(z.T(), true, found)

	z.sut.Unannounce()

	time.Sleep(time.Second * 2)

	z.mux.Lock()
	_, found = searchElement(removedEntries, "test")
	z.mux.Unlock()
	assert.Equal(z.T(), true, found)

	err = z.sut.Announce("", 4289, []string{"test=test"})
	assert.NotNil(z.T(), err)

	z.sut.Unannounce()
}

type mockPacket struct {
	data    []byte
	ifIndex int
	src     net.Addr
}

func configureMockClientConn(t *testing.T, conn *zmocks.MockPacketConn, inbound <-chan mockPacket, querySeen chan<- struct{}) {
	t.Helper()

	conn.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, int, net.Addr, error) {
		packet, ok := <-inbound
		if !ok {
			return 0, 0, nil, errors.New("closed")
		}

		copy(b, packet.data)
		return len(packet.data), packet.ifIndex, packet.src, nil
	}).Maybe()

	conn.EXPECT().WriteTo(mock.Anything, mock.AnythingOfType("int"), mock.Anything).RunAndReturn(
		func(b []byte, ifIndex int, dst net.Addr) (int, error) {
			select {
			case querySeen <- struct{}{}:
			default:
			}
			return len(b), nil
		}).Maybe()

	conn.EXPECT().Close().RunAndReturn(func() error {
		return nil
	}).Maybe()
}

func configureMockServerConn(t *testing.T, conn *zmocks.MockPacketConn, clientInbound chan<- mockPacket) chan mockPacket {
	t.Helper()

	serverInbound := make(chan mockPacket, 1)

	conn.EXPECT().ReadFrom(mock.Anything).RunAndReturn(func(b []byte) (int, int, net.Addr, error) {
		packet, ok := <-serverInbound
		if !ok {
			return 0, 0, nil, errors.New("closed")
		}

		copy(b, packet.data)
		return len(packet.data), packet.ifIndex, packet.src, nil
	}).Maybe()

	conn.EXPECT().WriteTo(mock.Anything, mock.AnythingOfType("int"), mock.Anything).RunAndReturn(
		func(b []byte, ifIndex int, dst net.Addr) (int, error) {
			clientInbound <- mockPacket{
				data:    append([]byte(nil), b...),
				ifIndex: ifIndex,
				src:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353},
			}
			return len(b), nil
		}).Maybe()

	conn.EXPECT().Close().RunAndReturn(func() error {
		close(serverInbound)
		return nil
	}).Maybe()

	return serverInbound
}

func TestZeroconf_WithMockConnections(t *testing.T) {
	clientInbound := make(chan mockPacket, 32)
	querySeen := make(chan struct{}, 1)

	clientConn := zmocks.NewMockPacketConn(t)
	configureMockClientConn(t, clientConn, clientInbound, querySeen)

	factory := zmocks.NewMockConnectionFactory(t)

	var factoryMu sync.Mutex
	createIPv4Calls := 0

	factory.EXPECT().CreateIPv4Conn(mock.Anything).RunAndReturn(func(ifaces []net.Interface) (zapi.PacketConn, error) {
		factoryMu.Lock()
		defer factoryMu.Unlock()

		createIPv4Calls++
		if createIPv4Calls == 1 {
			return clientConn, nil
		}

		serverConn := zmocks.NewMockPacketConn(t)
		configureMockServerConn(t, serverConn, clientInbound)
		return serverConn, nil
	}).Times(3)

	factory.EXPECT().CreateIPv6Conn(mock.Anything).Return(nil, errors.New("IPv6 unavailable")).Times(3)

	var connFactory zapi.ConnectionFactory = factory
	sut := NewZeroconfProvider(nil, &connFactory, nil)
	t.Cleanup(func() {
		sut.Shutdown()
		close(clientInbound)
	})

	var mux sync.Mutex
	var addedEntries, removedEntries []mDNSEntry

	cb := func(elements map[string]string, name, host string, addresses []net.IP, port int, remove bool) {
		entry := mDNSEntry{
			elements:  elements,
			name:      name,
			host:      host,
			addresses: addresses,
			port:      port,
		}

		mux.Lock()
		defer mux.Unlock()
		if remove {
			removedEntries = append(removedEntries, entry)
		} else {
			addedEntries = append(addedEntries, entry)
		}
	}

	require.True(t, sut.Start(false, cb))

	require.Eventually(t, func() bool {
		select {
		case <-querySeen:
			return true
		default:
			return false
		}
	}, 3*time.Second, 20*time.Millisecond, "browse client did not start querying over the mocked connection")

	require.NoError(t, sut.Announce("dummytest", 4289, []string{"more=more"}))

	require.Eventually(t, func() bool {
		mux.Lock()
		defer mux.Unlock()

		entry, found := searchElement(addedEntries, "dummytest")
		return found && entry.elements["more"] == "more" && entry.port == 4289
	}, 5*time.Second, 20*time.Millisecond)

	sut.Unannounce()

	require.Eventually(t, func() bool {
		mux.Lock()
		defer mux.Unlock()

		entry, found := searchElement(removedEntries, "dummytest")
		return found && entry.elements["more"] == "more" && entry.port == 4289
	}, 2*time.Second, 20*time.Millisecond)

	require.NoError(t, sut.Announce("test", 4289, []string{"test=test"}))

	require.Eventually(t, func() bool {
		mux.Lock()
		defer mux.Unlock()

		entry, found := searchElement(addedEntries, "test")
		return found && entry.elements["test"] == "test" && entry.port == 4289
	}, 5*time.Second, 20*time.Millisecond)

	sut.Unannounce()

	require.Eventually(t, func() bool {
		mux.Lock()
		defer mux.Unlock()

		entry, found := searchElement(removedEntries, "test")
		return found && entry.elements["test"] == "test" && entry.port == 4289
	}, 2*time.Second, 20*time.Millisecond)

	require.Error(t, sut.Announce("", 4289, []string{"test=test"}))
}
