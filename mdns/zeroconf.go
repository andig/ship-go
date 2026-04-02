package mdns

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/logging"
	"github.com/enbility/zeroconf/v2"
)

type ZeroconfProvider struct {
	ifaces []net.Interface

	zc *zeroconf.Server

	ctx    context.Context
	cancel context.CancelFunc

	isStarted    bool
	listenerDone chan struct{} // closed when chanListener exits

	mux sync.Mutex
}

func NewZeroconfProvider(ifaces []net.Interface) *ZeroconfProvider {
	return &ZeroconfProvider{
		ifaces: ifaces,
	}
}

var _ api.MdnsProviderInterface = (*ZeroconfProvider)(nil)

func (z *ZeroconfProvider) Start(autoReconnect bool, cb api.MdnsResolveCB) bool {
	z.mux.Lock()
	if z.isStarted {
		z.mux.Unlock()
		logging.Log().Debug("mdns: ZeroconfProvider already started, ignoring duplicate Start()")
		return true
	}
	z.isStarted = true
	z.listenerDone = make(chan struct{})
	z.mux.Unlock()

	go z.chanListener(cb)

	return true
}

func (z *ZeroconfProvider) Shutdown() {
	z.Unannounce()

	z.mux.Lock()
	if z.cancel != nil {
		z.cancel()
	}

	done := z.listenerDone
	z.isStarted = false
	z.mux.Unlock()

	// Wait for the chanListener goroutine to finish before returning,
	// so a subsequent Start() won't race with the old goroutine.
	if done != nil {
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			logging.Log().Debug("mdns: zeroconf chanListener did not exit in time")
		}
	}
}

func (z *ZeroconfProvider) Announce(serviceName string, port int, txt []string) error {
	logging.Log().Debug("mdns: using zeroconf")

	// use Zeroconf library if avahi is not available
	// Set TTL to 2 minutes as defined in SHIP chapter 7
	mDNSServer, err := zeroconf.Register(serviceName, shipZeroConfServiceType, shipZeroConfDomain, port, txt, z.ifaces, zeroconf.TTL(120))
	if err != nil {
		return err
	}

	z.mux.Lock()
	defer z.mux.Unlock()

	z.zc = mDNSServer

	return nil
}

func (z *ZeroconfProvider) Unannounce() {
	z.mux.Lock()
	defer z.mux.Unlock()

	if z.zc == nil {
		return
	}

	z.zc.Shutdown()
	z.zc = nil
}

func (z *ZeroconfProvider) chanListener(cb api.MdnsResolveCB) {
	defer func() {
		z.mux.Lock()
		if z.listenerDone != nil {
			close(z.listenerDone)
		}
		z.mux.Unlock()
	}()

	// Buffered channels prevent the Browse goroutine from deadlocking on shutdown.
	// When ctx is cancelled, chanListener exits and stops reading. Without a buffer,
	// Browse's mainloop blocks forever on a channel send and leaks. With a buffer,
	// the pending send completes into the buffer, mainloop loops back to its select,
	// picks ctx.Done(), and cleans up normally.
	zcEntries := make(chan *zeroconf.ServiceEntry, 2)
	zcRemoved := make(chan *zeroconf.ServiceEntry, 2)

	z.mux.Lock()
	z.ctx, z.cancel = context.WithCancel(context.Background())
	z.mux.Unlock()

	go func() {
		_ = zeroconf.Browse(z.ctx, shipZeroConfServiceType, shipZeroConfDomain, zcEntries, zcRemoved, zeroconf.SelectIfaces(z.ifaces))
	}()

	for {
		select {
		case <-z.ctx.Done():
			return
		case service := <-zcRemoved:
			// Zeroconf has issues with merging mDNS data and sometimes reports incomplete records
			if service == nil || len(service.Text) == 0 {
				continue
			}

			elements := parseTxt(service.Text)

			addresses := service.AddrIPv4
			cb(elements, service.Instance, service.HostName, addresses, service.Port, true)

		case service := <-zcEntries:
			// Zeroconf has issues with merging mDNS data and sometimes reports incomplete records
			if service == nil || len(service.Text) == 0 {
				continue
			}

			elements := parseTxt(service.Text)

			addresses := service.AddrIPv4
			addresses = append(addresses, service.AddrIPv6...)
			cb(elements, service.Instance, service.HostName, addresses, service.Port, false)
		}
	}
}
