package mdns

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enbility/go-avahi"
	avahiMocks "github.com/enbility/go-avahi/mocks"
	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

// IssuesSuite contains reproducer tests for known issues in the PR.
// Each test asserts the CORRECT expected behavior so it FAILS against
// the current code, and will PASS once the issue is fixed.
type IssuesSuite struct {
	suite.Suite
}

func TestIssuesSuite(t *testing.T) {
	suite.Run(t, new(IssuesSuite))
}

// ---------------------------------------------------------------------
// stopInterfaceRefresh() returns without waiting for the refreshLoop
// goroutine to exit. Shutdown() then sets mdnsProvider=nil while the
// goroutine may still be executing reannounceWithNewInterfaces().
//
// Reproducer: Inject a provider whose Announce() blocks. Trigger the
// refresh path so the goroutine enters Announce(). Call Shutdown().
// If stopInterfaceRefresh() doesn't wait, Shutdown() completes while
// the goroutine is still inside Announce() -- proving the goroutine
// outlives Shutdown().
// ---------------------------------------------------------------------

func (s *IssuesSuite) Test_ShutdownWaitsForRefreshGoroutineToExit() {
	usableIfaceName := findUsableInterfaceName(s.T())

	announceStarted := make(chan struct{})
	announceBlock := make(chan struct{})
	var announceCalls atomic.Int32

	provider := mocks.NewMdnsProviderInterface(s.T())
	provider.On("Shutdown").Maybe().Return()
	provider.On("Unannounce").Maybe().Return()
	provider.On("Announce", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			call := announceCalls.Add(1)
			if call >= 2 {
				// Signal that we're inside the re-announcement Announce call
				select {
				case announceStarted <- struct{}{}:
				default:
				}
				// Block until test releases us
				<-announceBlock
			}
		}).
		Return(nil)

	mgr := NewMDNS("test", "brand", "model", "EnergyManagementSystem",
		"12345",
		[]api.DeviceCategoryType{api.DeviceCategoryTypeEnergyManagementSystem},
		"shipid", "serviceName",
		4729, []string{usableIfaceName}, MdnsProviderSelectionAll)
	mgr.SetTestProvider(provider)

	err := mgr.Start(mocks.NewMdnsReportInterface(s.T()))
	assert.Nil(s.T(), err)

	// Simulate interface reappearance so attemptResolveMapping detects a change
	mgr.refreshMux.Lock()
	mgr.missingIfaces = map[string]struct{}{usableIfaceName: {}}
	mgr.currentIfaces = []string{}
	mgr.refreshMux.Unlock()

	// Trigger the refresh path (simulates what refreshLoop does on tick)
	go mgr.attemptResolveMapping()

	// Wait for the goroutine to be blocked inside Announce()
	select {
	case <-announceStarted:
	case <-time.After(5 * time.Second):
		close(announceBlock)
		s.T().Fatal("timed out waiting for Announce to be called")
	}

	// Call Shutdown() while goroutine is still inside Announce().
	shutdownDone := make(chan struct{})
	go func() {
		mgr.Shutdown()
		close(shutdownDone)
	}()

	// Check: did Shutdown() complete while the goroutine is still blocked?
	// If stopInterfaceRefresh properly waits, Shutdown() should NOT complete
	// until we release the goroutine.
	select {
	case <-shutdownDone:
		// BUG: Shutdown() completed while the goroutine is still inside
		// Announce(). The goroutine will continue to run after Shutdown()
		// has set mdnsProvider=nil.
		close(announceBlock) // release goroutine so test can clean up
		s.T().Fatal("Shutdown() returned while refresh goroutine was still running inside Announce()")
	case <-time.After(200 * time.Millisecond):
		// EXPECTED after fix: Shutdown() is blocked waiting for the goroutine.
		// Release the goroutine so everything can finish.
		close(announceBlock)
	}

	// Wait for shutdown to actually complete
	select {
	case <-shutdownDone:
	case <-time.After(5 * time.Second):
		s.T().Fatal("Shutdown() did not complete after goroutine was released")
	}
}

// ---------------------------------------------------------------------
// mdnsProvider is read by the background goroutine without any lock,
// while Shutdown() writes nil to it under shutdownMux.
//
// Reproducer: Run reannounceWithNewInterfaces() and Shutdown()
// concurrently. With -race, the race detector catches the
// unsynchronized read/write of mdnsProvider.
// ---------------------------------------------------------------------

func (s *IssuesSuite) Test_ProviderAccessSynchronizedWithShutdown() {
	usableIfaceName := findUsableInterfaceName(s.T())

	for i := 0; i < 50; i++ {
		provider := mocks.NewMdnsProviderInterface(s.T())
		provider.On("Shutdown").Maybe().Return()
		provider.On("Unannounce").Maybe().Return()
		provider.On("Announce", mock.Anything, mock.Anything, mock.Anything).Maybe().Return(nil)

		// Use a real interface name so resolveInterfaces() succeeds and
		// the full code path through updateProviderInterfaces() and
		// AnnounceMdnsEntry() is exercised -- both read mdnsProvider
		// without any lock.
		mgr := NewMDNS("test", "brand", "model", "EnergyManagementSystem",
			"12345",
			[]api.DeviceCategoryType{api.DeviceCategoryTypeEnergyManagementSystem},
			"shipid", "serviceName",
			4729, []string{usableIfaceName}, MdnsProviderSelectionAll)
		mgr.SetTestProvider(provider)

		mgr.mdnsProvider = provider
		mgr.setIsServiceAnnounce(true)
		mgr.currentIfaces = []string{usableIfaceName}
		mgr.missingIfaces = map[string]struct{}{}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			mgr.reannounceWithNewInterfaces()
		}()

		go func() {
			defer wg.Done()
			mgr.Shutdown()
		}()

		wg.Wait()
		// This test fails with -race: the race detector reports
		// concurrent read (updateProviderInterfaces/AnnounceMdnsEntry)
		// vs write (Shutdown sets mdnsProvider = nil).
	}
}

// ---------------------------------------------------------------------
// updateProviderInterfaces() uses a type-switch on concrete
// *AvahiProvider / *ZeroconfProvider. Any other MdnsProviderInterface
// implementation (mocks, future providers) is silently skipped.
//
// Reproducer: Create a minimal provider that implements the interface
// plus an UpdateInterfaces method. Show that updateProviderInterfaces
// never calls it because the type-switch doesn't know about it.
// ---------------------------------------------------------------------

// trackingProvider is a test provider that tracks whether its interfaces
// were updated. It implements MdnsProviderInterface.
type trackingProvider struct {
	interfacesUpdated atomic.Bool
}

func (t *trackingProvider) Start(bool, api.MdnsResolveCB) bool { return true }
func (t *trackingProvider) Shutdown()                          {}
func (t *trackingProvider) Announce(string, int, []string) error {
	return nil
}
func (t *trackingProvider) Unannounce() {}

// SetIfaces would be the natural method to call, but the type-switch
// in updateProviderInterfaces doesn't know about this type.
func (t *trackingProvider) SetIfaces(ifaces []net.Interface) {
	t.interfacesUpdated.Store(true)
}

func (s *IssuesSuite) Test_UpdateProviderInterfacesWorksForAnyProvider() {
	tp := &trackingProvider{}

	mgr := NewMDNS("test", "brand", "model", "EnergyManagementSystem",
		"12345",
		[]api.DeviceCategoryType{api.DeviceCategoryTypeEnergyManagementSystem},
		"shipid", "serviceName",
		4729, nil, MdnsProviderSelectionAll)
	mgr.mdnsProvider = tp

	testIfaces := []net.Interface{{Name: "eth0", Index: 1}}
	testIndexes := []int32{1}

	mgr.updateProviderInterfaces(testIfaces, testIndexes)

	// EXPECTED: the provider's interfaces should have been updated.
	// BUG: the type-switch only handles *AvahiProvider and *ZeroconfProvider,
	// so trackingProvider (or any mock/future provider) is silently skipped.
	assert.True(s.T(), tp.interfacesUpdated.Load(),
		"updateProviderInterfaces should update any provider, not just concrete Avahi/Zeroconf types")
}

// ---------------------------------------------------------------------
// Shutdown() does not explicitly reset isAnnounced. If
// UnannounceMdnsEntry() panics (caught by the recover wrapper),
// isAnnounced remains stale-true after Shutdown().
//
// Reproducer: Set isAnnounced=true, make Unannounce panic, call
// Shutdown(), assert isAnnounced is false (the correct behavior).
// This fails because Shutdown() never resets it.
// ---------------------------------------------------------------------

func (s *IssuesSuite) Test_IsAnnouncedResetAfterShutdownWithPanic() {
	provider := mocks.NewMdnsProviderInterface(s.T())
	provider.On("Shutdown").Maybe().Return()
	provider.On("Announce", mock.Anything, mock.Anything, mock.Anything).Maybe().Return(nil)
	provider.On("Unannounce").Run(func(args mock.Arguments) {
		panic("simulated unannounce panic")
	}).Return()

	mgr := NewMDNS("test", "brand", "model", "EnergyManagementSystem",
		"12345",
		[]api.DeviceCategoryType{api.DeviceCategoryTypeEnergyManagementSystem},
		"shipid", "serviceName",
		4729, []string{"fake_iface_issue4"}, MdnsProviderSelectionAll)
	mgr.SetTestProvider(provider)
	mgr.mdnsProvider = provider
	mgr.setIsServiceAnnounce(true)

	// Shutdown should not panic (it has recover() wrappers)
	assert.NotPanics(s.T(), func() {
		mgr.Shutdown()
	})

	// EXPECTED: isAnnounced should always be false after Shutdown(),
	// regardless of whether Unannounce panicked.
	// BUG: isAnnounced remains true because the panic prevented
	// UnannounceMdnsEntry from clearing it, and Shutdown() never
	// explicitly resets it.
	assert.False(s.T(), mgr.isServiceAnnounced(),
		"isAnnounced must be false after Shutdown, even if Unannounce panics")
}

// ---------------------------------------------------------------------
// AvahiProvider.Announce() uses manual a.mux.Unlock() on each error
// path instead of defer. If a new error path is added without an
// unlock, the mutex stays locked and the next call deadlocks.
//
// Regression guard: Force each error path in Announce(), then call
// Announce() again. If the mutex was not properly released, the
// second call deadlocks (detected via timeout).
// ---------------------------------------------------------------------

func (s *IssuesSuite) Test_AvahiAnnounceMutexReleasedOnAllErrorPaths() {
	someError := errors.New("some error")

	// Error path 1: EntryGroupNew fails
	s.Run("EntryGroupNew_fails", func() {
		avahiMock := avahiMocks.NewServerInterface(s.T())
		entryGroupMock := avahiMocks.NewEntryGroupInterface(s.T())

		sut := NewAvahiProvider([]int32{1})
		sut.avServer = avahiMock

		// First call: EntryGroupNew fails
		avahiMock.EXPECT().EntryGroupNew().Return(nil, someError).Once()
		err := sut.Announce("test", 4729, []string{"txt=1"})
		assert.NotNil(s.T(), err)

		// Second call: must not deadlock (mutex was released on error)
		avahiMock.EXPECT().EntryGroupNew().Return(entryGroupMock, nil).Once()
		entryGroupMock.EXPECT().AddService(
			mock.Anything, mock.Anything, mock.Anything,
			"test", shipZeroConfServiceType, shipZeroConfDomain,
			"", mock.Anything, mock.Anything,
		).Return(nil).Once()
		entryGroupMock.EXPECT().Commit().Return(nil).Once()

		done := make(chan error, 1)
		go func() {
			done <- sut.Announce("test", 4729, []string{"txt=1"})
		}()

		select {
		case err := <-done:
			assert.Nil(s.T(), err, "second Announce should succeed")
		case <-time.After(2 * time.Second):
			s.T().Fatal("deadlock: mutex not released after EntryGroupNew error")
		}
	})

	// Error path 2: AddService fails
	s.Run("AddService_fails", func() {
		avahiMock := avahiMocks.NewServerInterface(s.T())
		entryGroupMock := avahiMocks.NewEntryGroupInterface(s.T())

		sut := NewAvahiProvider([]int32{1})
		sut.avServer = avahiMock

		// First call: AddService fails
		avahiMock.EXPECT().EntryGroupNew().Return(entryGroupMock, nil).Once()
		entryGroupMock.EXPECT().AddService(
			mock.Anything, mock.Anything, mock.Anything,
			"test", shipZeroConfServiceType, shipZeroConfDomain,
			"", mock.Anything, mock.Anything,
		).Return(someError).Once()
		avahiMock.EXPECT().EntryGroupFree(entryGroupMock).Return().Once()
		err := sut.Announce("test", 4729, []string{"txt=1"})
		assert.NotNil(s.T(), err)

		// Second call: must not deadlock
		entryGroupMock2 := avahiMocks.NewEntryGroupInterface(s.T())
		avahiMock.EXPECT().EntryGroupNew().Return(entryGroupMock2, nil).Once()
		entryGroupMock2.EXPECT().AddService(
			mock.Anything, mock.Anything, mock.Anything,
			"test", shipZeroConfServiceType, shipZeroConfDomain,
			"", mock.Anything, mock.Anything,
		).Return(nil).Once()
		entryGroupMock2.EXPECT().Commit().Return(nil).Once()

		done := make(chan error, 1)
		go func() {
			done <- sut.Announce("test", 4729, []string{"txt=1"})
		}()

		select {
		case err := <-done:
			assert.Nil(s.T(), err, "second Announce should succeed")
		case <-time.After(2 * time.Second):
			s.T().Fatal("deadlock: mutex not released after AddService error")
		}
	})

	// Error path 3: Commit fails
	s.Run("Commit_fails", func() {
		avahiMock := avahiMocks.NewServerInterface(s.T())
		entryGroupMock := avahiMocks.NewEntryGroupInterface(s.T())

		sut := NewAvahiProvider([]int32{1})
		sut.avServer = avahiMock

		// First call: Commit fails
		avahiMock.EXPECT().EntryGroupNew().Return(entryGroupMock, nil).Once()
		entryGroupMock.EXPECT().AddService(
			mock.Anything, mock.Anything, mock.Anything,
			"test", shipZeroConfServiceType, shipZeroConfDomain,
			"", mock.Anything, mock.Anything,
		).Return(nil).Once()
		entryGroupMock.EXPECT().Commit().Return(someError).Once()
		avahiMock.EXPECT().EntryGroupFree(entryGroupMock).Return().Once()
		err := sut.Announce("test", 4729, []string{"txt=1"})
		assert.NotNil(s.T(), err)

		// Second call: must not deadlock
		entryGroupMock2 := avahiMocks.NewEntryGroupInterface(s.T())
		avahiMock.EXPECT().EntryGroupNew().Return(entryGroupMock2, nil).Once()
		entryGroupMock2.EXPECT().AddService(
			mock.Anything, mock.Anything, mock.Anything,
			"test", shipZeroConfServiceType, shipZeroConfDomain,
			"", mock.Anything, mock.Anything,
		).Return(nil).Once()
		entryGroupMock2.EXPECT().Commit().Return(nil).Once()

		done := make(chan error, 1)
		go func() {
			done <- sut.Announce("test", 4729, []string{"txt=1"})
		}()

		select {
		case err := <-done:
			assert.Nil(s.T(), err, "second Announce should succeed")
		case <-time.After(2 * time.Second):
			s.T().Fatal("deadlock: mutex not released after Commit error")
		}
	})
}

// Helper: verify avahi.InterfaceUnspec is what we expect
func init() {
	_ = avahi.InterfaceUnspec // ensure import is used
}
