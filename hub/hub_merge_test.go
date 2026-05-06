package hub

import (
	"testing"

	"github.com/enbility/ship-go/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests target the merge primitive introduced for the
// "merge duplicate ServiceDetails entries" change. The merge primitive only touches
// h.muxReg and h.remoteServices, so a zero-value Hub is sufficient — no
// websocket / mDNS / cert plumbing is needed.

func newMergeHub() *Hub {
	return &Hub{}
}

func mkSvc(t *testing.T, ski, fp, ship string) *api.ServiceDetails {
	t.Helper()
	s, err := api.NewServiceDetails(ski, fp, ship)
	require.NoError(t, err)
	return s
}

// emptySvc constructs a ServiceDetails with no identifiers set. Used to
// exercise the "candidate has no identifiers" path that NewServiceDetails
// would otherwise refuse.
func emptySvc() *api.ServiceDetails {
	return &api.ServiceDetails{}
}

// ---------------------------------------------------------------------------
// mergeOrAddService
// ---------------------------------------------------------------------------

func TestMergeOrAdd_NilCandidate(t *testing.T) {
	h := newMergeHub()
	got, err := h.mergeOrAddService(nil)
	assert.Nil(t, got)
	assert.Error(t, err)
}

func TestMergeOrAdd_NoIdentifiers(t *testing.T) {
	h := newMergeHub()
	got, err := h.mergeOrAddService(emptySvc())
	assert.Nil(t, got)
	assert.Error(t, err)
	assert.Empty(t, h.remoteServices)
}

func TestMergeOrAdd_AddsWhenNoMatch(t *testing.T) {
	h := newMergeHub()
	cand := mkSvc(t, "ski1", "FP1", "")
	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Same(t, cand, got)
	assert.Len(t, h.remoteServices, 1)
}

func TestMergeOrAdd_MatchBySKI_FoldsIdentifiers(t *testing.T) {
	h := newMergeHub()
	existing := mkSvc(t, "ski1", "", "")
	h.remoteServices = append(h.remoteServices, existing)

	cand := mkSvc(t, "ski1", "FPNEW", "shipNew")
	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Same(t, existing, got, "canonical should be the pre-existing entry")
	assert.Equal(t, "FPNEW", existing.Fingerprint())
	assert.Equal(t, "shipNew", existing.ShipID())
	assert.Len(t, h.remoteServices, 1)
}

func TestMergeOrAdd_MatchByFingerprint_CaseInsensitive(t *testing.T) {
	h := newMergeHub()
	existing := mkSvc(t, "", "ABCDEF", "ship1")
	h.remoteServices = append(h.remoteServices, existing)

	cand := mkSvc(t, "ski1", "abcdef", "")
	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Same(t, existing, got)
	assert.Equal(t, "ski1", existing.SKI())
	assert.Len(t, h.remoteServices, 1)
}

func TestMergeOrAdd_MatchByShipID(t *testing.T) {
	h := newMergeHub()
	existing := mkSvc(t, "", "FP1", "shipX")
	h.remoteServices = append(h.remoteServices, existing)

	cand := mkSvc(t, "skiNew", "", "shipX")
	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Same(t, existing, got)
	assert.Equal(t, "skinew", existing.SKI()) // normalized
	assert.Len(t, h.remoteServices, 1)
}

func TestMergeOrAdd_SKIConflictReturnsError(t *testing.T) {
	h := newMergeHub()
	existing := mkSvc(t, "ski1", "FP1", "")
	h.remoteServices = append(h.remoteServices, existing)

	cand := mkSvc(t, "ski2", "FP1", "")
	got, err := h.mergeOrAddService(cand)
	assert.Nil(t, got)
	assert.Error(t, err)
	// Registry must be unchanged on conflict.
	assert.Len(t, h.remoteServices, 1)
	assert.Equal(t, "ski1", h.remoteServices[0].SKI())
}

func TestMergeOrAdd_FingerprintConflictReturnsError(t *testing.T) {
	h := newMergeHub()
	existing := mkSvc(t, "ski1", "FP1", "")
	h.remoteServices = append(h.remoteServices, existing)

	cand := mkSvc(t, "ski1", "FP2", "")
	got, err := h.mergeOrAddService(cand)
	assert.Nil(t, got)
	assert.Error(t, err)
	assert.Len(t, h.remoteServices, 1)
}

func TestMergeOrAdd_ShipIDConflictReturnsError(t *testing.T) {
	h := newMergeHub()
	existing := mkSvc(t, "", "FP1", "shipA")
	h.remoteServices = append(h.remoteServices, existing)

	cand := mkSvc(t, "", "FP1", "shipB")
	got, err := h.mergeOrAddService(cand)
	assert.Nil(t, got)
	assert.Error(t, err)
	assert.Len(t, h.remoteServices, 1)
	assert.Equal(t, "shipA", h.remoteServices[0].ShipID())
}

// Split state: two existing entries describe the same device but were
// created by different code paths. A candidate that matches both must
// fold them into one canonical entry.
func TestMergeOrAdd_SplitStateAbsorbsBoth(t *testing.T) {
	h := newMergeHub()
	a := mkSvc(t, "ski1", "FP1", "") // from incoming TLS handshake
	// A ShipID-only entry would normally be created by RegisterRemoteService
	// before TLS reveals SKI/FP. NewServiceDetails refuses that shape, so
	// build it via the zero-value escape hatch.
	b := emptySvc()
	b.SetShipID("shipX")
	h.remoteServices = append(h.remoteServices, a, b)

	cand := mkSvc(t, "", "FP1", "shipX")
	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Len(t, h.remoteServices, 1, "split-state entries must be absorbed into one")
	assert.Equal(t, "ski1", got.SKI())
	assert.Equal(t, "FP1", got.Fingerprint())
	assert.Equal(t, "shipX", got.ShipID())
}

// When several entries match, a trusted entry must win as canonical so
// a stale untrusted duplicate cannot shadow trust.
func TestMergeOrAdd_TrustedMatchWinsAsCanonical(t *testing.T) {
	h := newMergeHub()
	untrusted := mkSvc(t, "ski1", "FP1", "")
	trusted := emptySvc()
	trusted.SetShipID("shipX")
	trusted.SetTrusted(true)
	h.remoteServices = append(h.remoteServices, untrusted, trusted)

	cand := mkSvc(t, "", "FP1", "shipX")
	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Same(t, trusted, got)
	assert.True(t, got.Trusted())
	assert.Equal(t, "ski1", got.SKI())
	assert.Len(t, h.remoteServices, 1)
}

// When matches exist but none are trusted, the first match becomes
// canonical.
func TestMergeOrAdd_FirstMatchWinsWhenNoneTrusted(t *testing.T) {
	h := newMergeHub()
	first := mkSvc(t, "ski1", "", "")
	second := emptySvc()
	second.SetShipID("shipX")
	h.remoteServices = append(h.remoteServices, first, second)

	cand := mkSvc(t, "ski1", "", "shipX")
	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Same(t, first, got)
	assert.Len(t, h.remoteServices, 1)
}

// Trust / pairing-type / IPv4 propagation from candidate onto canonical.
func TestMergeOrAdd_PropagatesTrustAndPairingState(t *testing.T) {
	h := newMergeHub()
	existing := mkSvc(t, "ski1", "", "")
	// Existing has IPv4 already — must not be overwritten.
	existing.SetIPv4("10.0.0.1")
	h.remoteServices = append(h.remoteServices, existing)

	cand := mkSvc(t, "ski1", "FP1", "shipX")
	cand.SetTrusted(true)
	cand.SetAutoAccept(true)
	cand.SetPairingType(api.PairingTypeAddCu)
	cand.SetIPv4("10.0.0.2") // should NOT overwrite

	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Same(t, existing, got)
	assert.True(t, got.Trusted())
	assert.True(t, got.AutoAccept())
	assert.Equal(t, api.PairingTypeAddCu, got.PairingType())
	assert.Equal(t, "10.0.0.1", got.IPv4(), "existing IPv4 must not be overwritten")
}

// IPv4 fills only when missing on the canonical entry.
func TestMergeOrAdd_IPv4FilledWhenEmpty(t *testing.T) {
	h := newMergeHub()
	existing := mkSvc(t, "ski1", "", "")
	h.remoteServices = append(h.remoteServices, existing)

	cand := mkSvc(t, "ski1", "", "")
	cand.SetIPv4("10.0.0.5")

	got, err := h.mergeOrAddService(cand)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.5", got.IPv4())
}

// Re-merging the same candidate is idempotent and does not duplicate.
func TestMergeOrAdd_Idempotent(t *testing.T) {
	h := newMergeHub()
	cand := mkSvc(t, "ski1", "FP1", "shipX")
	_, err := h.mergeOrAddService(cand)
	require.NoError(t, err)

	again := mkSvc(t, "ski1", "FP1", "shipX")
	_, err = h.mergeOrAddService(again)
	require.NoError(t, err)

	assert.Len(t, h.remoteServices, 1)
}

// ---------------------------------------------------------------------------
// addService (thin bool-returning wrapper)
// ---------------------------------------------------------------------------

func TestAddService_NilFalse(t *testing.T) {
	h := newMergeHub()
	assert.False(t, h.addService(nil))
}

func TestAddService_NewTrue(t *testing.T) {
	h := newMergeHub()
	assert.True(t, h.addService(mkSvc(t, "ski1", "FP1", "")))
	assert.Len(t, h.remoteServices, 1)
}

// addService now goes through merge, so re-adding the same identifiers
// no longer returns false — it returns true (the merge succeeded with no
// new entry created). This is a documented behavioural change.
func TestAddService_DuplicateMergesToTrue(t *testing.T) {
	h := newMergeHub()
	require.True(t, h.addService(mkSvc(t, "ski1", "FP1", "")))
	assert.True(t, h.addService(mkSvc(t, "ski1", "FP1", "")))
	assert.Len(t, h.remoteServices, 1)
}

func TestAddService_ConflictFalse(t *testing.T) {
	h := newMergeHub()
	require.True(t, h.addService(mkSvc(t, "ski1", "FP1", "")))
	assert.False(t, h.addService(mkSvc(t, "ski1", "FP2", "")))
	assert.Len(t, h.remoteServices, 1)
	assert.Equal(t, "FP1", h.remoteServices[0].Fingerprint())
}

// ---------------------------------------------------------------------------
// ServiceForIdentifierFull (lookup with trusted-wins tiebreak)
// ---------------------------------------------------------------------------

func TestLookupFull_AllEmptyReturnsNil(t *testing.T) {
	h := newMergeHub()
	h.remoteServices = append(h.remoteServices, mkSvc(t, "ski1", "FP1", "shipX"))
	assert.Nil(t, h.ServiceForIdentifierFull("", "", ""))
}

func TestLookupFull_MatchBySKI(t *testing.T) {
	h := newMergeHub()
	s := mkSvc(t, "ski1", "", "")
	h.remoteServices = append(h.remoteServices, s)
	assert.Same(t, s, h.ServiceForIdentifierFull("ski1", "", ""))
}

func TestLookupFull_MatchByFingerprint_CaseInsensitive(t *testing.T) {
	h := newMergeHub()
	s := mkSvc(t, "", "ABCDEF", "shipX")
	h.remoteServices = append(h.remoteServices, s)
	assert.Same(t, s, h.ServiceForIdentifierFull("", "abcdef", ""))
}

func TestLookupFull_MatchByShipID(t *testing.T) {
	h := newMergeHub()
	s := mkSvc(t, "", "FP1", "shipX")
	h.remoteServices = append(h.remoteServices, s)
	assert.Same(t, s, h.ServiceForIdentifierFull("", "", "shipX"))
}

func TestLookupFull_ConflictSkipsEntry(t *testing.T) {
	h := newMergeHub()
	other := mkSvc(t, "skiOther", "FPOther", "shipOther")
	h.remoteServices = append(h.remoteServices, other)
	// ski matches none, fp/ship empty → no result, no false match.
	assert.Nil(t, h.ServiceForIdentifierFull("skiX", "", ""))
}

// Split state: two entries match — the trusted one must be returned.
func TestLookupFull_TrustedWinsOnSplitState(t *testing.T) {
	h := newMergeHub()
	untrusted := mkSvc(t, "ski1", "FP1", "")
	trusted := emptySvc()
	trusted.SetShipID("shipX")
	trusted.SetFingerprint("FP1")
	trusted.SetTrusted(true)
	h.remoteServices = append(h.remoteServices, untrusted, trusted)

	got := h.ServiceForIdentifierFull("", "FP1", "")
	assert.Same(t, trusted, got)
}

func TestLookupFull_FirstMatchWhenNoneTrusted(t *testing.T) {
	h := newMergeHub()
	a := mkSvc(t, "", "FP1", "shipA")
	b := mkSvc(t, "", "FP1", "shipB")
	// b would conflict with a on shipID; build only a-style entries that
	// share fingerprint to avoid that.
	b = mkSvc(t, "ski2", "FP1", "")
	h.remoteServices = append(h.remoteServices, a, b)
	got := h.ServiceForIdentifierFull("", "FP1", "")
	assert.Same(t, a, got, "first match wins when no entry is trusted")
}

func TestLookupFull_NoMatchReturnsNil(t *testing.T) {
	h := newMergeHub()
	h.remoteServices = append(h.remoteServices, mkSvc(t, "ski1", "FP1", "shipX"))
	assert.Nil(t, h.ServiceForIdentifierFull("skiOther", "", ""))
}

func TestLookupFull_NormalizesSKI(t *testing.T) {
	h := newMergeHub()
	s := mkSvc(t, "AB-CD EF", "", "")
	h.remoteServices = append(h.remoteServices, s)
	// Stored SKI is normalized to "abcdef"; lookup must accept the
	// raw form too.
	assert.Same(t, s, h.ServiceForIdentifierFull("AB-CD EF", "", ""))
	assert.Same(t, s, h.ServiceForIdentifierFull("abcdef", "", ""))
}

// ---------------------------------------------------------------------------
// ServiceFor / ServiceForIdentifier (delegation)
// ---------------------------------------------------------------------------

func TestServiceFor_DelegatesToFull(t *testing.T) {
	h := newMergeHub()
	s := mkSvc(t, "ski1", "FP1", "shipX")
	h.remoteServices = append(h.remoteServices, s)

	got := h.ServiceFor(api.ServiceIdentity{SKI: "ski1", Fingerprint: "FP1", ShipID: "shipX"})
	assert.Same(t, s, got)
}

func TestServiceForIdentifier_PrefersTrustedOnSplitState(t *testing.T) {
	h := newMergeHub()
	untrusted := mkSvc(t, "ski1", "FP1", "")
	trusted := mkSvc(t, "ski1", "FP1", "shipX")
	trusted.SetTrusted(true)
	// Two entries with the same SKI/FP — should not happen normally but
	// is the rehydration-from-disk scenario the lookup must defend
	// against.
	h.remoteServices = append(h.remoteServices, untrusted, trusted)

	got := h.ServiceForIdentifier("ski1", "FP1")
	assert.Same(t, trusted, got)
}

// ---------------------------------------------------------------------------
// foldInto
// ---------------------------------------------------------------------------

func TestFoldInto_SameDstSrcNoOp(t *testing.T) {
	s := mkSvc(t, "ski1", "FP1", "")
	foldInto(s, s) // must not panic / deadlock
	assert.Equal(t, "ski1", s.SKI())
}

func TestFoldInto_NilSrcNoOp(t *testing.T) {
	dst := mkSvc(t, "ski1", "", "")
	foldInto(dst, nil)
	assert.Equal(t, "ski1", dst.SKI())
}

func TestFoldInto_CopiesMissingFields(t *testing.T) {
	dst := mkSvc(t, "ski1", "", "")
	src := mkSvc(t, "", "FP1", "shipX")
	src.SetIPv4("10.0.0.1")
	foldInto(dst, src)
	assert.Equal(t, "FP1", dst.Fingerprint())
	assert.Equal(t, "shipX", dst.ShipID())
	assert.Equal(t, "10.0.0.1", dst.IPv4())
}

func TestFoldInto_DoesNotOverwritePresentFields(t *testing.T) {
	dst := mkSvc(t, "skiDst", "FPDst", "shipDst")
	dst.SetIPv4("10.0.0.1")
	src := mkSvc(t, "skiSrc", "FPSrc", "shipSrc")
	src.SetIPv4("10.0.0.2")
	foldInto(dst, src)
	assert.Equal(t, "skidst", dst.SKI())
	assert.Equal(t, "FPDst", dst.Fingerprint())
	assert.Equal(t, "shipDst", dst.ShipID())
	assert.Equal(t, "10.0.0.1", dst.IPv4())
}

func TestFoldInto_TrustOrsIn(t *testing.T) {
	dst := mkSvc(t, "ski1", "", "")
	src := mkSvc(t, "ski1", "", "")
	src.SetTrusted(true)
	foldInto(dst, src)
	assert.True(t, dst.Trusted())
}

// Trust must not be cleared by a merge from an untrusted source.
func TestFoldInto_TrustNotCleared(t *testing.T) {
	dst := mkSvc(t, "ski1", "", "")
	dst.SetTrusted(true)
	src := mkSvc(t, "ski1", "", "")
	// src.Trusted() is false by default
	foldInto(dst, src)
	assert.True(t, dst.Trusted(), "trust must be monotonic")
}

func TestFoldInto_AutoAcceptOrsIn(t *testing.T) {
	dst := mkSvc(t, "ski1", "", "")
	src := mkSvc(t, "ski1", "", "")
	src.SetAutoAccept(true)
	foldInto(dst, src)
	assert.True(t, dst.AutoAccept())
}

func TestFoldInto_PairingTypeUpgradesToAddCu(t *testing.T) {
	dst := mkSvc(t, "ski1", "", "")
	src := mkSvc(t, "ski1", "", "")
	src.SetPairingType(api.PairingTypeAddCu)
	foldInto(dst, src)
	assert.Equal(t, api.PairingTypeAddCu, dst.PairingType())
}

// PairingTypeAddCu, once set on dst, is never downgraded by a default
// candidate.
func TestFoldInto_PairingTypeNotDowngraded(t *testing.T) {
	dst := mkSvc(t, "ski1", "", "")
	dst.SetPairingType(api.PairingTypeAddCu)
	src := mkSvc(t, "ski1", "", "")
	// src has PairingTypeDefault.
	foldInto(dst, src)
	assert.Equal(t, api.PairingTypeAddCu, dst.PairingType())
}
