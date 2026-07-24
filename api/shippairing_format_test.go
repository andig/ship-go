package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// validFormatTXTRecord returns a TXT record with values conforming to pairing
// spec section 5.4, Table 1 (SHIP spec Annex A.3 test vectors).
func validFormatTXTRecord() ShipPairingTXT {
	return ShipPairingTXT{
		TxtVers:    "1",
		ParType:    ParTypeFPSHA256,
		ForId:      "i:983327_u:C8277H008F-3",
		ForPar:     "C74B7855D3479415F62CC01E5F6D9A93EBC676057D85417ADA16FD1384338943",
		TrustId:    "i:46925_u:43652bk-2-gt1",
		TrustPar:   "2CC72E781F7A7D2A08D50196C50FEDF0F7BA583F43F76C8C0DDEC9EEF0D005B4",
		TrustCurve: CurveSecp256r1,
		Type:       CommandTypeAddCU,
		TrustNonce: "BDCEE427FA7208DF3C1F2A749BA6F4D4",
		Alg:        AlgorithmHMACSHA256,
		Digest:     "BCBB62B2176DA2CEE545784CEB1F2A55E049451B12A549C98E8CA213F001DA25",
	}
}

func TestShipPairingTXTValidate_ValidRecord(t *testing.T) {
	txt := validFormatTXTRecord()
	assert.NoError(t, txt.Validate())
}

// TestShipPairingTXTValidate_MalformedValues mirrors the error matrix of
// TC_SPS_TXT_009 (test spec V1.0.0, Table 5 with error types of section
// 2.8.9). In that test case the digest is calculated over the already
// malformed values, so HMAC verification passes — format validation is the
// only gate that can reject these records.
func TestShipPairingTXTValidate_MalformedValues(t *testing.T) {
	valid := validFormatTXTRecord()

	mutate := func(f func(*ShipPairingTXT)) ShipPairingTXT {
		txt := valid
		f(&txt)
		return txt
	}

	cases := []struct {
		name string
		txt  ShipPairingTXT
	}{}

	// txtvers: E03 (other version strings), E12 (empty)
	for _, v := range []string{"0", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", ""} {
		v := v
		cases = append(cases, struct {
			name string
			txt  ShipPairingTXT
		}{"txtvers=" + v, mutate(func(txt *ShipPairingTXT) { txt.TxtVers = v })})
	}

	// parType: E04 (case/length variants), E12 (empty)
	for _, v := range []string{"fpsha256", "fpSha2560", "fpSha25", "fpSha512", ""} {
		v := v
		cases = append(cases, struct {
			name string
			txt  ShipPairingTXT
		}{"parType=" + v, mutate(func(txt *ShipPairingTXT) { txt.ParType = v })})
	}

	// forId / trustId: E12 (empty)
	cases = append(cases,
		struct {
			name string
			txt  ShipPairingTXT
		}{"forId empty", mutate(func(txt *ShipPairingTXT) { txt.ForId = "" })},
		struct {
			name string
			txt  ShipPairingTXT
		}{"trustId empty", mutate(func(txt *ShipPairingTXT) { txt.TrustId = "" })},
	)

	// forPar / trustPar / digest: E05 (curtailed), E07 (appended), E08 (lowercase)
	for _, tc := range []struct {
		key string
		set func(*ShipPairingTXT, string)
		get func(ShipPairingTXT) string
	}{
		{"forPar", func(txt *ShipPairingTXT, v string) { txt.ForPar = v }, func(txt ShipPairingTXT) string { return txt.ForPar }},
		{"trustPar", func(txt *ShipPairingTXT, v string) { txt.TrustPar = v }, func(txt ShipPairingTXT) string { return txt.TrustPar }},
		{"digest", func(txt *ShipPairingTXT, v string) { txt.Digest = v }, func(txt ShipPairingTXT) string { return txt.Digest }},
	} {
		tc := tc
		original := tc.get(valid)
		// E05: curtail to lengths 0..63 (representative samples)
		for _, l := range []int{0, 1, 32, 63} {
			l := l
			cases = append(cases, struct {
				name string
				txt  ShipPairingTXT
			}{tc.key + " curtailed to " + original[:l], mutate(func(txt *ShipPairingTXT) { tc.set(txt, original[:l]) })})
		}
		// E07: append non-hex or odd suffixes
		for _, suffix := range []string{"G", "+", "A", "9B"} {
			suffix := suffix
			cases = append(cases, struct {
				name string
				txt  ShipPairingTXT
			}{tc.key + " appended " + suffix, mutate(func(txt *ShipPairingTXT) { tc.set(txt, original+suffix) })})
		}
		// E08: lowercase
		cases = append(cases, struct {
			name string
			txt  ShipPairingTXT
		}{tc.key + " lowercase", mutate(func(txt *ShipPairingTXT) { tc.set(txt, strings.ToLower(original)) })})
	}

	// trustCurve: E09 (variants), E12 (empty)
	for _, v := range []string{"secp256R1", "secp256r11", "P-256", "NIST P-256",
		"brainpoolp256r1", "brainpoolP256r12", "brainpoolP256",
		"brainpoolp384r1", "brainpoolP384r13", "brainpoolP384r", ""} {
		v := v
		cases = append(cases, struct {
			name string
			txt  ShipPairingTXT
		}{"trustCurve=" + v, mutate(func(txt *ShipPairingTXT) { txt.TrustCurve = v })})
	}

	// type: E10 (variants), E12 (empty)
	for _, v := range []string{"addcu", "addC", "addCuj", ""} {
		v := v
		cases = append(cases, struct {
			name string
			txt  ShipPairingTXT
		}{"type=" + v, mutate(func(txt *ShipPairingTXT) { txt.Type = v })})
	}

	// trustNonce: E08 (lowercase), E14 (appended valid hex), E15 (curtailed even lengths)
	nonce := valid.TrustNonce
	nonceCases := []string{strings.ToLower(nonce)}
	for _, suffix := range []string{"00", "8C", "FF"} {
		nonceCases = append(nonceCases, nonce+suffix)
	}
	for _, l := range []int{0, 2, 16, 30} {
		nonceCases = append(nonceCases, nonce[:l])
	}
	for _, v := range nonceCases {
		v := v
		cases = append(cases, struct {
			name string
			txt  ShipPairingTXT
		}{"trustNonce=" + v, mutate(func(txt *ShipPairingTXT) { txt.TrustNonce = v })})
	}

	// alg: E11 (variants), E12 (empty)
	for _, v := range []string{"hmacsha256", "hmacSha2561", "hmacSha25", "hmacSha512", ""} {
		v := v
		cases = append(cases, struct {
			name string
			txt  ShipPairingTXT
		}{"alg=" + v, mutate(func(txt *ShipPairingTXT) { txt.Alg = v })})
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, tc.txt.Validate(),
				"malformed value must be rejected by format validation (TC_SPS_TXT_009)")
		})
	}
}
