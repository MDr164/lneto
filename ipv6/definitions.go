package ipv6

import (
	"net/netip"

	"github.com/soypat/lneto/ipv4"
)

const (
	sizeHeader = 40
)

type ToS = ipv4.ToS

// Scope identifies an IPv6 address scope from RFC 4007.
type Scope uint8

const (
	ScopeReserved          Scope = 0x0
	ScopeInterfaceLocal    Scope = 0x1
	ScopeLinkLocal         Scope = 0x2
	ScopeRealmLocal        Scope = 0x3
	ScopeAdminLocal        Scope = 0x4
	ScopeSiteLocal         Scope = 0x5
	ScopeOrganizationLocal Scope = 0x8
	ScopeGlobal            Scope = 0xe
)

// AddrScope returns the RFC 4007 scope for addr.
func AddrScope(addr [16]byte) Scope {
	if IsMulticast(addr) {
		return Scope(addr[1] & 0x0f)
	}
	if addr == ([16]byte{}) {
		return ScopeReserved
	}
	if addr == ([16]byte{15: 1}) {
		return ScopeInterfaceLocal
	}
	if IsLinkLocalUnicast(addr) {
		return ScopeLinkLocal
	}
	return ScopeGlobal
}

// IsMulticast reports whether addr is an IPv6 multicast address.
func IsMulticast(addr [16]byte) bool { return addr[0] == 0xff }

// IsLinkLocalUnicast reports whether addr is an IPv6 link-local unicast address.
func IsLinkLocalUnicast(addr [16]byte) bool { return addr[0] == 0xfe && addr[1]&0xc0 == 0x80 }

// SLAACAddrFromMAC returns the stable IPv6 SLAAC address for prefix and mac.
// The prefix must be an IPv6 /64. The interface identifier is derived using
// the modified EUI-64 format from RFC 4862 Appendix A.
func SLAACAddrFromMAC(prefix netip.Prefix, mac [6]byte) (netip.Addr, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Bits() != 64 {
		return netip.Addr{}, false
	}
	addr := prefix.Masked().Addr().As16()
	addr[8] = mac[0] ^ 0x02
	addr[9] = mac[1]
	addr[10] = mac[2]
	addr[11] = 0xff
	addr[12] = 0xfe
	addr[13] = mac[3]
	addr[14] = mac[4]
	addr[15] = mac[5]
	return netip.AddrFrom16(addr), true
}

// AppendFormatAddr appends the canonical text representation of an IPv6 address
// to dst following RFC 5952 conventions (lowercase hex, :: compression for the
// longest run of consecutive zero groups of length ≥ 2). Zero heap allocations.
func AppendFormatAddr(dst []byte, addr [16]byte) []byte {
	const hexDigits = "0123456789abcdef"

	// Find the longest run of consecutive all-zero 16-bit groups for :: compression.
	bestStart, bestLen := 0, 0
	curStart := -1
	for i := range 8 {
		if addr[i*2] == 0 && addr[i*2+1] == 0 {
			if curStart < 0 {
				curStart = i
			}
			if i-curStart+1 > bestLen {
				bestStart = curStart
				bestLen = i - curStart + 1
			}
		} else {
			curStart = -1
		}
	}
	if bestLen < 2 {
		bestLen = 0 // RFC 5952 §4.2.2: do not compress a single 16-bit group.
	}

	needColon := false
	for i := 0; i < 8; i++ {
		if bestLen > 0 && i == bestStart {
			dst = append(dst, ':', ':')
			i += bestLen - 1 // skip compressed groups; loop increments i.
			needColon = false
			continue
		}
		if needColon {
			dst = append(dst, ':')
		}
		needColon = true
		hi := addr[i*2]
		lo := addr[i*2+1]
		v := uint16(hi)<<8 | uint16(lo)
		if v >= 0x1000 {
			dst = append(dst, hexDigits[hi>>4])
		}
		if v >= 0x100 {
			dst = append(dst, hexDigits[hi&0xf])
		}
		if v >= 0x10 {
			dst = append(dst, hexDigits[lo>>4])
		}
		dst = append(dst, hexDigits[lo&0xf])
	}
	return dst
}
