package ipv6

import (
	"net/netip"
	"strconv"

	"github.com/soypat/lneto/ipv4"
)

const (
	sizeHeader = 40
)

type ToS = ipv4.ToS

// ScopedAddr is an IPv6 address with an RFC 4007 numeric zone identifier.
type ScopedAddr struct {
	Addr [16]byte
	Zone uint32
}

// SourceCandidate describes a candidate source address for RFC 6724 selection.
type SourceCandidate struct {
	Addr       [16]byte
	Deprecated bool
	Temporary  bool
}

// DestinationCandidate describes a candidate destination address and the source
// address selected for reaching it.
type DestinationCandidate struct {
	Addr     [16]byte
	Source   SourceCandidate
	SourceOK bool
}

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

// NewScopedAddr returns addr with zone. A non-zero zone is only meaningful for
// non-global scopes; global addresses are returned with zone zero.
func NewScopedAddr(addr [16]byte, zone uint32) ScopedAddr {
	if AddrScope(addr) == ScopeGlobal {
		zone = 0
	}
	return ScopedAddr{Addr: addr, Zone: zone}
}

// Scope returns the RFC 4007 scope of addr.
func (addr ScopedAddr) Scope() Scope { return AddrScope(addr.Addr) }

// HasZone reports whether addr has a zone identifier.
func (addr ScopedAddr) HasZone() bool { return addr.Zone != 0 }

// AppendFormatScopedAddr appends addr as an IPv6 address with a numeric zone
// identifier when present.
func AppendFormatScopedAddr(dst []byte, addr ScopedAddr) []byte {
	dst = AppendFormatAddr(dst, addr.Addr)
	if addr.Zone != 0 {
		dst = append(dst, '%')
		dst = strconv.AppendUint(dst, uint64(addr.Zone), 10)
	}
	return dst
}

// SelectSourceAddr returns the best source address candidate for dst using the
// RFC 6724 source address selection rules that are meaningful without route or
// interface state.
func SelectSourceAddr(candidates []SourceCandidate, dst [16]byte) (idx int, ok bool) {
	if len(candidates) == 0 {
		return 0, false
	}
	best := 0
	for i := 1; i < len(candidates); i++ {
		if preferSource(candidates[i], candidates[best], dst) {
			best = i
		}
	}
	return best, true
}

// SortDestinationAddrs orders candidates in-place using RFC 6724 destination
// address selection rules that are meaningful without route probing state.
func SortDestinationAddrs(candidates []DestinationCandidate) {
	for i := 1; i < len(candidates); i++ {
		c := candidates[i]
		j := i - 1
		for ; j >= 0 && preferDestination(c, candidates[j]); j-- {
			candidates[j+1] = candidates[j]
		}
		candidates[j+1] = c
	}
}

func preferDestination(a, b DestinationCandidate) bool {
	aUsable := a.SourceOK && AddrScope(a.Source.Addr) >= AddrScope(a.Addr)
	bUsable := b.SourceOK && AddrScope(b.Source.Addr) >= AddrScope(b.Addr)
	if aUsable != bUsable {
		return aUsable
	}
	aMatchScope := a.SourceOK && AddrScope(a.Source.Addr) == AddrScope(a.Addr)
	bMatchScope := b.SourceOK && AddrScope(b.Source.Addr) == AddrScope(b.Addr)
	if aMatchScope != bMatchScope {
		return aMatchScope
	}
	aDeprecated := a.SourceOK && a.Source.Deprecated
	bDeprecated := b.SourceOK && b.Source.Deprecated
	if aDeprecated != bDeprecated {
		return !aDeprecated
	}
	aLabel := !a.SourceOK || addrLabel(a.Source.Addr) == addrLabel(a.Addr)
	bLabel := !b.SourceOK || addrLabel(b.Source.Addr) == addrLabel(b.Addr)
	if aLabel != bLabel {
		return aLabel
	}
	aPrec := addrPrecedence(a.Addr)
	bPrec := addrPrecedence(b.Addr)
	if aPrec != bPrec {
		return aPrec > bPrec
	}
	aScope := AddrScope(a.Addr)
	bScope := AddrScope(b.Addr)
	if aScope != bScope {
		return aScope < bScope
	}
	if a.SourceOK && b.SourceOK {
		return commonPrefixLen(a.Source.Addr, a.Addr) > commonPrefixLen(b.Source.Addr, b.Addr)
	}
	return false
}

func preferSource(a, b SourceCandidate, dst [16]byte) bool {
	if a.Addr == dst && b.Addr != dst {
		return true
	}
	if b.Addr == dst && a.Addr != dst {
		return false
	}
	dstScope := AddrScope(dst)
	aUsable := AddrScope(a.Addr) >= dstScope
	bUsable := AddrScope(b.Addr) >= dstScope
	if aUsable != bUsable {
		return aUsable
	}
	if a.Deprecated != b.Deprecated {
		return !a.Deprecated
	}
	dstLabel := addrLabel(dst)
	aLabelMatch := addrLabel(a.Addr) == dstLabel
	bLabelMatch := addrLabel(b.Addr) == dstLabel
	if aLabelMatch != bLabelMatch {
		return aLabelMatch
	}
	if a.Temporary != b.Temporary {
		return !a.Temporary
	}
	return commonPrefixLen(a.Addr, dst) > commonPrefixLen(b.Addr, dst)
}

func addrPrecedence(addr [16]byte) uint8 {
	switch {
	case addr == ([16]byte{15: 1}):
		return 50
	case isIPv4Mapped(addr):
		return 35
	case addr[0] == 0x20 && addr[1] == 0x02:
		return 30
	case addr[0] == 0x20 && addr[1] == 0x01 && addr[2] == 0 && addr[3] == 0:
		return 5
	case addr[0] == 0xfc || addr[0] == 0xfd:
		return 3
	default:
		return 40
	}
}

func addrLabel(addr [16]byte) uint8 {
	switch {
	case addr == ([16]byte{15: 1}):
		return 0
	case addr[0] == 0xfc || addr[0] == 0xfd:
		return 13
	case addr[0] == 0x20 && addr[1] == 0x02:
		return 2
	case addr[0] == 0x20 && addr[1] == 0x01 && addr[2] == 0 && addr[3] == 0:
		return 5
	case isIPv4Mapped(addr):
		return 4
	default:
		return 1
	}
}

func isIPv4Mapped(addr [16]byte) bool {
	return addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
		addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
		addr[8] == 0 && addr[9] == 0 && addr[10] == 0xff && addr[11] == 0xff
}

func commonPrefixLen(a, b [16]byte) int {
	bits := 0
	for i := range a {
		x := a[i] ^ b[i]
		if x == 0 {
			bits += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if x&mask != 0 {
				return bits
			}
			bits++
		}
	}
	return bits
}

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
