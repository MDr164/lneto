package ipv6

import (
	"net/netip"
	"testing"
)

func TestAddrScope(t *testing.T) {
	tests := []struct {
		addr string
		want Scope
	}{
		{addr: "::", want: ScopeReserved},
		{addr: "::1", want: ScopeInterfaceLocal},
		{addr: "fe80::1", want: ScopeLinkLocal},
		{addr: "ff01::1", want: ScopeInterfaceLocal},
		{addr: "ff02::1", want: ScopeLinkLocal},
		{addr: "ff05::1", want: ScopeSiteLocal},
		{addr: "ff0e::1", want: ScopeGlobal},
		{addr: "2001:db8::1", want: ScopeGlobal},
	}
	for _, tc := range tests {
		addr := netip.MustParseAddr(tc.addr).As16()
		if got := AddrScope(addr); got != tc.want {
			t.Errorf("AddrScope(%s) = %d, want %d", tc.addr, got, tc.want)
		}
	}
}

func TestIPv6ScopePredicates(t *testing.T) {
	if !IsMulticast(netip.MustParseAddr("ff02::1").As16()) {
		t.Fatal("IsMulticast(ff02::1) = false, want true")
	}
	if IsMulticast(netip.MustParseAddr("fe80::1").As16()) {
		t.Fatal("IsMulticast(fe80::1) = true, want false")
	}
	if !IsLinkLocalUnicast(netip.MustParseAddr("fe80::1").As16()) {
		t.Fatal("IsLinkLocalUnicast(fe80::1) = false, want true")
	}
	if IsLinkLocalUnicast(netip.MustParseAddr("ff02::1").As16()) {
		t.Fatal("IsLinkLocalUnicast(ff02::1) = true, want false")
	}
}

func TestScopedAddr(t *testing.T) {
	linkLocal := netip.MustParseAddr("fe80::1").As16()
	scoped := NewScopedAddr(linkLocal, 3)
	if scoped.Scope() != ScopeLinkLocal || !scoped.HasZone() || scoped.Zone != 3 {
		t.Fatalf("NewScopedAddr link-local = %+v", scoped)
	}
	if got := string(AppendFormatScopedAddr(nil, scoped)); got != "fe80::1%3" {
		t.Fatalf("AppendFormatScopedAddr = %q, want %q", got, "fe80::1%3")
	}
	global := NewScopedAddr(netip.MustParseAddr("2001:db8::1").As16(), 3)
	if global.HasZone() || global.Zone != 0 {
		t.Fatalf("NewScopedAddr global kept zone: %+v", global)
	}
}

func TestAppendFormatScopedAddrNoAllocs(t *testing.T) {
	var buf [64]byte
	addr := NewScopedAddr(netip.MustParseAddr("fe80::1").As16(), 3)
	allocs := testing.AllocsPerRun(100, func() {
		_ = AppendFormatScopedAddr(buf[:0], addr)
	})
	if allocs != 0 {
		t.Errorf("expected 0 allocs, got %v", allocs)
	}
}

func TestSelectSourceAddr(t *testing.T) {
	dst := netip.MustParseAddr("2001:db8:1::99").As16()
	candidates := []SourceCandidate{
		{Addr: netip.MustParseAddr("2001:db8:2::1").As16()},
		{Addr: netip.MustParseAddr("2001:db8:1::1").As16()},
	}
	idx, ok := SelectSourceAddr(candidates, dst)
	if !ok || idx != 1 {
		t.Fatalf("SelectSourceAddr longest prefix = %d, %v, want 1, true", idx, ok)
	}
}

func TestSelectSourceAddrRules(t *testing.T) {
	tests := []struct {
		name       string
		dst        string
		candidates []SourceCandidate
		want       int
	}{
		{
			name: "same address",
			dst:  "2001:db8::1",
			candidates: []SourceCandidate{
				{Addr: netip.MustParseAddr("2001:db8::2").As16()},
				{Addr: netip.MustParseAddr("2001:db8::1").As16()},
			},
			want: 1,
		},
		{
			name: "avoid deprecated",
			dst:  "2001:db8::99",
			candidates: []SourceCandidate{
				{Addr: netip.MustParseAddr("2001:db8::1").As16(), Deprecated: true},
				{Addr: netip.MustParseAddr("2001:db8::2").As16()},
			},
			want: 1,
		},
		{
			name: "scope",
			dst:  "2001:db8::99",
			candidates: []SourceCandidate{
				{Addr: netip.MustParseAddr("fe80::1").As16()},
				{Addr: netip.MustParseAddr("2001:db8::1").As16()},
			},
			want: 1,
		},
		{
			name: "label",
			dst:  "fd00::99",
			candidates: []SourceCandidate{
				{Addr: netip.MustParseAddr("2001:db8::1").As16()},
				{Addr: netip.MustParseAddr("fd00::1").As16()},
			},
			want: 1,
		},
		{
			name: "avoid temporary",
			dst:  "2001:db8::99",
			candidates: []SourceCandidate{
				{Addr: netip.MustParseAddr("2001:db8::1").As16(), Temporary: true},
				{Addr: netip.MustParseAddr("2001:db8::2").As16()},
			},
			want: 1,
		},
	}
	for _, tc := range tests {
		idx, ok := SelectSourceAddr(tc.candidates, netip.MustParseAddr(tc.dst).As16())
		if !ok || idx != tc.want {
			t.Errorf("%s: SelectSourceAddr = %d, %v, want %d, true", tc.name, idx, ok, tc.want)
		}
	}
}

func TestSLAACAddrFromMAC(t *testing.T) {
	addr, ok := SLAACAddrFromMAC(netip.MustParsePrefix("2001:db8:1:2::/64"), [6]byte{0x00, 0x25, 0x96, 0x12, 0x34, 0x56})
	if !ok {
		t.Fatal("SLAACAddrFromMAC returned ok=false")
	}
	want := netip.MustParseAddr("2001:db8:1:2:225:96ff:fe12:3456")
	if addr != want {
		t.Fatalf("SLAACAddrFromMAC = %s, want %s", addr, want)
	}
}

func TestSLAACAddrFromMACInvalidPrefix(t *testing.T) {
	if _, ok := SLAACAddrFromMAC(netip.MustParsePrefix("2001:db8::/48"), [6]byte{1, 2, 3, 4, 5, 6}); ok {
		t.Fatal("SLAACAddrFromMAC /48 ok=true, want false")
	}
	if _, ok := SLAACAddrFromMAC(netip.MustParsePrefix("192.0.2.0/24"), [6]byte{1, 2, 3, 4, 5, 6}); ok {
		t.Fatal("SLAACAddrFromMAC IPv4 ok=true, want false")
	}
}

func TestSLAACAddrFromMACNoAllocs(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:1:2::/64")
	mac := [6]byte{0x00, 0x25, 0x96, 0x12, 0x34, 0x56}
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = SLAACAddrFromMAC(prefix, mac)
	})
	if allocs != 0 {
		t.Errorf("expected 0 allocs, got %v", allocs)
	}
}

func TestAppendFormatAddr(t *testing.T) {
	tests := []struct {
		addr [16]byte
		want string
	}{
		// All zeros → "::".
		{addr: [16]byte{}, want: "::"},
		// Loopback → "::1".
		{addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, want: "::1"},
		// Full address, no compression.
		{addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06}, want: "2001:db8:1:2:3:4:5:6"},
		// Trailing zero run.
		{addr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, want: "fe80::"},
		// Leading non-zero + middle compression.
		{addr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, want: "2001:db8::1"},
		// Link-local with interface ID.
		{addr: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, want: "fe80::1"},
		// Two zero runs; compress the longer one (groups 3-6 len=4 vs group 1 len=1).
		{addr: [16]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, want: "2001:0:1::1"},
		// Single zero group should NOT compress (RFC 5952 §4.2.2).
		{addr: [16]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06}, want: "1:0:1:2:3:4:5:6"},
		// All ff → no compression.
		{addr: [16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		// IPv4-mapped ::ffff:192.168.1.1 — we format as pure hex groups.
		{addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01}, want: "::ffff:c0a8:101"},
		// Two equal-length zero runs; first one wins.
		{addr: [16]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, want: "1::1:2:0:0:1"},
	}

	for _, tc := range tests {
		got := string(AppendFormatAddr(nil, tc.addr))
		if got != tc.want {
			t.Errorf("AppendFormatAddr(%v):\n got  %q\n want %q", tc.addr, got, tc.want)
		}
	}
}

func TestAppendFormatAddr_matchesNetip(t *testing.T) {
	// Verify output matches netip.Addr.AppendTo for non-IPv4-mapped addresses.
	addrs := [][16]byte{
		{},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01},
		{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb},
		{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	for _, addr := range addrs {
		got := string(AppendFormatAddr(nil, addr))
		want := netip.AddrFrom16(addr).String()
		if got != want {
			t.Errorf("mismatch for %v:\n got  %q\n want %q", addr, got, want)
		}
	}
}

func TestAppendFormatAddr_noAllocs(t *testing.T) {
	var buf [64]byte
	addr := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	allocs := testing.AllocsPerRun(100, func() {
		_ = AppendFormatAddr(buf[:0], addr)
	})
	if allocs != 0 {
		t.Errorf("expected 0 allocs, got %v", allocs)
	}
}
