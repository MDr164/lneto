package xnet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dhcp/dhcpv6"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/internet"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/ipv6/icmpv6"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

const (
	ipv6HeaderSize = 40
	mtu6Test       = 1500
	maxFrame6      = ipv6HeaderSize + mtu6Test
)

func stack6PairConfigs(seed int64, maxports, icmpQueue uint16) (cfg1, cfg2 StackConfig) {
	var (
		testAddr6A = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} // 2001:db8::1
		testAddr6B = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2} // 2001:db8::2
		testMAC6A  = [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
		testMAC6B  = [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	)
	cfg1 = StackConfig{
		Hostname:          "stack6-1",
		RandSeed:          seed,
		StaticAddress6:    testAddr6A,
		HardwareAddress:   testMAC6A,
		MTU:               mtu6Test,
		MaxActiveUDPPorts: maxports,
		MaxActiveTCPPorts: maxports,
		ICMPQueueLimit:    int(icmpQueue),
	}
	cfg2 = StackConfig{
		Hostname:          "stack6-2",
		RandSeed:          ^seed,
		StaticAddress6:    testAddr6B,
		HardwareAddress:   testMAC6B,
		MTU:               mtu6Test,
		MaxActiveUDPPorts: maxports,
		MaxActiveTCPPorts: maxports,
		ICMPQueueLimit:    int(icmpQueue),
	}
	return cfg1, cfg2
}

// newStack6Pair creates two stack6 instances with distinct IPv6 addresses and MACs.
// ICMPQueueLimit is zero so NDP is disabled; DialUDP6/DialTCP6 skip MAC filtering.
func newStack6Pair(t testing.TB, seed int64, maxports, icmpQueue uint16) (s1, s2 Stack6) {
	t.Helper()
	cfg1, cfg2 := stack6PairConfigs(seed, maxports, icmpQueue)
	s1 = DefaultStack6()
	s2 = DefaultStack6()
	if err := s1.Reset6(&cfg1); err != nil {
		t.Fatal("s1 Reset6:", err)
	}
	if err := s2.Reset6(&cfg2); err != nil {
		t.Fatal("s2 Reset6:", err)
	}
	return s1, s2
}

// newUDPConn6 allocates and configures a udp.Conn for use with stack6.
func newUDPConn6(t testing.TB) *udp.Conn {
	t.Helper()
	const bufSize = 2048
	conn := new(udp.Conn)
	if err := conn.Configure(udp.ConnConfig{
		RxBuf:       make([]byte, bufSize),
		TxBuf:       make([]byte, bufSize),
		RxQueueSize: 4,
		TxQueueSize: 4,
		RWBackoff:   backoffYield,
	}); err != nil {
		t.Fatal("UDP Configure:", err)
	}
	return conn
}

// newTCPConn6 allocates and configures a tcp.Conn for use with stack6.
func newTCPConn6(t testing.TB) *tcp.Conn {
	t.Helper()
	const bufSize = 2048
	conn := new(tcp.Conn)
	if err := conn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, bufSize),
		TxBuf:             make([]byte, bufSize),
		TxPacketQueueSize: 4,
		RWBackoff:         backoffYield,
	}); err != nil {
		t.Fatal("TCP Configure:", err)
	}
	return conn
}

// exchangeIPv6Once encapsulates one IPv6 frame from src and delivers it to dst.
// Returns the number of bytes written (0 if src had nothing to send).
func exchangeIPv6Once(t testing.TB, src, dst Stack6, buf []byte) int {
	t.Helper()
	n, err := src.EgressIPv6(buf)
	if err != nil {
		t.Error("EgressIPv6:", err)
		return 0
	}
	if n == 0 {
		return 0
	}
	if err := dst.IngressIPv6(buf[:n]); err != nil {
		t.Error("IngressIPv6:", err)
	}
	return n
}

type dhcpv6ServerTestNode struct {
	connID       uint64
	xid          uint32
	requestSeen  bool
	assignedAddr [16]byte
	dnsServer    [16]byte
	domainSearch []byte
	ntpServer    [16]byte
	ntpMulticast [16]byte
	ntpName      []byte
	delegated    netip.Prefix
	clientIAID   [4]byte
}

func (sv *dhcpv6ServerTestNode) Encapsulate(carrierData []byte, _, offsetToFrame int) (int, error) {
	if sv.xid == 0 {
		return 0, nil
	}
	msg := dhcpv6.MsgAdvertise
	if sv.requestSeen {
		msg = dhcpv6.MsgReply
	}
	n := appendDHCPv6ServerFrame(carrierData[offsetToFrame:], msg, sv.xid, sv.clientIAID, sv.assignedAddr, sv.dnsServer, sv.domainSearch, sv.ntpServer, sv.ntpMulticast, sv.ntpName, sv.delegated)
	if sv.requestSeen {
		sv.xid = 0
	}
	return n, nil
}

func (sv *dhcpv6ServerTestNode) Demux(carrierData []byte, frameOffset int) error {
	frm, err := dhcpv6.NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	sv.xid = frm.TransactionID()
	sv.requestSeen = frm.MsgType() == dhcpv6.MsgRequest
	return frm.ForEachOption(func(_ int, code dhcpv6.OptCode, data []byte) error {
		if code == dhcpv6.OptIANA && len(data) >= 4 {
			sv.clientIAID = [4]byte(data[:4])
		}
		return nil
	})
}

func (sv *dhcpv6ServerTestNode) LocalPort() uint16 { return dhcpv6.ServerPort }
func (sv *dhcpv6ServerTestNode) Protocol() uint64  { return uint64(lneto.IPProtoUDP) }
func (sv *dhcpv6ServerTestNode) ConnectionID() *uint64 {
	if sv.connID == 0 {
		sv.connID = 1
	}
	return &sv.connID
}

func appendDHCPv6ServerFrame(dst []byte, msg dhcpv6.MsgType, xid uint32, iaid [4]byte, assigned, dnssv [16]byte, domainSearch []byte, ntp, ntpMulticast [16]byte, ntpName []byte, delegated netip.Prefix) int {
	dst[0] = byte(msg)
	dst[1] = byte(xid >> 16)
	dst[2] = byte(xid >> 8)
	dst[3] = byte(xid)
	n := dhcpv6.OptionsOffset
	n += writeDHCPv6Opt(dst[n:], dhcpv6.OptServerID, []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6})
	var iaaddr [28]byte
	binary.BigEndian.PutUint16(iaaddr[:2], uint16(dhcpv6.OptIAAddr))
	binary.BigEndian.PutUint16(iaaddr[2:4], 24)
	copy(iaaddr[4:20], assigned[:])
	binary.BigEndian.PutUint32(iaaddr[20:24], 1800)
	binary.BigEndian.PutUint32(iaaddr[24:28], 3600)
	var iana [40]byte
	copy(iana[:4], iaid[:])
	binary.BigEndian.PutUint32(iana[4:8], 900)
	binary.BigEndian.PutUint32(iana[8:12], 1800)
	copy(iana[12:], iaaddr[:])
	n += writeDHCPv6Opt(dst[n:], dhcpv6.OptIANA, iana[:])
	n += writeDHCPv6Opt(dst[n:], dhcpv6.OptDNSServers, dnssv[:])
	if len(domainSearch) > 0 {
		n += writeDHCPv6Opt(dst[n:], dhcpv6.OptDomainList, domainSearch)
	}
	if ntp != ([16]byte{}) {
		var ntpPayload []byte
		ntpPayload = appendNTPServerAddrSuboption6(ntpPayload, 1, ntp)
		if ntpMulticast != ([16]byte{}) {
			ntpPayload = appendNTPServerAddrSuboption6(ntpPayload, 2, ntpMulticast)
		}
		if len(ntpName) > 0 {
			nameStart := len(ntpPayload) + 4
			ntpPayload = append(ntpPayload, 0, 3, 0, 0)
			ntpPayload = append(ntpPayload, ntpName...)
			binary.BigEndian.PutUint16(ntpPayload[nameStart-2:nameStart], uint16(len(ntpPayload)-nameStart))
		}
		n += writeDHCPv6Opt(dst[n:], dhcpv6.OptNTPServer, ntpPayload)
	}
	if delegated.IsValid() {
		var iaPrefix [29]byte
		binary.BigEndian.PutUint16(iaPrefix[0:2], uint16(dhcpv6.OptIAPrefix))
		binary.BigEndian.PutUint16(iaPrefix[2:4], 25)
		binary.BigEndian.PutUint32(iaPrefix[4:8], 1800)
		binary.BigEndian.PutUint32(iaPrefix[8:12], 3600)
		iaPrefix[12] = byte(delegated.Bits())
		prefixAddr := delegated.Addr().As16()
		copy(iaPrefix[13:], prefixAddr[:])
		var iapd [41]byte
		copy(iapd[:4], iaid[:])
		binary.BigEndian.PutUint32(iapd[4:8], 900)
		binary.BigEndian.PutUint32(iapd[8:12], 1800)
		copy(iapd[12:], iaPrefix[:])
		n += writeDHCPv6Opt(dst[n:], dhcpv6.OptIAPD, iapd[:])
	}
	return n
}

func appendNTPServerAddrSuboption6(dst []byte, code uint16, addr [16]byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0, 0, 16)
	binary.BigEndian.PutUint16(dst[start:start+2], code)
	return append(dst, addr[:]...)
}

func writeDHCPv6Opt(dst []byte, code dhcpv6.OptCode, data []byte) int {
	binary.BigEndian.PutUint16(dst[:2], uint16(code))
	binary.BigEndian.PutUint16(dst[2:4], uint16(len(data)))
	copy(dst[4:], data)
	return 4 + len(data)
}

// listenTCP6 opens a passive TCP connection and registers it with a stack6 directly,
// mirroring what StackAsync.ListenTCP4 does for IPv4.
func listenTCP6(t testing.TB, s Stack6, conn *tcp.Conn, localPort uint16, iss tcp.Value) {
	t.Helper()
	if err := conn.OpenListen(localPort, iss); err != nil {
		t.Fatal("OpenListen:", err)
	}
	if err := s.(*stack6).tcps6.RegisterMACFiltered(conn, nil); err != nil {
		conn.Abort()
		t.Fatal("RegisterMACFiltered:", err)
	}
}

// ===== Tests =====

func TestStack6Reset(t *testing.T) {
	s := DefaultStack6()
	testMAC6A := [6]byte{1, 2, 3}
	testAddr6A := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	err := s.Reset6(&StackConfig{
		Hostname:        "reset-test-1",
		RandSeed:        42,
		StaticAddress6:  testAddr6A,
		HardwareAddress: testMAC6A,
		MTU:             mtu6Test,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Addr6(); got != testAddr6A {
		t.Errorf("Addr6 = %v, want %v", got, testAddr6A)
	}
	testAddr2 := testAddr6A
	testAddr2[15] = 2
	// SetAddr6 must update the returned address.
	s.SetAddr6(testAddr2)
	if got := s.Addr6(); got != testAddr2 {
		t.Errorf("after SetAddr6: got %v, want %v", got, testAddr2)
	}
}

func TestStack6Reset_ICMPConfigured(t *testing.T) {
	s := DefaultStack6()
	err := s.Reset6(&StackConfig{
		Hostname:       "icmp-cfg-1",
		RandSeed:       1337,
		MTU:            mtu6Test,
		ICMPQueueLimit: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	// EnableICMP6 should succeed since the client was configured.
	if err := s.EnableICMP6(true); err != nil {
		t.Fatal("EnableICMP6:", err)
	}
	// Disable should always succeed.
	if err := s.EnableICMP6(false); err != nil {
		t.Fatal("EnableICMP6(false):", err)
	}
}

func TestStack6ApplyRouterAdvertisementSLAAC(t *testing.T) {
	cfg := StackConfig{
		Hostname:        "slaac-test",
		RandSeed:        1,
		HardwareAddress: [6]byte{0x00, 0x25, 0x96, 0x12, 0x34, 0x56},
		ICMPQueueLimit:  1,
	}
	s := DefaultStack6()
	if err := s.Reset6(&cfg); err != nil {
		t.Fatal(err)
	}
	opt := makeRouterAdvertisementPrefixOption(netip.MustParsePrefix("2001:db8:1:2::/64"), 3600, 1800, true)
	addr, ok, err := s.ApplyRouterAdvertisement6(opt[:])
	if err != nil {
		t.Fatal(err)
	}
	want := netip.MustParseAddr("2001:db8:1:2:225:96ff:fe12:3456")
	if !ok || addr != want {
		t.Fatalf("ApplyRouterAdvertisement6 = %s, %v, want %s, true", addr, ok, want)
	}
	if got := netip.AddrFrom16(s.Addr6()); got != want {
		t.Fatalf("Addr6 = %s, want %s", got, want)
	}
}

func makeRouterAdvertisementPrefixOption(prefix netip.Prefix, valid, preferred uint32, autonomous bool) [32]byte {
	var buf [32]byte
	buf[0] = icmpv6.OptPrefixInformation
	buf[1] = 4
	buf[2] = byte(prefix.Bits())
	if autonomous {
		buf[3] = 0x40
	}
	binary.BigEndian.PutUint32(buf[4:8], valid)
	binary.BigEndian.PutUint32(buf[8:12], preferred)
	addr := prefix.Addr().As16()
	copy(buf[16:], addr[:])
	return buf
}

// TestStack6UDP_DataExchange sends a datagram from stack A to stack B and reads it back.
// Both stacks are configured without ICMP so NDP/MAC-filtering is bypassed.
func TestStack6UDP_DataExchange(t *testing.T) {
	const (
		rngseed = 100
		portA   = 5001
		portB   = 5002
		nports  = 2
	)
	s1, s2 := newStack6Pair(t, rngseed, nports, 0)
	buf := make([]byte, maxFrame6)

	connA := newUDPConn6(t)
	connB := newUDPConn6(t)

	// Open A -> B direction.
	if err := s1.DialUDP6(connA, portA, s2.Addr6(), portB); err != nil {
		t.Fatal("DialUDP6 A:", err)
	}
	// Open B -> A direction so B's stack accepts datagrams from A.
	if err := s2.DialUDP6(connB, portB, s1.Addr6(), portA); err != nil {
		t.Fatal("DialUDP6 B:", err)
	}

	want := []byte("hello ipv6 udp")
	if _, err := connA.Write(want); err != nil {
		t.Fatal("Write:", err)
	}
	if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
		t.Fatal("expected packet from A to B")
	}

	var rbuf [256]byte
	n, err := connB.Read(rbuf[:])
	if err != nil {
		t.Fatal("Read:", err)
	}
	if !bytes.Equal(rbuf[:n], want) {
		t.Errorf("got %q, want %q", rbuf[:n], want)
	}
}

func TestStack6UDP_DestinationOptionsDemux(t *testing.T) {
	const (
		rngseed = 101
		portA   = 5101
		portB   = 5102
		nports  = 2
	)
	s1, s2 := newStack6Pair(t, rngseed, nports, 0)
	buf := make([]byte, maxFrame6)

	connA := newUDPConn6(t)
	connB := newUDPConn6(t)
	if err := s1.DialUDP6(connA, portA, s2.Addr6(), portB); err != nil {
		t.Fatal("DialUDP6 A:", err)
	}
	if err := s2.DialUDP6(connB, portB, s1.Addr6(), portA); err != nil {
		t.Fatal("DialUDP6 B:", err)
	}

	want := []byte("hello with destopts")
	if _, err := connA.Write(want); err != nil {
		t.Fatal("Write:", err)
	}
	n, err := s1.EgressIPv6(buf)
	if err != nil {
		t.Fatal("EgressIPv6:", err)
	}
	if n == 0 {
		t.Fatal("expected packet from A to B")
	}
	n = insertIPv6DestinationOptions(t, buf, n)
	if err := s2.IngressIPv6(buf[:n]); err != nil {
		t.Fatal("IngressIPv6 with destination options:", err)
	}

	var rbuf [256]byte
	rn, err := connB.Read(rbuf[:])
	if err != nil {
		t.Fatal("Read:", err)
	}
	if !bytes.Equal(rbuf[:rn], want) {
		t.Errorf("got %q, want %q", rbuf[:rn], want)
	}
}

func insertIPv6DestinationOptions(t testing.TB, buf []byte, n int) int {
	t.Helper()
	const (
		ipHeaderLen  = 40
		extHeaderLen = 8
	)
	if len(buf) < n+extHeaderLen {
		t.Fatal("short test buffer")
	}
	ifrm, err := ipv6.NewFrame(buf[:n+extHeaderLen])
	if err != nil {
		t.Fatal(err)
	}
	oldPayloadLen := ifrm.PayloadLength()
	copy(buf[ipHeaderLen+extHeaderLen:n+extHeaderLen], buf[ipHeaderLen:n])
	ifrm.SetNextHeader(lneto.IPProtoIPv6Opts)
	ifrm.SetPayloadLength(oldPayloadLen + extHeaderLen)
	buf[ipHeaderLen] = byte(lneto.IPProtoUDP)
	buf[ipHeaderLen+1] = 0
	ufrm, err := udp.NewFrame(buf[ipHeaderLen+extHeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	ufrm.SetCRC(0)
	var crc lneto.CRC791
	ifrm.CRCWritePseudoNext(&crc, lneto.IPProtoUDP, uint32(ufrm.Length()))
	ufrm.SetCRC(lneto.NeverZeroSum(crc.PayloadSum16(ufrm.RawData()[:ufrm.Length()])))
	return n + extHeaderLen
}

// TestStack6UDP_BidirectionalExchange verifies that both sides can send and receive.
func TestStack6UDP_BidirectionalExchange(t *testing.T) {
	const (
		rngseed = 100
		nports  = 1
		portA   = 6001
		portB   = 6002
	)
	s1, s2 := newStack6Pair(t, rngseed, nports, 0)
	buf := make([]byte, maxFrame6)

	connA := newUDPConn6(t)
	connB := newUDPConn6(t)

	if err := s1.DialUDP6(connA, portA, s2.Addr6(), portB); err != nil {
		t.Fatal("DialUDP6 A:", err)
	}
	if err := s2.DialUDP6(connB, portB, s1.Addr6(), portA); err != nil {
		t.Fatal("DialUDP6 B:", err)
	}

	// A -> B
	msgAtoB := []byte("A->B")
	if _, err := connA.Write(msgAtoB); err != nil {
		t.Fatal("Write A->B:", err)
	}
	if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
		t.Fatal("expected packet A->B")
	}
	var rbuf [256]byte
	n, err := connB.Read(rbuf[:])
	if err != nil {
		t.Fatal("Read B:", err)
	}
	if !bytes.Equal(rbuf[:n], msgAtoB) {
		t.Errorf("B received %q, want %q", rbuf[:n], msgAtoB)
	}

	// B -> A
	msgBtoA := []byte("B->A reply")
	if _, err := connB.Write(msgBtoA); err != nil {
		t.Fatal("Write B->A:", err)
	}
	if n := exchangeIPv6Once(t, s2, s1, buf); n == 0 {
		t.Fatal("expected packet B->A")
	}
	n, err = connA.Read(rbuf[:])
	if err != nil {
		t.Fatal("Read A:", err)
	}
	if !bytes.Equal(rbuf[:n], msgBtoA) {
		t.Errorf("A received %q, want %q", rbuf[:n], msgBtoA)
	}
}

func TestStack6DHCPv6Request(t *testing.T) {
	const rngseed = 12345
	client, server := newStack6Pair(t, rngseed, 0, 0)
	assigned := [16]byte{0xfd, 0, 0x4e, 0x42, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}
	dnssv := [16]byte{0xfd, 0, 0x4e, 0x42, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53}
	ntp := [16]byte{0xfd, 0, 0x4e, 0x42, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123}
	ntpMulticast := [16]byte{0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01}
	ntpName := appendDomainSearchList6(t, "time.example.com")
	delegated := netip.MustParsePrefix("fd00:4e42:2::/48")
	domainSearch := appendDomainSearchList6(t, "example.com", "corp.example.com")
	sv := &dhcpv6ServerTestNode{assignedAddr: assigned, dnsServer: dnssv, domainSearch: domainSearch, ntpServer: ntp, ntpMulticast: ntpMulticast, ntpName: ntpName, delegated: delegated}
	var svUDP internet.StackUDPPort
	svUDP.SetStackNode(sv, nil, dhcpv6.ClientPort)
	if err := server.(*stack6).udps6.RegisterMACFiltered(&svUDP, nil); err != nil {
		t.Fatal("register DHCPv6 server:", err)
	}

	if err := client.StartDHCPv6Request(); err != nil {
		t.Fatal("StartDHCPv6Request:", err)
	}
	buf := make([]byte, maxFrame6)
	for i := range 4 {
		if i%2 == 0 {
			exchangeIPv6Once(t, client, server, buf)
		} else {
			exchangeIPv6Once(t, server, client, buf)
		}
	}

	got, err := client.ResultDHCPv6()
	if err != nil {
		t.Fatal("ResultDHCPv6:", err)
	}
	if got.AssignedAddr6 != assigned {
		t.Errorf("AssignedAddr6 = %v, want %v", got.AssignedAddr6, assigned)
	}
	if got.TRenewal != 900 || got.TRebind != 1800 || got.TPreferred != 1800 || got.TValid != 3600 {
		t.Errorf("timers = renewal:%d rebind:%d preferred:%d valid:%d", got.TRenewal, got.TRebind, got.TPreferred, got.TValid)
	}
	if len(got.DNSServers) != 1 || got.DNSServers[0] != netip.AddrFrom16(dnssv) {
		t.Errorf("DNSServers = %v, want %v", got.DNSServers, netip.AddrFrom16(dnssv))
	}
	if len(got.DomainSearch) != 2 || !got.DomainSearch[0].EqualString("example.com") || !got.DomainSearch[1].EqualString("corp.example.com") {
		t.Errorf("DomainSearch = %v", got.DomainSearch)
	}
	if len(got.NTPServers) != 1 || got.NTPServers[0] != netip.AddrFrom16(ntp) {
		t.Errorf("NTPServers = %v, want %v", got.NTPServers, netip.AddrFrom16(ntp))
	}
	if len(got.NTPMulticast) != 1 || got.NTPMulticast[0] != netip.AddrFrom16(ntpMulticast) {
		t.Errorf("NTPMulticast = %v, want %v", got.NTPMulticast, netip.AddrFrom16(ntpMulticast))
	}
	if len(got.NTPNames) != 1 || !got.NTPNames[0].EqualString("time.example.com") {
		t.Errorf("NTPNames = %v", got.NTPNames)
	}
	if len(got.Delegated) != 1 || got.Delegated[0].Prefix != delegated || got.Delegated[0].PreferredLifetime != 1800 || got.Delegated[0].ValidLifetime != 3600 {
		t.Errorf("Delegated = %+v", got.Delegated)
	}
	if got.TPDRenewal != 900 || got.TPDRebind != 1800 {
		t.Errorf("IA_PD timers = renewal:%d rebind:%d, want 900/1800", got.TPDRenewal, got.TPDRebind)
	}
}

func TestStackAsyncAssimilateDHCPv6Results(t *testing.T) {
	assigned := [16]byte{0xfd, 0, 0x4e, 0x42, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}
	dnssv := netip.MustParseAddr("fd00:4e42:1::53")
	var stack StackAsync
	if err := stack.Reset(StackConfig{
		Hostname:          "async6-1",
		RandSeed:          1,
		HardwareAddress:   [6]byte{1, 2, 3, 4, 5, 6},
		IPv6Stack:         DefaultStack6(),
		MTU:               mtu6Test,
		MaxActiveUDPPorts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	err := stack.AssimilateDHCPv6Results(&DHCPResultsV6{
		AssignedAddr6: assigned,
		DNSServers:    []netip.Addr{dnssv},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := stack.Addr6(); got != assigned {
		t.Fatalf("Addr6 = %v, want %v", got, assigned)
	}
	if stack.dnssv != dnssv {
		t.Fatalf("dnssv = %v, want %v", stack.dnssv, dnssv)
	}
}

func appendDomainSearchList6(t testing.TB, domains ...string) []byte {
	t.Helper()
	var payload []byte
	for _, domain := range domains {
		name, err := dns.NewName(domain)
		if err != nil {
			t.Fatal(err)
		}
		payload, err = name.AppendTo(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	return payload
}

// TestStack6ICMPv6_PingEcho verifies a full ICMPv6 echo request/reply exchange.
func TestStack6ICMPv6_PingEcho(t *testing.T) {
	const (
		rngSeed   = 42
		nports    = 1
		icmpQueue = 2
	)
	s1, s2 := newStack6Pair(t, rngSeed, nports, icmpQueue)
	buf := make([]byte, maxFrame6)

	if err := s1.EnableICMP6(true); err != nil {
		t.Fatal("s1 EnableICMP6:", err)
	}
	if err := s2.EnableICMP6(true); err != nil {
		t.Fatal("s2 EnableICMP6:", err)
	}

	// Verify that no packets are pending before the ping.
	if n, _ := s1.EgressIPv6(buf); n != 0 {
		t.Fatal("unexpected egress from s1 before ping")
	}
	if n, _ := s2.EgressIPv6(buf); n != 0 {
		t.Fatal("unexpected egress from s2 before ping")
	}

	// Start the ping from s1 to s2.
	pattern := []byte("ping6test")
	key, err := s1.(*stack6).icmp6.PingStart(s2.Addr6(), pattern, 32)
	if err != nil {
		t.Fatal("PingStart:", err)
	}

	// s1 sends echo request to s2.
	if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
		t.Fatal("expected ICMPv6 echo request from s1")
	}

	// s2 sends echo reply back to s1.
	if n := exchangeIPv6Once(t, s2, s1, buf); n == 0 {
		t.Fatal("expected ICMPv6 echo reply from s2")
	}

	// No further packets should be needed.
	if n, _ := s1.EgressIPv6(buf); n != 0 {
		t.Error("unexpected extra egress from s1 after ping")
	}
	if n, _ := s2.EgressIPv6(buf); n != 0 {
		t.Error("unexpected extra egress from s2 after ping")
	}

	completed, ok := s1.(*stack6).icmp6.PingPop(key)
	if !ok {
		t.Fatal("ping key not found after exchange")
	}
	if !completed {
		t.Fatal("expected ping to be completed")
	}
}

// TestStack6ICMPv6_MultiPing verifies multiple sequential pings work.
func TestStack6ICMPv6_MultiPing(t *testing.T) {
	const (
		rngseed   = 193213
		icmpqueue = 2
	)
	s1, s2 := newStack6Pair(t, rngseed, 0, icmpqueue)
	buf := make([]byte, maxFrame6)

	if err := s1.EnableICMP6(true); err != nil {
		t.Fatal("s1 EnableICMP6:", err)
	}
	if err := s2.EnableICMP6(true); err != nil {
		t.Fatal("s2 EnableICMP6:", err)
	}

	for i, pattern := range [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
	} {
		key, err := s1.(*stack6).icmp6.PingStart(s2.Addr6(), pattern, uint16(len(pattern)+4))
		if err != nil {
			t.Fatalf("PingStart [%d]: %v", i, err)
		}
		if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
			t.Fatalf("[%d] expected echo request from s1", i)
		}
		if n := exchangeIPv6Once(t, s2, s1, buf); n == 0 {
			t.Fatalf("[%d] expected echo reply from s2", i)
		}
		completed, ok := s1.(*stack6).icmp6.PingPop(key)
		if !ok {
			t.Fatalf("[%d] ping key not found", i)
		}
		if !completed {
			t.Fatalf("[%d] ping not completed", i)
		}
	}
}

// TestStack6TCP_Handshake verifies that a TCP connection can be established over stack6.
func TestStack6TCP_Handshake(t *testing.T) {
	const (
		rngseed   = 213213
		svPort    = 8080
		clPort    = 12345
		nports    = 1
		icmpqueue = 2
	)
	s1, s2 := newStack6Pair(t, rngseed, nports, icmpqueue)
	buf := make([]byte, maxFrame6)

	svConn := newTCPConn6(t)
	clConn := newTCPConn6(t)

	// Server listens on s2.
	listenTCP6(t, s2, svConn, svPort, 200)

	// Client dials from s1 to s2.
	if err := s1.DialTCP6(clConn, clPort, s2.Addr6(), svPort, 100); err != nil {
		t.Fatal("DialTCP6:", err)
	}

	// SYN: client -> server.
	if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
		t.Fatal("expected SYN from client")
	}
	if clConn.State() != tcp.StateSynSent {
		t.Errorf("client state = %s, want SYN_SENT", clConn.State())
	}
	if svConn.State() != tcp.StateSynRcvd {
		t.Errorf("server state = %s, want SYN_RCVD", svConn.State())
	}

	// SYNACK: server -> client.
	if n := exchangeIPv6Once(t, s2, s1, buf); n == 0 {
		t.Fatal("expected SYNACK from server")
	}
	if clConn.State() != tcp.StateEstablished {
		t.Errorf("client state = %s, want ESTABLISHED", clConn.State())
	}

	// ACK: client -> server.
	if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
		t.Fatal("expected ACK from client")
	}
	if svConn.State() != tcp.StateEstablished {
		t.Errorf("server state = %s, want ESTABLISHED", svConn.State())
	}
}

// TestStack6TCP_DataExchange establishes a TCP connection and transfers data.
func TestStack6TCP_DataExchange(t *testing.T) {
	const (
		rngseed   = 400
		svPort    = 9090
		clPort    = 11111
		nports    = 1
		icmpqueue = 1
	)
	s1, s2 := newStack6Pair(t, rngseed, nports, icmpqueue)
	buf := make([]byte, maxFrame6)

	svConn := newTCPConn6(t)
	clConn := newTCPConn6(t)

	listenTCP6(t, s2, svConn, svPort, 300)
	if err := s1.DialTCP6(clConn, clPort, s2.Addr6(), svPort, 200); err != nil {
		t.Fatal("DialTCP6:", err)
	}

	// Three-way handshake.
	tcp6Handshake(t, s1, s2, buf)

	// Send data from client to server.
	payload := []byte("hello over tcp6")
	if _, err := clConn.Write(payload); err != nil {
		t.Fatal("Write:", err)
	}

	// PSH+ACK: client -> server.
	if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
		t.Fatal("expected data packet from client")
	}
	// ACK: server -> client.
	if n := exchangeIPv6Once(t, s2, s1, buf); n == 0 {
		t.Fatal("expected ACK from server")
	}
	// Drain any extra ACKs.
	exchangeIPv6Once(t, s1, s2, buf)
	exchangeIPv6Once(t, s2, s1, buf)

	var rbuf [256]byte
	n, err := svConn.Read(rbuf[:])
	if err != nil {
		t.Fatal("svConn.Read:", err)
	}
	if !bytes.Equal(rbuf[:n], payload) {
		t.Errorf("server received %q, want %q", rbuf[:n], payload)
	}
}

// TestStack6_NDP_DialUDP verifies that DialUDP6 with ICMP enabled triggers NDP
// resolution and that seeding the NDP cache allows the connection to proceed.
func TestStack6_NDP_DialUDP(t *testing.T) {
	const (
		portA     = 7001
		portB     = 7002
		rngseed   = 132131
		nports    = 1
		icmpqueue = 4
	)
	cfg1, cfg2 := stack6PairConfigs(rngseed, nports, icmpqueue)
	s1, s2 := newStack6Pair(t, rngseed, nports, icmpqueue)
	buf := make([]byte, maxFrame6)

	if err := s1.EnableICMP6(true); err != nil {
		t.Fatal("s1 EnableICMP6:", err)
	}
	if err := s2.EnableICMP6(true); err != nil {
		t.Fatal("s2 EnableICMP6:", err)
	}

	// Seed s2's NDP cache so it knows s1's MAC (needed for NA reply).
	if err := s2.(*stack6).icmp6.NDPCacheSeed(cfg1.StaticAddress6, cfg1.HardwareAddress); err != nil {
		t.Fatal("NDPCacheSeed s2:", err)
	}

	connA := newUDPConn6(t)
	connB := newUDPConn6(t)

	// DialUDP6 on s1 queues an NS since s2's MAC is not yet in s1's NDP cache.
	if err := s1.DialUDP6(connA, portA, cfg2.StaticAddress6, portB); err != nil {
		t.Fatal("DialUDP6 A:", err)
	}
	// s2 already has s1's address seeded so DialUDP6 resolves immediately.
	if err := s2.DialUDP6(connB, portB, cfg1.StaticAddress6, portA); err != nil {
		t.Fatal("DialUDP6 B:", err)
	}

	// NDP exchange: s1 sends Neighbor Solicitation, s2 replies with Neighbor Advertisement.
	if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
		t.Fatal("expected NDP Neighbor Solicitation from s1")
	}
	if n := exchangeIPv6Once(t, s2, s1, buf); n == 0 {
		t.Fatal("expected NDP Neighbor Advertisement from s2")
	}

	// After NDP resolved, connA's macBuf is patched; verify the cache now has s2's MAC.
	mac, err := s1.(*stack6).icmp6.NDPCacheLookup(cfg2.StaticAddress6)
	if err != nil {
		t.Fatal("NDPCacheLookup after NDP exchange:", err)
	}
	if mac != cfg2.HardwareAddress {
		t.Errorf("NDP resolved MAC = %v, want %v", mac, cfg2.HardwareAddress)
	}

	// Now that NDP is resolved, data should flow.
	want := []byte("ndp resolved udp")
	if _, err := connA.Write(want); err != nil {
		t.Fatal("Write:", err)
	}
	if n := exchangeIPv6Once(t, s1, s2, buf); n == 0 {
		t.Fatal("expected UDP packet after NDP resolution")
	}
	var rbuf [256]byte
	n, err := connB.Read(rbuf[:])
	if err != nil {
		t.Fatal("Read:", err)
	}
	if !bytes.Equal(rbuf[:n], want) {
		t.Errorf("got %q, want %q", rbuf[:n], want)
	}
}

// tcp6Handshake performs the SYN/SYNACK/ACK exchange between two stacks.
func tcp6Handshake(t testing.TB, client, server Stack6, buf []byte) {
	t.Helper()
	if n := exchangeIPv6Once(t, client, server, buf); n == 0 {
		t.Fatal("handshake: expected SYN")
	}
	if n := exchangeIPv6Once(t, server, client, buf); n == 0 {
		t.Fatal("handshake: expected SYNACK")
	}
	if n := exchangeIPv6Once(t, client, server, buf); n == 0 {
		t.Fatal("handshake: expected ACK")
	}
}

// TestStack6_EgressNoData checks that EgressIPv6 returns 0 when there is nothing to send.
func TestStack6_EgressNoData(t *testing.T) {
	s, _ := newStack6Pair(t, 13213, 2, 2)
	buf := make([]byte, maxFrame6)
	n, err := s.EgressIPv6(buf)
	if err != nil {
		t.Errorf("EgressIPv6 with no traffic: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes, got %d", n)
	}
}

// TestStack6_IngressDropsWrongDst checks that packets destined for a different address are dropped.
func TestStack6_IngressDropsWrongDst(t *testing.T) {
	s1, s2 := newStack6Pair(t, 2133213, 1, 1)
	buf := make([]byte, maxFrame6)

	connA := newUDPConn6(t)
	connB := newUDPConn6(t)
	const (
		portA = 4001
		portB = 4002
	)
	if err := s1.DialUDP6(connA, portA, s2.Addr6(), portB); err != nil {
		t.Fatal(err)
	}
	if err := s2.DialUDP6(connB, portB, s1.Addr6(), portA); err != nil {
		t.Fatal(err)
	}

	// Write and encapsulate from s1 (destination = testAddr6B).
	if _, err := connA.Write([]byte("drop me")); err != nil {
		t.Fatal(err)
	}
	n, err := s1.EgressIPv6(buf)
	if err != nil || n == 0 {
		t.Fatalf("expected encapsulated packet: n=%d err=%v", n, err)
	}

	// Feed to s1 itself (wrong destination) – should be dropped (ErrPacketDrop or similar).
	wrongDst := s1
	if err := wrongDst.IngressIPv6(buf[:n]); err == nil {
		t.Error("expected error when delivering packet to wrong destination stack, got nil")
	}

	// Deliver correctly to s2 – should succeed.
	if err := s2.IngressIPv6(buf[:n]); err != nil {
		t.Errorf("correct delivery to s2 failed: %v", err)
	}

	// s2 should have received the datagram.
	var rbuf [256]byte
	rn, err := connB.Read(rbuf[:])
	if err != nil || rn == 0 {
		t.Errorf("expected s2 to have received data: n=%d err=%v", rn, err)
	}

}
