package icmpv6

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/internal"
)

const (
	testHashSeed = 0xdeadbeef
)

func TestClients(t *testing.T) {
	const sizebuffer = 64
	const queuesize = 2
	var sender, responder Client
	err := sender.Configure(ClientConfig{
		ResponseQueueBuffer: make([]byte, sizebuffer),
		ResponseQueueLimit:  queuesize,
		HashSeed:            testHashSeed,
		ID:                  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = responder.Configure(ClientConfig{
		ResponseQueueBuffer: make([]byte, sizebuffer),
		ResponseQueueLimit:  queuesize,
		HashSeed:            testHashSeed,
		ID:                  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	pattern := []byte("ab12")
	size := 8
	var buf [64]byte
	key1 := testSingleExchange(t, &sender, &responder, buf[:], pattern, uint16(size))
	completed, ok := sender.PingPop(key1)
	if !completed || !ok {
		t.Fatal("ping did not complete or not exist")
	}
	n, err := sender.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Error(err)
	} else if n > 0 {
		t.Error("sender: expected no more data to be sent")
	}
	n, err = responder.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Error(err)
	} else if n > 0 {
		t.Error("responder: expected no more data to be sent")
	}
}

func TestRouterAdvertisementDNSOptions(t *testing.T) {
	rdnssLifetime := uint32(1200)
	dnsslLifetime := uint32(900)
	dns1 := netip.MustParseAddr("2001:db8::53")
	dns2 := netip.MustParseAddr("2001:db8::54")
	prefix := netip.MustParsePrefix("2001:db8:abcd::/48")
	prefixOpt := makePrefixInformationOption(prefix, 3600, 1800, true, true)
	rdnss := makeRDNSSOption(rdnssLifetime, dns1, dns2)
	dnssl := makeDNSSLOption(t, dnsslLifetime, "example.com", "corp.example.com")

	buf := make([]byte, sizeRouterAd+len(prefixOpt)+len(rdnss)+len(dnssl))
	frm, err := NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	frm.SetType(TypeRouterAdvertisement)
	copy(buf[sizeRouterAd:], prefixOpt)
	copy(buf[sizeRouterAd+len(prefixOpt):], rdnss)
	copy(buf[sizeRouterAd+len(prefixOpt)+len(rdnss):], dnssl)
	ra := FrameRouterAdvertisement{Frame: frm}

	var gotPrefix PrefixInformation
	var gotPrefixOK bool
	var gotDNS []netip.Addr
	var gotDomains []dns.Name
	var gotRDNSSLifetime, gotDNSSLLifetime uint32
	err = ForEachOption(ra.Options(), func(option []byte) error {
		switch option[0] {
		case OptPrefixInformation:
			gotPrefix, gotPrefixOK = ParsePrefixInformationOption(option)
		case OptRecursiveDNSServer:
			var ok bool
			gotRDNSSLifetime, gotDNS, ok = ParseRDNSSOption(gotDNS, option)
			if !ok {
				t.Fatal("ParseRDNSSOption failed")
			}
		case OptDNSSearchList:
			var ok bool
			gotDNSSLLifetime, gotDomains, ok = ParseDNSSLOption(gotDomains, option)
			if !ok {
				t.Fatal("ParseDNSSLOption failed")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !gotPrefixOK || gotPrefix.Prefix != prefix || !gotPrefix.OnLink || !gotPrefix.Autonomous || gotPrefix.ValidLifetime != 3600 || gotPrefix.PreferredLifetime != 1800 {
		t.Fatalf("PrefixInformation = %+v ok=%v", gotPrefix, gotPrefixOK)
	}
	if gotRDNSSLifetime != rdnssLifetime || len(gotDNS) != 2 || gotDNS[0] != dns1 || gotDNS[1] != dns2 {
		t.Fatalf("RDNSS lifetime=%d servers=%v", gotRDNSSLifetime, gotDNS)
	}
	if gotDNSSLLifetime != dnsslLifetime || len(gotDomains) != 2 {
		t.Fatalf("DNSSL lifetime=%d domains=%v", gotDNSSLLifetime, gotDomains)
	}
	if !gotDomains[0].EqualString("example.com") || !gotDomains[1].EqualString("corp.example.com") {
		t.Fatalf("DNSSL domains=%q %q", gotDomains[0].String(), gotDomains[1].String())
	}
}

func TestClientPacketTooBig(t *testing.T) {
	const frameOffset = 40
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	var buf [frameOffset + sizeHeader]byte
	copy(buf[8:24], src[:])
	copy(buf[24:40], dst[:])
	frm, err := NewFrame(buf[frameOffset:])
	if err != nil {
		t.Fatal(err)
	}
	frm.SetType(TypePacketTooBig)
	ptb := FramePacketTooBig{Frame: frm}
	ptb.SetMTU(1280)
	frm.SetCRC(0)
	var crc lneto.CRC791
	crc.WriteEven(buf[8:40])
	crc.AddUint32(sizeHeader)
	crc.AddUint32(uint32(lneto.IPProtoIPv6ICMP))
	frm.SetCRC(crc.PayloadSum16(buf[frameOffset:]))

	var client Client
	if err := client.Demux(buf[:], frameOffset); err != nil {
		t.Fatal(err)
	}
	report, ok := client.LastPacketTooBig()
	if !ok {
		t.Fatal("LastPacketTooBig ok=false, want true")
	}
	if report.Source != src || report.MTU != 1280 {
		t.Fatalf("LastPacketTooBig = %+v, want source %v mtu 1280", report, src)
	}
	client.Reset()
	if _, ok := client.LastPacketTooBig(); ok {
		t.Fatal("LastPacketTooBig after Reset ok=true, want false")
	}
}

func TestClientRouterAdvertisement(t *testing.T) {
	const frameOffset = 40
	src := netip.MustParseAddr("fe80::1").As16()
	dst := netip.MustParseAddr("ff02::1").As16()
	var buf [frameOffset + sizeRouterAd]byte
	copy(buf[8:24], src[:])
	copy(buf[24:40], dst[:])
	frm, err := NewFrame(buf[frameOffset:])
	if err != nil {
		t.Fatal(err)
	}
	frm.SetType(TypeRouterAdvertisement)
	buf[frameOffset+4] = 64
	binary.BigEndian.PutUint16(buf[frameOffset+6:frameOffset+8], 1800)
	frm.SetCRC(0)
	var crc lneto.CRC791
	crc.WriteEven(buf[8:40])
	crc.AddUint32(sizeRouterAd)
	crc.AddUint32(uint32(lneto.IPProtoIPv6ICMP))
	frm.SetCRC(crc.PayloadSum16(buf[frameOffset:]))

	var client Client
	if err := client.Demux(buf[:], frameOffset); err != nil {
		t.Fatal(err)
	}
	report, ok := client.LastRouterAdvertisement()
	if !ok {
		t.Fatal("LastRouterAdvertisement ok=false, want true")
	}
	if report.Source != src || report.CurrentHopLimit != 64 || report.RouterLifetime != 1800 {
		t.Fatalf("LastRouterAdvertisement = %+v", report)
	}
	client.Reset()
	if _, ok := client.LastRouterAdvertisement(); ok {
		t.Fatal("LastRouterAdvertisement after Reset ok=true, want false")
	}
}

func makePrefixInformationOption(prefix netip.Prefix, valid, preferred uint32, onLink, autonomous bool) []byte {
	var buf [32]byte
	buf[0] = OptPrefixInformation
	buf[1] = 4
	buf[2] = byte(prefix.Bits())
	if onLink {
		buf[3] |= 0x80
	}
	if autonomous {
		buf[3] |= 0x40
	}
	binary.BigEndian.PutUint32(buf[4:8], valid)
	binary.BigEndian.PutUint32(buf[8:12], preferred)
	addr := prefix.Addr().As16()
	copy(buf[16:], addr[:])
	return buf[:]
}

func makeRDNSSOption(lifetime uint32, addrs ...netip.Addr) []byte {
	optLen := 8 + 16*len(addrs)
	buf := make([]byte, optLen)
	buf[0] = OptRecursiveDNSServer
	buf[1] = byte(optLen / 8)
	binary.BigEndian.PutUint32(buf[4:8], lifetime)
	for i, addr := range addrs {
		a := addr.As16()
		copy(buf[8+16*i:], a[:])
	}
	return buf
}

func makeDNSSLOption(t testing.TB, lifetime uint32, domains ...string) []byte {
	t.Helper()
	buf := []byte{OptDNSSearchList, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(buf[4:8], lifetime)
	for _, domain := range domains {
		name, err := dns.NewName(domain)
		if err != nil {
			t.Fatal(err)
		}
		buf, err = name.AppendTo(buf)
		if err != nil {
			t.Fatal(err)
		}
	}
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	buf[1] = byte(len(buf) / 8)
	return buf
}

func testSingleExchange(t *testing.T, sender, responder *Client, buf []byte, pattern []byte, size uint16) (senderKey uint32) {
	const frameOff = 0
	const ipOff = -1
	n, err := responder.Encapsulate(buf, ipOff, frameOff)
	if err != nil {
		t.Fatal(err)
	} else if n > 0 {
		t.Fatal("expected no data pending to be sent from responder")
	}
	senderKey, n = testSendEcho(t, sender, buf, pattern, size)
	completed, ok := sender.PingPeek(senderKey)
	if !ok {
		t.Error("ping key not exist")
	} else if completed {
		t.Error("ping completed before response")
	}
	ifrm, _ := NewFrame(buf[frameOff : frameOff+n])
	efrm := FrameEcho{Frame: ifrm}
	id, seq := efrm.Identifier(), efrm.SequenceNumber()
	err1 := responder.Demux(buf[:frameOff+n], frameOff)
	if err1 != nil {
		t.Error("responder demux during single", err1)
	}
	n, err = responder.Encapsulate(buf, ipOff, frameOff)
	if err != nil {
		t.Error("responder encaps during single", err)
		return
	} else if n == 0 && err1 == nil {
		t.Error("responder wrote no data")
		return
	}
	ifrm, err = NewFrame(buf[frameOff : frameOff+n])
	if err != nil {
		t.Fatal(err)
	}
	if ifrm.Type() != TypeEchoReply {
		t.Fatalf("expected echo reply %d", ifrm.Type())
	}
	efrm = FrameEcho{Frame: ifrm}
	if efrm.Identifier() != id {
		t.Error("mismatched identifier want/got:", id, efrm.Identifier())
	}
	if efrm.SequenceNumber() != seq {
		t.Error("mismatched sequence number want/got:", seq, efrm.SequenceNumber())
	}
	data := efrm.Data()
	testPatternMatch(t, data, pattern, int(size))
	err = sender.Demux(buf[:frameOff+n], frameOff)
	if err != nil {
		t.Error("sender demuxed response", err)
	}
	completed, ok = sender.PingPeek(senderKey)
	if !completed {
		t.Error("expected ping to have completed")
	}
	if !ok {
		t.Error("ping key not exist after completion")
	}
	if completed2, ok2 := sender.PingPeek(senderKey); completed != completed2 || ok != ok2 {
		t.Error("change in status after peek")
	}
	n, err = sender.Encapsulate(buf, ipOff, frameOff)
	if err != nil {
		t.Error("error after done")
	}
	if n > 0 {
		t.Error("expected no data to be sent after ping completion", n)
	}
	return senderKey
}

func testSendEcho(t *testing.T, sender *Client, buf []byte, pattern []byte, size uint16) (key uint32, n int) {
	t.Helper()
	const frameOff = 0
	const ipOff = -1
	n, err := sender.Encapsulate(buf, ipOff, frameOff)
	if err != nil {
		t.Fatal(err)
	} else if n > 0 {
		t.Fatal("expected no data pending to send on testSendEcho start")
	}
	key, err = sender.PingStart([16]byte{1}, pattern, size)
	if err != nil {
		t.Fatal(err)
	}

	n, err = sender.Encapsulate(buf[:], ipOff, frameOff)
	if err != nil {
		t.Errorf("sender encapsulate: %v", err)
	}
	ifrm, err := NewFrame(buf[:n])
	if err != nil {
		t.Fatal(err) // only fails in short frame case.
	}
	if ifrm.Type() != TypeEchoRequest {
		t.Errorf("not echo request type on send: %d", ifrm.Type())
	}
	efrm := FrameEcho{Frame: ifrm}
	data := efrm.Data()
	testPatternMatch(t, data, pattern, int(size))
	return key, n
}

func testPatternMatch(t *testing.T, data []byte, pattern []byte, size int) {
	t.Helper()
	if len(data) != size {
		t.Errorf("pattern size mismatch, want %d, got %d", size, len(data))
	}
	for i := 0; i < size; i += len(pattern) {
		got := data[i:min(len(data), i+len(pattern))]
		want := pattern[:len(got)]
		if !internal.BytesEqual(got, want) {
			t.Errorf("pattern data mismatch at %d, got %s, want %s", i, got, want)
		}
	}
}
