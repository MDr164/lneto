package dhcpv6

import (
	"net/netip"
	"testing"
)

func TestRelayFrame(t *testing.T) {
	clientMsg := []byte{byte(MsgSolicit), 0, 0, 1}
	buf := make([]byte, RelayOptionsOffset+4+len(clientMsg))
	frm, err := NewRelayFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	frm.SetMsgType(MsgRelayForw)
	frm.SetHopCount(2)
	*frm.LinkAddr() = netip.MustParseAddr("2001:db8::1").As16()
	*frm.PeerAddr() = netip.MustParseAddr("fe80::1234").As16()
	if _, err := EncodeOption(buf[RelayOptionsOffset:], OptRelayMsg, clientMsg...); err != nil {
		t.Fatal(err)
	}
	if frm.MsgType() != MsgRelayForw || frm.HopCount() != 2 {
		t.Fatalf("relay header type=%v hops=%d", frm.MsgType(), frm.HopCount())
	}
	if got := netip.AddrFrom16(*frm.LinkAddr()); got != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("LinkAddr = %s", got)
	}
	if err := frm.ValidateSize(); err != nil {
		t.Fatal(err)
	}
	msg, ok, err := frm.RelayMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(msg) != string(clientMsg) {
		t.Fatalf("RelayMessage = %v, %v, want %v, true", msg, ok, clientMsg)
	}
}

func TestRelayFrameTruncatedOption(t *testing.T) {
	buf := make([]byte, RelayOptionsOffset+5)
	frm, err := NewRelayFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf[RelayOptionsOffset] = byte(OptRelayMsg >> 8)
	buf[RelayOptionsOffset+1] = byte(OptRelayMsg)
	buf[RelayOptionsOffset+3] = 2
	if err := frm.ValidateSize(); err == nil {
		t.Fatal("ValidateSize nil error, want truncated option error")
	}
}
