package dhcpv6

import (
	"net/netip"
	"testing"
)

func TestRelayAgent(t *testing.T) {
	agent := RelayAgent{
		LinkAddr: netip.MustParseAddr("2001:db8::1").As16(),
		PeerAddr: netip.MustParseAddr("fe80::1234").As16(),
		HopCount: 1,
	}
	clientMsg := []byte{byte(MsgSolicit), 0, 0, 1}
	var buf [128]byte
	n, err := agent.EncapsulateForward(buf[:], clientMsg)
	if err != nil {
		t.Fatal(err)
	}
	frm, err := NewRelayFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if frm.MsgType() != MsgRelayForw || frm.HopCount() != 1 {
		t.Fatalf("relay frame type=%v hop=%d", frm.MsgType(), frm.HopCount())
	}
	payload, ok, err := RelayPayload(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(payload) != string(clientMsg) {
		t.Fatalf("RelayPayload = %v, %v, want %v, true", payload, ok, clientMsg)
	}
	replyMsg := []byte{byte(MsgReply), 0, 0, 1}
	n, err = agent.EncapsulateReply(buf[:], replyMsg)
	if err != nil {
		t.Fatal(err)
	}
	frm, err = NewRelayFrame(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if frm.MsgType() != MsgRelayRepl {
		t.Fatalf("reply relay type=%v, want %v", frm.MsgType(), MsgRelayRepl)
	}
}
