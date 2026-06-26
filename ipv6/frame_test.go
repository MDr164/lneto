package ipv6

import (
	"testing"

	"github.com/soypat/lneto"
)

func TestFrameForEachExtensionHeader(t *testing.T) {
	buf := make([]byte, 40+8+8+20)
	frm, err := NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	frm.SetVersionTrafficAndFlow(6, 0, 0)
	frm.SetPayloadLength(uint16(len(buf) - 40))
	frm.SetNextHeader(lneto.IPProtoHopByHop)

	buf[40] = byte(lneto.IPProtoIPv6Route)
	buf[41] = 0
	buf[48] = byte(lneto.IPProtoTCP)
	buf[49] = 0

	var got []ExtensionHeader
	proto, off, err := frm.ForEachExtensionHeader(func(hdr ExtensionHeader) error {
		got = append(got, hdr)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if proto != lneto.IPProtoTCP || off != 56 {
		t.Fatalf("terminal proto/off = %s/%d, want TCP/56", proto, off)
	}
	if len(got) != 2 {
		t.Fatalf("headers len = %d, want 2", len(got))
	}
	if got[0].Protocol != lneto.IPProtoHopByHop || got[0].NextHeader != lneto.IPProtoIPv6Route || got[0].Offset != 40 || got[0].Length != 8 {
		t.Fatalf("first header = %+v", got[0])
	}
	if got[1].Protocol != lneto.IPProtoIPv6Route || got[1].NextHeader != lneto.IPProtoTCP || got[1].Offset != 48 || got[1].Length != 8 {
		t.Fatalf("second header = %+v", got[1])
	}
}

func TestFrameForEachExtensionHeaderFragmentAndAH(t *testing.T) {
	buf := make([]byte, 40+8+12+8)
	frm, err := NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	frm.SetVersionTrafficAndFlow(6, 0, 0)
	frm.SetPayloadLength(uint16(len(buf) - 40))
	frm.SetNextHeader(lneto.IPProtoIPv6Frag)

	buf[40] = byte(lneto.IPProtoAH)
	buf[48] = byte(lneto.IPProtoUDP)
	buf[49] = 1

	var got []ExtensionHeader
	proto, off, err := frm.ForEachExtensionHeader(func(hdr ExtensionHeader) error {
		got = append(got, hdr)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if proto != lneto.IPProtoUDP || off != 60 {
		t.Fatalf("terminal proto/off = %s/%d, want UDP/60", proto, off)
	}
	if len(got) != 2 || got[0].Length != 8 || got[1].Length != 12 {
		t.Fatalf("headers = %+v", got)
	}
}

func TestFrameForEachExtensionHeaderTruncated(t *testing.T) {
	buf := make([]byte, 40+4)
	frm, err := NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	frm.SetPayloadLength(4)
	frm.SetNextHeader(lneto.IPProtoHopByHop)
	buf[41] = 0

	if _, _, err := frm.ForEachExtensionHeader(nil); err != lneto.ErrTruncatedFrame {
		t.Fatalf("ForEachExtensionHeader err = %v, want %v", err, lneto.ErrTruncatedFrame)
	}
}

func TestFrameForEachExtensionHeaderNoNext(t *testing.T) {
	buf := make([]byte, 40)
	frm, err := NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	frm.SetNextHeader(lneto.IPProtoIPv6NoNxt)
	proto, off, err := frm.ForEachExtensionHeader(func(ExtensionHeader) error {
		t.Fatal("unexpected extension header callback")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if proto != lneto.IPProtoIPv6NoNxt || off != 40 {
		t.Fatalf("terminal proto/off = %s/%d, want NoNext/40", proto, off)
	}
}
