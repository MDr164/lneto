package timestamps

import (
	"math/rand"
	"testing"
	"time"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/tcp/rto"
)

const mtu = ethernet.MaxMTU

// TestNegotiation verifies timestamps are used only when both sides offer the
// option, and that the SYN-ACK and final ACK carry it only then (RFC 7323
// §3.2).
func TestNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		client, server bool
	}{
		{"both", true, true},
		{"client-only", true, false},
		{"server-only", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var now int64
			client, server := newHandler(t), newHandler(t)
			cp, sp := newPolicy(t, &now, false, nil), newPolicy(t, &now, false, nil)
			if tc.client {
				client.SetPolicy(cp)
			}
			if tc.server {
				server.SetPolicy(sp)
			}
			handshake := establish(t, client, server)
			want := tc.client && tc.server
			if cp.Enabled() != want || sp.Enabled() != want {
				t.Errorf("enabled client=%v server=%v, want %v", cp.Enabled(), sp.Enabled(), want)
			}
			for i, wantTS := range []bool{tc.client, want, want} {
				if _, _, ok := timestampOf(t, handshake[i]); ok != wantTS {
					t.Errorf("handshake segment %d carries timestamps: %v, want %v", i, ok, wantTS)
				}
			}
		})
	}
}

// TestEcho verifies segments carry the sender's clock and echo TS.Recent, and
// that TS.Recent advances only for a segment at or below Last.ACK.sent: of two
// segments arriving before an ACK is sent, the first is echoed (RFC 7323 §4.3).
func TestEcho(t *testing.T) {
	var now int64
	client, server := newHandler(t), newHandler(t)
	cp, sp := newPolicy(t, &now, false, nil), newPolicy(t, &now, false, nil)
	client.SetPolicy(cp)
	server.SetPolicy(sp)
	establish(t, client, server)

	now += 5 * int64(time.Millisecond)
	first := sendData(t, client, []byte("one"))
	now += 5 * int64(time.Millisecond)
	second := sendData(t, client, []byte("two"))
	tsval1, tsecr1, _ := timestampOf(t, first)
	tsval2, _, _ := timestampOf(t, second)
	if tsval2-tsval1 != 5 {
		t.Fatalf("TSval %d then %d, want 5 ms apart", tsval1, tsval2)
	}
	if recent, _ := cp.Recent(); tsecr1 != recent {
		t.Fatalf("TSecr %d, want the server's timestamp %d", tsecr1, recent)
	}
	for _, pkt := range [][]byte{first, second} {
		if err := server.Recv(pkt); err != nil {
			t.Fatal(err)
		}
	}
	if _, tsecr, _ := timestampOf(t, send(t, server)); tsecr != tsval1 {
		t.Fatalf("ACK echoes %d, want the first segment's %d", tsecr, tsval1)
	}
}

// TestDropWithoutOption verifies that once timestamps are in use a segment
// without the option is dropped, while a RST without it is honoured (RFC 7323
// §3.2).
func TestDropWithoutOption(t *testing.T) {
	var now int64
	client, server := newHandler(t), newHandler(t)
	client.SetPolicy(newPolicy(t, &now, false, nil))
	server.SetPolicy(newPolicy(t, &now, false, nil))
	establish(t, client, server)
	seg := tcp.Segment{SEQ: server.ControlBlock().RecvNext(), ACK: server.ControlBlock().SendNext(), Flags: tcp.FlagACK, WND: mtu}
	if err := server.Recv(frameFor(t, client, server, seg, nil, []byte("data"))); err != nil {
		t.Fatal(err)
	}
	if server.BufferedInput() != 0 {
		t.Fatal("segment without timestamps was accepted")
	}
	seg.Flags = tcp.FlagRST | tcp.FlagACK
	server.Recv(frameFor(t, client, server, seg, nil, nil))
	if server.State() != tcp.StateClosed {
		t.Fatalf("RST without timestamps ignored: state %s", server.State())
	}
}

// TestPAWS verifies a segment with a timestamp older than TS.Recent is dropped
// and answered with an ACK when PAWS is on (RFC 7323 §5.3), and accepted when
// PAWS is off or TS.Recent has been idle past 24 days (§5.5).
func TestPAWS(t *testing.T) {
	for _, tc := range []struct {
		name       string
		paws       bool
		idle       time.Duration
		wantAccept bool
	}{
		{name: "drop", paws: true},
		{name: "off", wantAccept: true},
		{name: "recent-expired", paws: true, idle: pawsIdle + time.Second, wantAccept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var now int64
			client, server := newHandler(t), newHandler(t)
			client.SetPolicy(newPolicy(t, &now, false, nil))
			sp := newPolicy(t, &now, tc.paws, nil)
			server.SetPolicy(sp)
			establish(t, client, server)
			now += int64(tc.idle)
			recent, _ := sp.Recent()
			seg := tcp.Segment{SEQ: server.ControlBlock().RecvNext(), ACK: server.ControlBlock().SendNext(), Flags: tcp.FlagACK, WND: mtu}
			if err := server.Recv(frameFor(t, client, server, seg, &[2]uint32{recent - 1, 1}, []byte("data"))); err != nil {
				t.Fatal(err)
			}
			if accepted := server.BufferedInput() != 0; accepted != tc.wantAccept {
				t.Fatalf("old timestamp accepted: %v, want %v", accepted, tc.wantAccept)
			}
			ack := send(t, server)
			if ack == nil || segmentOf(t, ack).ACK != server.ControlBlock().RecvNext() {
				t.Fatalf("no ACK of the receive state sent: %v", ack)
			}
		})
	}
}

// TestRTTFromRetransmission verifies a round-trip sample is taken from the
// echo of a retransmitted segment, which Karn's algorithm keeps the timer
// itself from sampling, and fed to the timer.
func TestRTTFromRetransmission(t *testing.T) {
	var now int64
	clock := func() int64 { return now }
	client, server := newHandler(t), newHandler(t)
	var timer rto.Timer
	if err := timer.Configure(clock); err != nil {
		t.Fatal(err)
	}
	cp := newPolicy(t, &now, false, &timer)
	client.SetPolicy(tcp.Policies{&timer, cp})
	server.SetPolicy(newPolicy(t, &now, false, nil))
	establish(t, client, server)

	sendData(t, client, []byte("lost"))
	now = timer.NextDeadline()
	resent := send(t, client)
	if resent == nil {
		t.Fatal("no retransmission after the RTO expired")
	}
	const rtt = 20 * time.Millisecond
	now += int64(rtt)
	if err := server.Recv(resent); err != nil {
		t.Fatal(err)
	}
	if err := client.Recv(send(t, server)); err != nil {
		t.Fatal(err)
	}
	if got, ok := cp.LastRTT(); !ok || got != rtt {
		t.Fatalf("LastRTT = %v (%v), want %v", got, ok, rtt)
	}
	if timer.SmoothedRTT() != rtt {
		t.Fatalf("timer SRTT = %v, want the timestamp sample %v", timer.SmoothedRTT(), rtt)
	}
}

func newPolicy(t *testing.T, now *int64, paws bool, timer *rto.Timer) *Policy {
	t.Helper()
	p := new(Policy)
	if err := p.Configure(Config{Nanotime: func() int64 { return *now }, PAWS: paws, Timer: timer}); err != nil {
		t.Fatal(err)
	}
	return p
}

func newHandler(t *testing.T) *tcp.Handler {
	t.Helper()
	h := new(tcp.Handler)
	if err := h.SetBuffers(make([]byte, mtu), make([]byte, mtu), 8); err != nil {
		t.Fatal(err)
	}
	return h
}

// establish completes the three-way handshake and returns its segments.
func establish(t *testing.T, client, server *tcp.Handler) (handshake [3][]byte) {
	t.Helper()
	rng := rand.New(rand.NewSource(1))
	if err := server.OpenListen(uint16(rng.Uint32()), 100); err != nil {
		t.Fatal(err)
	}
	if err := client.OpenActive(uint16(rng.Uint32()), server.LocalPort(), 300); err != nil {
		t.Fatal(err)
	}
	for i, h := range [][2]*tcp.Handler{{client, server}, {server, client}, {client, server}} {
		handshake[i] = send(t, h[0])
		if err := h[1].Recv(handshake[i]); err != nil {
			t.Fatal(err)
		}
	}
	if client.State() != tcp.StateEstablished || server.State() != tcp.StateEstablished {
		t.Fatalf("handshake: client %s, server %s", client.State(), server.State())
	}
	return handshake
}

// send returns a copy of the next frame h emits, or nil if it emits none.
func send(t *testing.T, h *tcp.Handler) []byte {
	t.Helper()
	var buf [mtu]byte
	n, err := h.Send(buf[:])
	if err != nil {
		t.Fatal(err)
	} else if n == 0 {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

func sendData(t *testing.T, h *tcp.Handler, data []byte) []byte {
	t.Helper()
	if _, err := h.Write(data); err != nil {
		t.Fatal(err)
	}
	return send(t, h)
}

func segmentOf(t *testing.T, pkt []byte) tcp.Segment {
	t.Helper()
	frm, err := tcp.NewFrame(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return frm.Segment(len(frm.Payload()))
}

func timestampOf(t *testing.T, pkt []byte) (tsval, tsecr uint32, ok bool) {
	t.Helper()
	frm, err := tcp.NewFrame(pkt)
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	return p.parse(frm.Options())
}

// frameFor builds a segment from src to dst carrying the timestamps ts, or no
// option if ts is nil.
func frameFor(t *testing.T, src, dst *tcp.Handler, seg tcp.Segment, ts *[2]uint32, payload []byte) []byte {
	t.Helper()
	pkt := make([]byte, 20+12+len(payload))
	frm, _ := tcp.NewFrame(pkt)
	seg.DATALEN = tcp.Size(len(payload))
	frm.SetSegment(seg, 5)
	frm.SetSourcePort(src.LocalPort())
	frm.SetDestinationPort(dst.LocalPort())
	if ts != nil {
		var data [optDataLen]byte
		put32(data[:4], ts[0])
		put32(data[4:], ts[1])
		var p Policy
		if !p.writeOption(frm, data[:]) {
			t.Fatal("option did not fit")
		}
	} else {
		pkt = pkt[:20+len(payload)]
	}
	copy(pkt[len(pkt)-len(payload):], payload)
	return pkt
}
