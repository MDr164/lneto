package dhcpv6

import "testing"

func TestServerSolicitRequest(t *testing.T) {
	const xid = 0x112233
	clientMAC := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	serverMAC := [6]byte{0x02, 0, 0, 0, 0, 1}
	assigned := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	var client Client
	if err := client.BeginRequest(xid, RequestConfig{ClientHardwareAddr: clientMAC}); err != nil {
		t.Fatal(err)
	}
	var server Server
	if err := server.Configure(ServerConfig{ServerHardwareAddr: serverMAC, AssignedAddr: assigned}); err != nil {
		t.Fatal(err)
	}
	var buf [1024]byte
	n, err := client.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Demux(buf[:n], 0); err != nil {
		t.Fatal(err)
	}
	n, err = server.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Demux(buf[:n], 0); err != nil {
		t.Fatal(err)
	}
	n, err = client.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Demux(buf[:n], 0); err != nil {
		t.Fatal(err)
	}
	n, err = server.Encapsulate(buf[:], -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Demux(buf[:n], 0); err != nil {
		t.Fatal(err)
	}
	addr, ok := client.AssignedAddr()
	if !ok || addr != assigned {
		t.Fatalf("AssignedAddr = %v, %v, want %v, true", addr, ok, assigned)
	}
}
