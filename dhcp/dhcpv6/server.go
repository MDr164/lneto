package dhcpv6

import (
	"net"

	"github.com/soypat/lneto"
)

// ServerConfig contains configuration parameters for [Server.Configure].
type ServerConfig struct {
	ServerDUID         []byte
	ServerHardwareAddr [6]byte
	AssignedAddr       [16]byte
	PreferredLifetime  uint32
	ValidLifetime      uint32
	T1                 uint32
	T2                 uint32
}

// Server is a minimal DHCPv6 server for static IA_NA address assignment.
type Server struct {
	connID uint64
	duid   []byte
	addr   [16]byte
	pref   uint32
	valid  uint32
	t1     uint32
	t2     uint32

	pending    MsgType
	xid        uint32
	clientID   []byte
	clientIAID [4]byte
}

// Configure resets and configures the DHCPv6 server.
func (s *Server) Configure(cfg ServerConfig) error {
	if cfg.AssignedAddr == ([16]byte{}) {
		return lneto.ErrInvalidConfig
	}
	duid := s.duid[:0]
	if len(cfg.ServerDUID) != 0 {
		duid = append(duid, cfg.ServerDUID...)
	} else if cfg.ServerHardwareAddr != ([6]byte{}) {
		duid = AppendDUIDLL(duid, cfg.ServerHardwareAddr)
	} else {
		return lneto.ErrInvalidConfig
	}
	pref := cfg.PreferredLifetime
	if pref == 0 {
		pref = 1800
	}
	valid := cfg.ValidLifetime
	if valid == 0 {
		valid = 3600
	}
	t1 := cfg.T1
	if t1 == 0 {
		t1 = pref / 2
	}
	t2 := cfg.T2
	if t2 == 0 {
		t2 = pref
	}
	*s = Server{
		connID:   s.connID + 1,
		duid:     duid,
		addr:     cfg.AssignedAddr,
		pref:     pref,
		valid:    valid,
		t1:       t1,
		t2:       t2,
		clientID: s.clientID[:0],
	}
	return nil
}

// Demux processes an incoming DHCPv6 client message.
func (s *Server) Demux(carrierData []byte, frameOffset int) error {
	if len(s.duid) == 0 {
		return net.ErrClosed
	}
	frm, err := NewFrame(carrierData[frameOffset:])
	if err != nil {
		return err
	}
	msg := frm.MsgType()
	if msg != MsgSolicit && msg != MsgRequest {
		return lneto.ErrPacketDrop
	}
	s.xid = frm.TransactionID()
	s.clientID = s.clientID[:0]
	s.clientIAID = [4]byte{}
	sawIANA := false
	err = frm.ForEachOption(func(_ int, code OptCode, data []byte) error {
		switch code {
		case OptClientID:
			s.clientID = append(s.clientID, data...)
		case OptIANA:
			if len(data) >= 4 {
				copy(s.clientIAID[:], data[:4])
				sawIANA = true
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(s.clientID) == 0 || !sawIANA {
		return lneto.ErrInvalidField
	}
	if msg == MsgSolicit {
		s.pending = MsgAdvertise
	} else {
		s.pending = MsgReply
	}
	return nil
}

// Encapsulate writes the pending DHCPv6 server response.
func (s *Server) Encapsulate(carrierData []byte, _, offsetToFrame int) (int, error) {
	if s.pending == 0 {
		return 0, nil
	}
	dst := carrierData[offsetToFrame:]
	if len(dst) < OptionsOffset+128 {
		return 0, lneto.ErrShortBuffer
	}
	frm, err := NewFrame(dst)
	if err != nil {
		return 0, err
	}
	frm.SetMsgType(s.pending)
	frm.SetTransactionID(s.xid)
	n := OptionsOffset
	m, _ := EncodeOption(dst[n:], OptServerID, s.duid...)
	n += m
	m, _ = EncodeOption(dst[n:], OptClientID, s.clientID...)
	n += m
	addrOpt, _ := EncodeOptionIAAddr(dst[n+16:], s.addr, s.pref, s.valid)
	m, _ = EncodeOptionIANA(dst[n:], s.clientIAID, s.t1, s.t2, dst[n+16:n+16+addrOpt])
	n += m
	s.pending = 0
	return n, nil
}

// ConnectionID returns a pointer to the server's connection ID.
func (s *Server) ConnectionID() *uint64 { return &s.connID }

// LocalPort returns the DHCPv6 server port.
func (s *Server) LocalPort() uint16 { return ServerPort }

// Protocol returns the IP protocol number for UDP.
func (s *Server) Protocol() uint64 { return uint64(lneto.IPProtoUDP) }
