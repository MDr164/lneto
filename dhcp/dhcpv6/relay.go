package dhcpv6

import "github.com/soypat/lneto"

// RelayAgent wraps and unwraps DHCPv6 relay messages for one relay hop.
type RelayAgent struct {
	LinkAddr [16]byte
	PeerAddr [16]byte
	HopCount uint8
}

// EncapsulateForward writes a Relay-forward message carrying clientMsg into dst.
func (r RelayAgent) EncapsulateForward(dst, clientMsg []byte) (int, error) {
	return r.encapsulate(dst, MsgRelayForw, clientMsg)
}

// EncapsulateReply writes a Relay-reply message carrying serverMsg into dst.
func (r RelayAgent) EncapsulateReply(dst, serverMsg []byte) (int, error) {
	return r.encapsulate(dst, MsgRelayRepl, serverMsg)
}

func (r RelayAgent) encapsulate(dst []byte, msgType MsgType, msg []byte) (int, error) {
	if len(dst) < RelayOptionsOffset+4+len(msg) {
		return 0, lneto.ErrShortBuffer
	}
	frm, err := NewRelayFrame(dst)
	if err != nil {
		return 0, err
	}
	frm.SetMsgType(msgType)
	frm.SetHopCount(r.HopCount)
	*frm.LinkAddr() = r.LinkAddr
	*frm.PeerAddr() = r.PeerAddr
	n, err := EncodeOption(dst[RelayOptionsOffset:], OptRelayMsg, msg...)
	if err != nil {
		return 0, err
	}
	return RelayOptionsOffset + n, nil
}

// RelayPayload returns the DHCPv6 message carried by a relay message.
func RelayPayload(relay []byte) ([]byte, bool, error) {
	frm, err := NewRelayFrame(relay)
	if err != nil {
		return nil, false, err
	}
	return frm.RelayMessage()
}
