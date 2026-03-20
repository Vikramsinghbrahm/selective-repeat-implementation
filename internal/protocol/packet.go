package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
)

type PacketType uint8

const (
	TypeSYN PacketType = 1 + iota
	TypeSYNACK
	_
	TypeFIN
	TypeFINACK
	TypeData
	TypeDataACK
)

const (
	HeaderSize     = 11
	MaxPacketSize  = 1024
	MaxPayloadSize = MaxPacketSize - HeaderSize
)

type Packet struct {
	Type     PacketType
	Seq      uint32
	PeerIP   net.IP
	PeerPort uint16
	Payload  []byte
}

func (p Packet) MarshalBinary() ([]byte, error) {
	ipv4 := p.PeerIP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("peer address must be IPv4: %v", p.PeerIP)
	}
	if len(p.Payload) > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d > %d", len(p.Payload), MaxPayloadSize)
	}

	buffer := make([]byte, HeaderSize+len(p.Payload))
	buffer[0] = byte(p.Type)
	binary.BigEndian.PutUint32(buffer[1:5], p.Seq)
	copy(buffer[5:9], ipv4)
	binary.BigEndian.PutUint16(buffer[9:11], p.PeerPort)
	copy(buffer[11:], p.Payload)

	return buffer, nil
}

func UnmarshalPacket(raw []byte) (Packet, error) {
	if len(raw) < HeaderSize {
		return Packet{}, fmt.Errorf("packet too short: got %d bytes", len(raw))
	}

	packet := Packet{
		Type:     PacketType(raw[0]),
		Seq:      binary.BigEndian.Uint32(raw[1:5]),
		PeerIP:   net.IPv4(raw[5], raw[6], raw[7], raw[8]).To4(),
		PeerPort: binary.BigEndian.Uint16(raw[9:11]),
		Payload:  append([]byte(nil), raw[11:]...),
	}

	return packet, nil
}

func (p Packet) PeerAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   append(net.IP(nil), p.PeerIP.To4()...),
		Port: int(p.PeerPort),
	}
}

func (t PacketType) String() string {
	switch t {
	case TypeSYN:
		return "SYN"
	case TypeSYNACK:
		return "SYN-ACK"
	case TypeFIN:
		return "FIN"
	case TypeFINACK:
		return "FIN-ACK"
	case TypeData:
		return "DATA"
	case TypeDataACK:
		return "DATA-ACK"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
