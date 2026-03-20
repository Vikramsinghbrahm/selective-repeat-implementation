package protocol

import (
	"bytes"
	"net"
	"testing"
)

func TestPacketMarshalRoundTrip(t *testing.T) {
	original := Packet{
		Type:     TypeData,
		Seq:      42,
		PeerIP:   net.IPv4(127, 0, 0, 1).To4(),
		PeerPort: 9000,
		Payload:  []byte("hello selective repeat"),
	}

	raw, err := original.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	decoded, err := UnmarshalPacket(raw)
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}

	if decoded.Type != original.Type {
		t.Fatalf("Type = %v, want %v", decoded.Type, original.Type)
	}
	if decoded.Seq != original.Seq {
		t.Fatalf("Seq = %d, want %d", decoded.Seq, original.Seq)
	}
	if !decoded.PeerIP.Equal(original.PeerIP) {
		t.Fatalf("PeerIP = %v, want %v", decoded.PeerIP, original.PeerIP)
	}
	if decoded.PeerPort != original.PeerPort {
		t.Fatalf("PeerPort = %d, want %d", decoded.PeerPort, original.PeerPort)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Fatalf("Payload = %q, want %q", decoded.Payload, original.Payload)
	}
}

func TestPacketMarshalRejectsOversizedPayload(t *testing.T) {
	packet := Packet{
		Type:     TypeData,
		Seq:      1,
		PeerIP:   net.IPv4(127, 0, 0, 1).To4(),
		PeerPort: 1,
		Payload:  bytes.Repeat([]byte("a"), MaxPayloadSize+1),
	}

	if _, err := packet.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary() succeeded for oversized payload")
	}
}

func TestUnmarshalPacketRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "short", raw: []byte{1, 2, 3}},
		{name: "oversized", raw: bytes.Repeat([]byte{0}, MaxPacketSize+1)},
		{name: "unknown type", raw: append([]byte{255, 0, 0, 0, 1, 127, 0, 0, 1, 0, 1}, []byte("x")...)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := UnmarshalPacket(test.raw); err == nil {
				t.Fatal("UnmarshalPacket() succeeded for malformed input")
			}
		})
	}
}
