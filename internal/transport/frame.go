package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"

	"selective-repeat-implementation/internal/protocol"
)

const (
	frameVersion     = 1
	frameVersionSize = 1
	sessionTokenSize = 8
	frameTagSize     = 16
	frameHeaderSize  = frameVersionSize + sessionTokenSize + frameTagSize
)

func marshalPayloadFrame(packetType protocol.PacketType, sequence uint32, peerAddr *net.UDPAddr, sessionToken uint64, body []byte) []byte {
	framed := make([]byte, frameHeaderSize+len(body))
	framed[0] = frameVersion
	binary.BigEndian.PutUint64(framed[1:1+sessionTokenSize], sessionToken)
	copy(framed[frameHeaderSize:], body)

	tag := computeFrameTag(packetType, sequence, peerAddr, sessionToken, body)
	copy(framed[1+sessionTokenSize:frameHeaderSize], tag[:frameTagSize])

	return framed
}

func unmarshalPayloadFrame(packet protocol.Packet) (uint64, []byte, error) {
	if len(packet.Payload) < frameHeaderSize {
		return 0, nil, fmt.Errorf("payload frame too short: %d", len(packet.Payload))
	}
	if packet.PeerIP == nil || packet.PeerIP.To4() == nil {
		return 0, nil, fmt.Errorf("packet peer address must be IPv4")
	}

	sessionToken := binary.BigEndian.Uint64(packet.Payload[1 : 1+sessionTokenSize])
	if packet.Payload[0] != frameVersion {
		return 0, nil, fmt.Errorf("unsupported payload frame version: %d", packet.Payload[0])
	}

	body := packet.Payload[frameHeaderSize:]
	expected := computeFrameTag(packet.Type, packet.Seq, packet.PeerAddr(), sessionToken, body)
	actual := packet.Payload[1+sessionTokenSize : frameHeaderSize]
	if !hmac.Equal(actual, expected[:frameTagSize]) {
		return 0, nil, fmt.Errorf("payload frame authentication failed")
	}

	return sessionToken, append([]byte(nil), body...), nil
}

func computeFrameTag(packetType protocol.PacketType, sequence uint32, _ *net.UDPAddr, sessionToken uint64, body []byte) []byte {
	key := make([]byte, sessionTokenSize)
	binary.BigEndian.PutUint64(key, sessionToken)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{byte(packetType)})

	var sequenceBuffer [4]byte
	binary.BigEndian.PutUint32(sequenceBuffer[:], sequence)
	mac.Write(sequenceBuffer[:])
	mac.Write(body)

	return mac.Sum(nil)
}
