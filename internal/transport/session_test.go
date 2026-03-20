package transport

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"selective-repeat-implementation/internal/protocol"
)

func TestPayloadFrameRoundTripAndTamperDetection(t *testing.T) {
	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 9000}
	sessionToken := uint64(0x1234567890abcdef)

	packet := protocol.Packet{
		Type:     protocol.TypeData,
		Seq:      7,
		PeerIP:   append(net.IP(nil), peerAddr.IP...),
		PeerPort: uint16(peerAddr.Port),
		Payload:  marshalPayloadFrame(protocol.TypeData, 7, peerAddr, sessionToken, []byte("payload")),
	}

	gotToken, gotBody, err := unmarshalPayloadFrame(packet)
	if err != nil {
		t.Fatalf("unmarshalPayloadFrame() error = %v", err)
	}
	if gotToken != sessionToken {
		t.Fatalf("token = %x, want %x", gotToken, sessionToken)
	}
	if !bytes.Equal(gotBody, []byte("payload")) {
		t.Fatalf("body = %q, want %q", gotBody, "payload")
	}

	packet.Payload[len(packet.Payload)-1] ^= 0xff
	if _, _, err := unmarshalPayloadFrame(packet); err == nil {
		t.Fatal("unmarshalPayloadFrame() succeeded after tampering")
	}

	control := controlPacket(protocol.TypeFIN, 19, peerAddr, sessionToken)
	if _, _, err := unmarshalPayloadFrame(control); err != nil {
		t.Fatalf("control packet frame validation failed: %v", err)
	}
}

func TestSendMessageSlidesWindowOnOutOfOrderACKs(t *testing.T) {
	sessionConn := mustListenUDP(t)
	defer sessionConn.Close()

	routerConn := mustListenUDP(t)
	defer routerConn.Close()

	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 9100}
	session := newDialedSession(sessionConn, localUDPAddr(t, routerConn), peerAddr, 0x55aa, Config{
		WindowSize: 2,
		Timeout:    150 * time.Millisecond,
		MinTimeout: 50 * time.Millisecond,
		MaxTimeout: 500 * time.Millisecond,
	}.normalized())
	defer session.Close()

	payload := bytes.Repeat([]byte("z"), 2*(protocol.MaxPayloadSize-frameHeaderSize)+32)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- session.SendMessage(ctx, payload, 10)
	}()

	packet1 := readPacket(t, routerConn, 500*time.Millisecond)
	assertPacket(t, packet1, protocol.TypeData, 10)

	packet2 := readPacket(t, routerConn, 500*time.Millisecond)
	assertPacket(t, packet2, protocol.TypeData, 11)

	writePacket(t, routerConn, localUDPAddr(t, sessionConn), ackPacket(protocol.TypeDataACK, 12, peerAddr, session.token))
	assertNoPacket(t, routerConn, 60*time.Millisecond)

	writePacket(t, routerConn, localUDPAddr(t, sessionConn), ackPacket(protocol.TypeDataACK, 11, peerAddr, session.token))

	packet3 := readPacket(t, routerConn, 500*time.Millisecond)
	assertPacket(t, packet3, protocol.TypeData, 12)

	writePacket(t, routerConn, localUDPAddr(t, sessionConn), ackPacket(protocol.TypeDataACK, 13, peerAddr, session.token))

	fin := readPacket(t, routerConn, 500*time.Millisecond)
	assertPacket(t, fin, protocol.TypeFIN, 13)

	writePacket(t, routerConn, localUDPAddr(t, sessionConn), ackPacket(protocol.TypeFINACK, 14, peerAddr, session.token))

	if err := <-errCh; err != nil {
		t.Fatalf("SendMessage() error = %v", err)
	}
}

func TestReceiveMessageAssemblesOutOfOrderData(t *testing.T) {
	sessionConn := mustListenUDP(t)
	defer sessionConn.Close()

	routerConn := mustListenUDP(t)
	defer routerConn.Close()

	peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 9200}
	session := newDialedSession(sessionConn, localUDPAddr(t, routerConn), peerAddr, 0x77bb, Config{
		WindowSize: 3,
		Timeout:    150 * time.Millisecond,
		MinTimeout: 50 * time.Millisecond,
		MaxTimeout: 500 * time.Millisecond,
	}.normalized())
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type result struct {
		payload []byte
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		payload, err := session.ReceiveMessage(ctx, 1)
		resultCh <- result{payload: payload, err: err}
	}()

	writePacket(t, routerConn, localUDPAddr(t, sessionConn), dataPacket(2, peerAddr, session.token, []byte("world")))
	assertPacket(t, readPacket(t, routerConn, 500*time.Millisecond), protocol.TypeDataACK, 3)

	writePacket(t, routerConn, localUDPAddr(t, sessionConn), dataPacket(1, peerAddr, session.token, []byte("hello ")))
	assertPacket(t, readPacket(t, routerConn, 500*time.Millisecond), protocol.TypeDataACK, 2)

	writePacket(t, routerConn, localUDPAddr(t, sessionConn), ackPacket(protocol.TypeFIN, 3, peerAddr, session.token))
	assertPacket(t, readPacket(t, routerConn, 500*time.Millisecond), protocol.TypeFINACK, 4)

	received := <-resultCh
	if received.err != nil {
		t.Fatalf("ReceiveMessage() error = %v", received.err)
	}
	if string(received.payload) != "hello world" {
		t.Fatalf("payload = %q, want %q", received.payload, "hello world")
	}
}

func TestSendMessageRejectsOversizedPayload(t *testing.T) {
	sessionConn := mustListenUDP(t)
	defer sessionConn.Close()

	routerConn := mustListenUDP(t)
	defer routerConn.Close()

	session := newDialedSession(
		sessionConn,
		localUDPAddr(t, routerConn),
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 9300},
		0x99cc,
		Config{MaxMessageSize: 16}.normalized(),
	)
	defer session.Close()

	err := session.SendMessage(context.Background(), bytes.Repeat([]byte("a"), 17), 1)
	if err == nil {
		t.Fatal("SendMessage() succeeded for oversized payload")
	}
}

func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}

	return conn
}

func localUDPAddr(t *testing.T, conn *net.UDPConn) *net.UDPAddr {
	t.Helper()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("LocalAddr() is not a UDP address")
	}

	cloned := cloneUDPAddr(addr)
	if cloned.IP == nil || cloned.IP.IsUnspecified() {
		cloned.IP = net.IPv4(127, 0, 0, 1).To4()
	}

	return cloned
}

func readPacket(t *testing.T, conn *net.UDPConn, timeout time.Duration) protocol.Packet {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	var buffer [protocol.MaxPacketSize]byte
	n, _, err := conn.ReadFromUDP(buffer[:])
	if err != nil {
		t.Fatalf("ReadFromUDP() error = %v", err)
	}

	packet, err := protocol.UnmarshalPacket(buffer[:n])
	if err != nil {
		t.Fatalf("UnmarshalPacket() error = %v", err)
	}

	return packet
}

func assertNoPacket(t *testing.T, conn *net.UDPConn, timeout time.Duration) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	var buffer [protocol.MaxPacketSize]byte
	if _, _, err := conn.ReadFromUDP(buffer[:]); err == nil {
		t.Fatal("unexpected packet arrived")
	} else if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("ReadFromUDP() error = %v, want timeout", err)
	}
}

func writePacket(t *testing.T, conn *net.UDPConn, destination *net.UDPAddr, packet protocol.Packet) {
	t.Helper()

	raw, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	if _, err := conn.WriteToUDP(raw, destination); err != nil {
		t.Fatalf("WriteToUDP() error = %v", err)
	}
}

func assertPacket(t *testing.T, packet protocol.Packet, packetType protocol.PacketType, sequence uint32) {
	t.Helper()

	if packet.Type != packetType {
		t.Fatalf("packet type = %s, want %s", packet.Type, packetType)
	}
	if packet.Seq != sequence {
		t.Fatalf("packet sequence = %d, want %d", packet.Seq, sequence)
	}
}

func ackPacket(packetType protocol.PacketType, sequence uint32, peerAddr *net.UDPAddr, token uint64) protocol.Packet {
	return protocol.Packet{
		Type:     packetType,
		Seq:      sequence,
		PeerIP:   append(net.IP(nil), peerAddr.IP...),
		PeerPort: uint16(peerAddr.Port),
		Payload:  marshalPayloadFrame(packetType, sequence, peerAddr, token, nil),
	}
}

func dataPacket(sequence uint32, peerAddr *net.UDPAddr, token uint64, body []byte) protocol.Packet {
	return protocol.Packet{
		Type:     protocol.TypeData,
		Seq:      sequence,
		PeerIP:   append(net.IP(nil), peerAddr.IP...),
		PeerPort: uint16(peerAddr.Port),
		Payload:  marshalPayloadFrame(protocol.TypeData, sequence, peerAddr, token, body),
	}
}
