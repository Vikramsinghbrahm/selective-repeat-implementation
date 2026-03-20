package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"selective-repeat-implementation/internal/protocol"
)

type Listener struct {
	conn   *net.UDPConn
	config Config
}

type Session struct {
	conn       *net.UDPConn
	routerAddr *net.UDPAddr
	peerAddr   *net.UDPAddr
	config     Config
	ownsConn   bool
}

func Listen(port int, config Config) (*Listener, error) {
	normalized := config.normalized()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	return &Listener{
		conn:   conn,
		config: normalized,
	}, nil
}

func (l *Listener) Close() error {
	return l.conn.Close()
}

func (l *Listener) Accept(ctx context.Context) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var buffer [protocol.MaxPacketSize]byte
	for {
		if err := l.conn.SetReadDeadline(deadlineFromContext(ctx, l.config.Timeout)); err != nil {
			return nil, err
		}

		n, sender, err := l.conn.ReadFromUDP(buffer[:])
		if err != nil {
			if isTimeout(err) && ctx.Err() == nil {
				continue
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}

		packet, err := protocol.UnmarshalPacket(buffer[:n])
		if err != nil {
			l.config.Logger.Printf("discarding malformed packet: %v", err)
			continue
		}

		if packet.Type != protocol.TypeSYN {
			l.config.Logger.Printf("ignoring %s from %s while waiting for SYN", packet.Type, sender)
			continue
		}

		session := &Session{
			conn:       l.conn,
			routerAddr: cloneUDPAddr(sender),
			peerAddr:   cloneUDPAddr(packet.PeerAddr()),
			config:     l.config,
			ownsConn:   false,
		}

		if err := session.sendControl(protocol.TypeSYNACK, packet.Seq+1); err != nil {
			return nil, fmt.Errorf("send SYN-ACK: %w", err)
		}

		l.config.Logger.Printf("accepted session from %s via %s", session.peerAddr, session.routerAddr)
		return session, nil
	}
}

func DialContext(ctx context.Context, routerAddr *net.UDPAddr, peerAddr *net.UDPAddr, config Config) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if routerAddr == nil {
		return nil, fmt.Errorf("router address is required")
	}
	if peerAddr == nil {
		return nil, fmt.Errorf("peer address is required")
	}
	if peerAddr.IP == nil || peerAddr.IP.To4() == nil {
		return nil, fmt.Errorf("peer address must be IPv4")
	}

	normalized := config.normalized()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("open udp socket: %w", err)
	}

	session := &Session{
		conn:       conn,
		routerAddr: cloneUDPAddr(routerAddr),
		peerAddr:   cloneUDPAddr(peerAddr),
		config:     normalized,
		ownsConn:   true,
	}

	seq := uint32(1)
	lastSent := time.Time{}
	wait := pollInterval(normalized.Timeout)

	for {
		if lastSent.IsZero() || time.Since(lastSent) >= normalized.Timeout {
			if err := session.sendControl(protocol.TypeSYN, seq); err != nil {
				conn.Close()
				return nil, fmt.Errorf("send SYN: %w", err)
			}
			lastSent = time.Now()
		}

		packet, _, err := session.readPacket(ctx, wait)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			conn.Close()
			return nil, err
		}

		if packet.Type == protocol.TypeSYNACK && packet.Seq == seq+1 {
			return session, nil
		}
	}
}

func (s *Session) RemoteAddr() *net.UDPAddr {
	return cloneUDPAddr(s.peerAddr)
}

func (s *Session) Close() error {
	if s.ownsConn && s.conn != nil {
		return s.conn.Close()
	}

	return nil
}

func (s *Session) SendMessage(ctx context.Context, payload []byte, startSeq uint32) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if startSeq == 0 {
		return fmt.Errorf("start sequence must be greater than zero")
	}

	packets := segmentPayload(payload, startSeq, s.peerAddr)
	packetsBySeq := make(map[uint32]protocol.Packet, len(packets))
	for _, packet := range packets {
		packetsBySeq[packet.Seq] = packet
	}

	sendBase := startSeq
	nextIndex := 0
	limit := startSeq + uint32(len(packets))
	acked := make(map[uint32]bool, len(packets))
	sentAt := make(map[uint32]time.Time, len(packets))
	wait := pollInterval(s.config.Timeout)

	for sendBase < limit {
		for nextIndex < len(packets) && packets[nextIndex].Seq < sendBase+uint32(s.config.WindowSize) {
			packet := packets[nextIndex]
			if err := s.sendPacket(packet); err != nil {
				return err
			}

			sentAt[packet.Seq] = time.Now()
			nextIndex++
		}

		packet, _, err := s.readPacket(ctx, wait)
		if err != nil {
			if isTimeout(err) {
				if err := s.resendExpired(packetsBySeq, sentAt); err != nil {
					return err
				}
				continue
			}

			return err
		}

		if packet.Type != protocol.TypeDataACK || packet.Seq == 0 {
			continue
		}

		ackSeq := packet.Seq - 1
		if ackSeq < startSeq || ackSeq >= limit {
			continue
		}

		acked[ackSeq] = true
		delete(sentAt, ackSeq)
		for sendBase < limit && acked[sendBase] {
			delete(acked, sendBase)
			sendBase++
		}
	}

	finSeq := limit
	lastSent := time.Time{}
	for {
		if lastSent.IsZero() || time.Since(lastSent) >= s.config.Timeout {
			if err := s.sendControl(protocol.TypeFIN, finSeq); err != nil {
				return err
			}
			lastSent = time.Now()
		}

		packet, _, err := s.readPacket(ctx, wait)
		if err != nil {
			if isTimeout(err) {
				continue
			}

			return err
		}

		if packet.Type == protocol.TypeFINACK && packet.Seq == finSeq+1 {
			return nil
		}
	}
}

func (s *Session) ReceiveMessage(ctx context.Context, startSeq uint32) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if startSeq == 0 {
		return nil, fmt.Errorf("start sequence must be greater than zero")
	}

	expected := startSeq
	buffered := make(map[uint32][]byte)
	var assembled bytes.Buffer

	for {
		packet, _, err := s.readPacket(ctx, s.config.Timeout)
		if err != nil {
			if isTimeout(err) {
				continue
			}

			return nil, err
		}

		switch packet.Type {
		case protocol.TypeSYN:
			if err := s.sendControl(protocol.TypeSYNACK, packet.Seq+1); err != nil {
				return nil, err
			}
		case protocol.TypeData:
			sequence := packet.Seq
			if sequence < expected {
				if err := s.sendControl(protocol.TypeDataACK, sequence+1); err != nil {
					return nil, err
				}
				continue
			}

			if sequence >= expected+uint32(s.config.WindowSize) {
				continue
			}

			if _, exists := buffered[sequence]; !exists {
				buffered[sequence] = append([]byte(nil), packet.Payload...)
			}

			if err := s.sendControl(protocol.TypeDataACK, sequence+1); err != nil {
				return nil, err
			}

			for {
				payload, ok := buffered[expected]
				if !ok {
					break
				}

				if _, err := assembled.Write(payload); err != nil {
					return nil, err
				}

				delete(buffered, expected)
				expected++
			}
		case protocol.TypeFIN:
			if err := s.sendControl(protocol.TypeFINACK, packet.Seq+1); err != nil {
				return nil, err
			}

			if packet.Seq == expected || packet.Seq < expected {
				return assembled.Bytes(), nil
			}
		}
	}
}

func (s *Session) resendExpired(packets map[uint32]protocol.Packet, sentAt map[uint32]time.Time) error {
	now := time.Now()
	for sequence, sentTime := range sentAt {
		if now.Sub(sentTime) < s.config.Timeout {
			continue
		}

		packet, ok := packets[sequence]
		if !ok {
			continue
		}

		if err := s.sendPacket(packet); err != nil {
			return err
		}

		sentAt[sequence] = now
	}

	return nil
}

func (s *Session) readPacket(ctx context.Context, maxWait time.Duration) (protocol.Packet, *net.UDPAddr, error) {
	var buffer [protocol.MaxPacketSize]byte

	for {
		if err := s.conn.SetReadDeadline(deadlineFromContext(ctx, maxWait)); err != nil {
			return protocol.Packet{}, nil, err
		}

		n, sender, err := s.conn.ReadFromUDP(buffer[:])
		if err != nil {
			if isTimeout(err) && ctx.Err() == nil {
				return protocol.Packet{}, nil, err
			}
			if ctx.Err() != nil {
				return protocol.Packet{}, nil, ctx.Err()
			}
			return protocol.Packet{}, nil, err
		}

		packet, err := protocol.UnmarshalPacket(buffer[:n])
		if err != nil {
			s.config.Logger.Printf("discarding malformed packet: %v", err)
			continue
		}

		if !sameUDPAddr(sender, s.routerAddr) {
			s.config.Logger.Printf("ignoring packet from unexpected sender %s", sender)
			continue
		}

		if !sameUDPAddr(packet.PeerAddr(), s.peerAddr) {
			s.config.Logger.Printf("ignoring packet for unexpected peer %s", packet.PeerAddr())
			continue
		}

		return packet, sender, nil
	}
}

func (s *Session) sendControl(packetType protocol.PacketType, sequence uint32) error {
	return s.sendPacket(protocol.Packet{
		Type:     packetType,
		Seq:      sequence,
		PeerIP:   cloneIP(s.peerAddr.IP),
		PeerPort: uint16(s.peerAddr.Port),
	})
}

func (s *Session) sendPacket(packet protocol.Packet) error {
	raw, err := packet.MarshalBinary()
	if err != nil {
		return err
	}

	if _, err := s.conn.WriteToUDP(raw, s.routerAddr); err != nil {
		return fmt.Errorf("send %s #%d: %w", packet.Type, packet.Seq, err)
	}

	return nil
}

func segmentPayload(payload []byte, startSeq uint32, peerAddr *net.UDPAddr) []protocol.Packet {
	if len(payload) == 0 {
		return nil
	}

	packets := make([]protocol.Packet, 0, (len(payload)+protocol.MaxPayloadSize-1)/protocol.MaxPayloadSize)
	sequence := startSeq

	for offset := 0; offset < len(payload); offset += protocol.MaxPayloadSize {
		limit := offset + protocol.MaxPayloadSize
		if limit > len(payload) {
			limit = len(payload)
		}

		chunk := append([]byte(nil), payload[offset:limit]...)
		packets = append(packets, protocol.Packet{
			Type:     protocol.TypeData,
			Seq:      sequence,
			PeerIP:   cloneIP(peerAddr.IP),
			PeerPort: uint16(peerAddr.Port),
			Payload:  chunk,
		})
		sequence++
	}

	return packets
}

func deadlineFromContext(ctx context.Context, fallback time.Duration) time.Time {
	if ctx == nil {
		return time.Now().Add(fallback)
	}

	if deadline, ok := ctx.Deadline(); ok {
		candidate := time.Now().Add(fallback)
		if candidate.After(deadline) {
			return deadline
		}
		return candidate
	}

	return time.Now().Add(fallback)
}

func pollInterval(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 200 * time.Millisecond
	}

	interval := timeout / 4
	if interval < 100*time.Millisecond {
		return 100 * time.Millisecond
	}

	return interval
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}

	return &net.UDPAddr{
		IP:   cloneIP(addr.IP),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return append(net.IP(nil), ip...)
	}

	return append(net.IP(nil), ipv4...)
}

func sameUDPAddr(left *net.UDPAddr, right *net.UDPAddr) bool {
	if left == nil || right == nil {
		return false
	}

	leftIP := left.IP.To4()
	rightIP := right.IP.To4()
	if leftIP == nil || rightIP == nil {
		return false
	}

	return left.Port == right.Port && leftIP.Equal(rightIP)
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
