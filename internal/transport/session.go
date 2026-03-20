package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"selective-repeat-implementation/internal/protocol"
)

type Listener struct {
	conn      *net.UDPConn
	config    Config
	acceptCh  chan *Session
	errCh     chan error
	closeCh   chan struct{}
	closeOnce sync.Once
	writeMu   sync.Mutex

	mu       sync.Mutex
	sessions map[string]*Session
}

type Session struct {
	conn       *net.UDPConn
	routerAddr *net.UDPAddr
	peerAddr   *net.UDPAddr
	config     Config
	ownsConn   bool
	writeMu    *sync.Mutex
	sessionKey string
	token      uint64

	inbox     chan packetEnvelope
	release   func()
	done      chan struct{}
	closeOnce sync.Once

	rto     *rtoEstimator
	metrics *Metrics

	statsMu              sync.Mutex
	startedAt            time.Time
	handshakeRTT         time.Duration
	packetsSent          uint64
	packetsReceived      uint64
	packetsRetransmitted uint64
	ackPacketsReceived   uint64
	bytesSent            uint64
	bytesReceived        uint64
	rttSamples           uint64
}

type SessionSnapshot struct {
	RemoteAddr           string
	Lifetime             time.Duration
	HandshakeRTT         time.Duration
	CurrentRTO           time.Duration
	PacketsSent          uint64
	PacketsReceived      uint64
	PacketsRetransmitted uint64
	AckPacketsReceived   uint64
	BytesSent            uint64
	BytesReceived        uint64
	RTTSamples           uint64
}

type packetEnvelope struct {
	packet protocol.Packet
	sender *net.UDPAddr
	size   int
	valid  bool
}

type inflightPacket struct {
	packet        protocol.Packet
	sentAt        time.Time
	retransmitted bool
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func Listen(port int, config Config) (*Listener, error) {
	normalized := config.normalized()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	listener := &Listener{
		conn:     conn,
		config:   normalized,
		acceptCh: make(chan *Session, normalized.SessionQueueSize),
		errCh:    make(chan error, 1),
		closeCh:  make(chan struct{}),
		sessions: make(map[string]*Session),
	}

	go listener.serve()

	return listener, nil
}

func (l *Listener) Accept(ctx context.Context) (*Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case session := <-l.acceptCh:
		return session, nil
	case err := <-l.errCh:
		return nil, err
	case <-l.closeCh:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *Listener) Addr() *net.UDPAddr {
	if l == nil || l.conn == nil {
		return nil
	}

	addr, _ := l.conn.LocalAddr().(*net.UDPAddr)
	return cloneUDPAddr(addr)
}

func (l *Listener) Close() error {
	var closeErr error

	l.closeOnce.Do(func() {
		close(l.closeCh)
		closeErr = l.conn.Close()

		l.mu.Lock()
		sessions := make([]*Session, 0, len(l.sessions))
		for _, session := range l.sessions {
			sessions = append(sessions, session)
		}
		l.sessions = make(map[string]*Session)
		l.mu.Unlock()

		for _, session := range sessions {
			session.Close()
		}
	})

	return closeErr
}

func (l *Listener) serve() {
	var buffer [protocol.MaxPacketSize]byte

	for {
		n, sender, err := l.conn.ReadFromUDP(buffer[:])
		if err != nil {
			if l.isClosing() || errors.Is(err, net.ErrClosed) {
				return
			}

			select {
			case l.errCh <- err:
			default:
			}

			return
		}

		packet, err := protocol.UnmarshalPacket(buffer[:n])
		if err != nil {
			l.config.Metrics.onPacketDropped()
			l.logf("discarding malformed packet from %s: %v", sender, err)
			continue
		}

		sessionToken, payload, err := unmarshalPayloadFrame(packet)
		if err != nil {
			l.config.Metrics.onPacketDropped()
			l.logf("discarding unauthenticated packet from %s: %v", sender, err)
			continue
		}
		packet.Payload = payload

		key := sessionKey(sender, packet.PeerAddr(), sessionToken)
		session := l.sessionForKey(key)
		if session == nil {
			if packet.Type != protocol.TypeSYN {
				l.config.Metrics.onPacketDropped()
				l.logf("dropping %s seq=%d for unknown session from %s", packet.Type, packet.Seq, sender)
				continue
			}

			session = newAcceptedSession(l.conn, sender, packet.PeerAddr(), sessionToken, l.config, l.releaseFunc(key), &l.writeMu)
			l.storeSession(key, session)

			if err := session.sendControl(protocol.TypeSYNACK, packet.Seq+1, false); err != nil {
				session.Close()
				l.logf("failed to send SYN-ACK to %s: %v", session.peerAddr, err)
				continue
			}

			l.logf("accepted session from %s via %s", session.peerAddr, session.routerAddr)

			select {
			case l.acceptCh <- session:
			default:
				l.config.Metrics.onPacketDropped()
				session.logf("dropping new session: accept queue is full")
				session.Close()
			}

			continue
		}

		if !session.enqueue(packetEnvelope{
			packet: packet,
			sender: cloneUDPAddr(sender),
			size:   n,
			valid:  true,
		}) {
			l.config.Metrics.onPacketDropped()
			session.logf("dropping %s seq=%d: session queue is full", packet.Type, packet.Seq)
		}
	}
}

func (l *Listener) sessionForKey(key string) *Session {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.sessions[key]
}

func (l *Listener) storeSession(key string, session *Session) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sessions[key] = session
}

func (l *Listener) releaseFunc(key string) func() {
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()

		delete(l.sessions, key)
	}
}

func (l *Listener) isClosing() bool {
	select {
	case <-l.closeCh:
		return true
	default:
		return false
	}
}

func (l *Listener) logf(format string, args ...any) {
	if l.config.LogEvents {
		l.config.Logger.Printf(format, args...)
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

	sessionToken, err := randomUint64NonZero()
	if err != nil {
		conn.Close()
		return nil, err
	}

	sequence, err := randomUint32NonZero()
	if err != nil {
		conn.Close()
		return nil, err
	}

	session := newDialedSession(conn, routerAddr, peerAddr, sessionToken, normalized)
	synPacket := controlPacket(protocol.TypeSYN, sequence, session.peerAddr, session.token)

	if err := session.sendPacket(synPacket, false); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send SYN: %w", err)
	}

	sentAt := time.Now()
	retransmitted := false

	for {
		packet, _, err := session.readPacket(ctx, pollInterval(session.currentRTO()))
		if err != nil {
			if isTimeout(err) {
				if time.Since(sentAt) >= session.currentRTO() {
					session.backoffRTO("SYN timeout")
					if err := session.sendPacket(synPacket, true); err != nil {
						session.Close()
						return nil, fmt.Errorf("resend SYN: %w", err)
					}

					sentAt = time.Now()
					retransmitted = true
				}

				continue
			}

			session.Close()
			return nil, err
		}

		if packet.Type != protocol.TypeSYNACK || packet.Seq != sequence+1 {
			continue
		}

		if !retransmitted {
			sample := time.Since(sentAt)
			session.recordHandshakeRTT(sample)
			session.noteRTTSample(sample)
			session.logf("dial established handshake_rtt=%s rto=%s", sample.Truncate(time.Millisecond), session.currentRTO().Truncate(time.Millisecond))
		} else {
			session.logf("dial established after retransmission rto=%s", session.currentRTO().Truncate(time.Millisecond))
		}
		return session, nil
	}
}

func (s *Session) RemoteAddr() *net.UDPAddr {
	return cloneUDPAddr(s.peerAddr)
}

func (s *Session) Snapshot() SessionSnapshot {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	return SessionSnapshot{
		RemoteAddr:           s.peerAddr.String(),
		Lifetime:             time.Since(s.startedAt),
		HandshakeRTT:         s.handshakeRTT,
		CurrentRTO:           s.currentRTO(),
		PacketsSent:          s.packetsSent,
		PacketsReceived:      s.packetsReceived,
		PacketsRetransmitted: s.packetsRetransmitted,
		AckPacketsReceived:   s.ackPacketsReceived,
		BytesSent:            s.bytesSent,
		BytesReceived:        s.bytesReceived,
		RTTSamples:           s.rttSamples,
	}
}

func (s SessionSnapshot) String() string {
	return fmt.Sprintf(
		"remote=%s lifetime=%s handshake_rtt=%s current_rto=%s packets_sent=%d packets_received=%d retransmissions=%d ack_packets=%d bytes_sent=%d bytes_received=%d rtt_samples=%d",
		s.RemoteAddr,
		s.Lifetime.Truncate(time.Millisecond),
		s.HandshakeRTT.Truncate(time.Millisecond),
		s.CurrentRTO.Truncate(time.Millisecond),
		s.PacketsSent,
		s.PacketsReceived,
		s.PacketsRetransmitted,
		s.AckPacketsReceived,
		s.BytesSent,
		s.BytesReceived,
		s.RTTSamples,
	)
}

func (s *Session) Close() error {
	var closeErr error

	s.closeOnce.Do(func() {
		close(s.done)

		if s.release != nil {
			s.release()
		}

		if s.metrics != nil {
			s.metrics.onSessionClosed()
		}

		if s.ownsConn && s.conn != nil {
			closeErr = s.conn.Close()
		}

		s.logf("session closed %s", s.Snapshot())
	})

	return closeErr
}

func (s *Session) SendMessage(ctx context.Context, payload []byte, startSeq uint32) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if startSeq == 0 {
		return fmt.Errorf("start sequence must be greater than zero")
	}
	if len(payload) > s.config.MaxMessageSize {
		return fmt.Errorf("message exceeds maximum size: %d > %d", len(payload), s.config.MaxMessageSize)
	}

	packets := segmentPayload(payload, startSeq, s.peerAddr, s.token)
	inflight := make(map[uint32]*inflightPacket, len(packets))
	acked := make(map[uint32]bool, len(packets))
	sendBase := startSeq
	nextIndex := 0
	limit := startSeq + uint32(len(packets))

	for sendBase < limit {
		for nextIndex < len(packets) && packets[nextIndex].Seq < sendBase+uint32(s.config.WindowSize) {
			// Store an immutable copy for retransmission so later slice reuse
			// cannot corrupt in-flight packet state.
			packet := clonePacket(packets[nextIndex])
			if err := s.sendPacket(packet, false); err != nil {
				return err
			}

			inflight[packet.Seq] = &inflightPacket{
				packet: packet,
				sentAt: time.Now(),
			}
			nextIndex++
		}

		packet, _, err := s.readPacket(ctx, pollInterval(s.currentRTO()))
		if err != nil {
			if isTimeout(err) {
				if _, err := s.resendExpired(inflight); err != nil {
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

		if state, ok := inflight[ackSeq]; ok {
			if !state.retransmitted {
				s.noteRTTSample(time.Since(state.sentAt))
			}
			delete(inflight, ackSeq)
		}

		acked[ackSeq] = true
		for sendBase < limit && acked[sendBase] {
			delete(acked, sendBase)
			sendBase++
		}
	}

	finPacket := controlPacket(protocol.TypeFIN, limit, s.peerAddr, s.token)
	if err := s.sendPacket(finPacket, false); err != nil {
		return err
	}

	finSentAt := time.Now()
	finRetransmitted := false

	for {
		packet, _, err := s.readPacket(ctx, pollInterval(s.currentRTO()))
		if err != nil {
			if isTimeout(err) {
				if time.Since(finSentAt) >= s.currentRTO() {
					s.backoffRTO("FIN timeout")
					if err := s.sendPacket(finPacket, true); err != nil {
						return err
					}

					finSentAt = time.Now()
					finRetransmitted = true
				}
				continue
			}

			return err
		}

		if packet.Type == protocol.TypeFINACK && packet.Seq == finPacket.Seq+1 {
			if !finRetransmitted {
				s.noteRTTSample(time.Since(finSentAt))
			}
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
	bufferedBytes := 0
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
			if err := s.sendControl(protocol.TypeSYNACK, packet.Seq+1, false); err != nil {
				return nil, err
			}
		case protocol.TypeData:
			sequence := packet.Seq
			if sequence < expected {
				if err := s.sendControl(protocol.TypeDataACK, sequence+1, false); err != nil {
					return nil, err
				}
				continue
			}

			if sequence >= expected+uint32(s.config.WindowSize) {
				continue
			}

			payload := packet.Payload

			if _, exists := buffered[sequence]; !exists {
				if assembled.Len()+bufferedBytes+len(payload) > s.config.MaxMessageSize {
					return nil, fmt.Errorf("message exceeds maximum size: %d > %d", assembled.Len()+bufferedBytes+len(payload), s.config.MaxMessageSize)
				}
				buffered[sequence] = payload
				bufferedBytes += len(payload)
			}

			if err := s.sendControl(protocol.TypeDataACK, sequence+1, false); err != nil {
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
				bufferedBytes -= len(payload)
				expected++
			}
		case protocol.TypeFIN:
			if err := s.sendControl(protocol.TypeFINACK, packet.Seq+1, false); err != nil {
				return nil, err
			}

			if packet.Seq <= expected {
				return assembled.Bytes(), nil
			}
		}
	}
}

func (s *Session) readPacket(ctx context.Context, maxWait time.Duration) (protocol.Packet, *net.UDPAddr, error) {
	if s.inbox != nil {
		return s.readPacketFromQueue(ctx, maxWait)
	}

	return s.readPacketFromConn(ctx, maxWait)
}

func (s *Session) readPacketFromQueue(ctx context.Context, maxWait time.Duration) (protocol.Packet, *net.UDPAddr, error) {
	wait := waitDurationFromContext(ctx, maxWait)
	timer := time.NewTimer(wait)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return protocol.Packet{}, nil, ctx.Err()
		case <-s.done:
			return protocol.Packet{}, nil, net.ErrClosed
		case envelope := <-s.inbox:
			packet := envelope.packet
			if !envelope.valid {
				validated, err := s.validatePacket(packet)
				if err != nil {
					s.metrics.onPacketDropped()
					s.logf("discarding unauthenticated queued packet seq=%d type=%s: %v", packet.Seq, packet.Type, err)
					continue
				}
				packet = validated
			}

			s.recordPacketReceived(packet, envelope.size)
			return packet, envelope.sender, nil
		case <-timer.C:
			return protocol.Packet{}, nil, timeoutError{}
		}
	}
}

func (s *Session) readPacketFromConn(ctx context.Context, maxWait time.Duration) (protocol.Packet, *net.UDPAddr, error) {
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
			s.metrics.onPacketDropped()
			s.logf("discarding malformed packet from %s: %v", sender, err)
			continue
		}

		if !sameUDPAddr(sender, s.routerAddr) {
			s.metrics.onPacketDropped()
			s.logf("ignoring packet from unexpected sender %s", sender)
			continue
		}

		if !sameUDPAddr(packet.PeerAddr(), s.peerAddr) {
			s.metrics.onPacketDropped()
			s.logf("ignoring packet for unexpected peer %s", packet.PeerAddr())
			continue
		}

		packet, err = s.validatePacket(packet)
		if err != nil {
			s.metrics.onPacketDropped()
			s.logf("discarding unauthenticated packet seq=%d type=%s: %v", packet.Seq, packet.Type, err)
			continue
		}

		s.recordPacketReceived(packet, n)
		return packet, sender, nil
	}
}

func (s *Session) resendExpired(inflight map[uint32]*inflightPacket) (bool, error) {
	if len(inflight) == 0 {
		return false, nil
	}

	now := time.Now()
	timeout := s.currentRTO()
	resent := false
	backedOff := false

	for _, state := range inflight {
		if now.Sub(state.sentAt) < timeout {
			continue
		}

		if !backedOff {
			s.backoffRTO("packet timeout")
			backedOff = true
		}

		if err := s.sendPacket(state.packet, true); err != nil {
			return false, err
		}

		state.sentAt = now
		state.retransmitted = true
		resent = true
		s.logf("retransmitting %s seq=%d", state.packet.Type, state.packet.Seq)
	}

	return resent, nil
}

func (s *Session) enqueue(envelope packetEnvelope) bool {
	select {
	case <-s.done:
		return false
	default:
	}

	select {
	case s.inbox <- envelope:
		return true
	default:
		return false
	}
}

func (s *Session) sendControl(packetType protocol.PacketType, sequence uint32, retransmission bool) error {
	return s.sendPacket(controlPacket(packetType, sequence, s.peerAddr, s.token), retransmission)
}

func (s *Session) sendPacket(packet protocol.Packet, retransmission bool) error {
	raw, err := packet.MarshalBinary()
	if err != nil {
		return err
	}

	if s.writeMu != nil {
		s.writeMu.Lock()
		defer s.writeMu.Unlock()
	}

	if _, err := s.conn.WriteToUDP(raw, s.routerAddr); err != nil {
		return fmt.Errorf("send %s #%d: %w", packet.Type, packet.Seq, err)
	}

	s.recordPacketSent(len(raw), retransmission)

	return nil
}

func (s *Session) validatePacket(packet protocol.Packet) (protocol.Packet, error) {
	sessionToken, payload, err := unmarshalPayloadFrame(packet)
	if err != nil {
		return protocol.Packet{}, err
	}
	if sessionToken != s.token {
		return protocol.Packet{}, fmt.Errorf("unexpected session token")
	}

	packet.Payload = payload
	return packet, nil
}

func (s *Session) currentRTO() time.Duration {
	return s.rto.Current()
}

func (s *Session) backoffRTO(reason string) {
	newRTO := s.rto.Backoff()
	s.metrics.onRTOChange(newRTO)
	s.logf("%s -> rto=%s", reason, newRTO.Truncate(time.Millisecond))
}

func (s *Session) noteRTTSample(sample time.Duration) {
	newRTO := s.rto.NoteSample(sample)
	s.metrics.onRTTSample(newRTO)

	s.statsMu.Lock()
	s.rttSamples++
	s.statsMu.Unlock()

	s.logf("rtt_sample=%s updated_rto=%s", sample.Truncate(time.Millisecond), newRTO.Truncate(time.Millisecond))
}

func (s *Session) recordHandshakeRTT(sample time.Duration) {
	s.statsMu.Lock()
	s.handshakeRTT = sample
	s.statsMu.Unlock()
}

func (s *Session) recordPacketSent(packetBytes int, retransmission bool) {
	s.statsMu.Lock()
	s.packetsSent++
	s.bytesSent += uint64(packetBytes)
	if retransmission {
		s.packetsRetransmitted++
	}
	s.statsMu.Unlock()

	s.metrics.onPacketSent(packetBytes, retransmission)
}

func (s *Session) recordPacketReceived(packet protocol.Packet, packetBytes int) {
	s.statsMu.Lock()
	s.packetsReceived++
	s.bytesReceived += uint64(packetBytes)
	if isAckPacket(packet.Type) {
		s.ackPacketsReceived++
	}
	s.statsMu.Unlock()

	s.metrics.onPacketReceived(packetBytes, isAckPacket(packet.Type))
}

func (s *Session) logf(format string, args ...any) {
	if s.config.LogEvents {
		s.config.Logger.Printf("transport remote=%s "+format, append([]any{s.peerAddr}, args...)...)
	}
}

func newAcceptedSession(conn *net.UDPConn, routerAddr *net.UDPAddr, peerAddr *net.UDPAddr, sessionToken uint64, config Config, release func(), writeMu *sync.Mutex) *Session {
	return newSession(conn, routerAddr, peerAddr, sessionToken, config, false, make(chan packetEnvelope, config.SessionQueueSize), release, writeMu)
}

func newDialedSession(conn *net.UDPConn, routerAddr *net.UDPAddr, peerAddr *net.UDPAddr, sessionToken uint64, config Config) *Session {
	return newSession(conn, routerAddr, peerAddr, sessionToken, config, true, nil, nil, nil)
}

func newSession(conn *net.UDPConn, routerAddr *net.UDPAddr, peerAddr *net.UDPAddr, sessionToken uint64, config Config, ownsConn bool, inbox chan packetEnvelope, release func(), writeMu *sync.Mutex) *Session {
	session := &Session{
		conn:       conn,
		routerAddr: cloneUDPAddr(routerAddr),
		peerAddr:   cloneUDPAddr(peerAddr),
		config:     config,
		ownsConn:   ownsConn,
		writeMu:    writeMu,
		sessionKey: sessionKey(routerAddr, peerAddr, sessionToken),
		token:      sessionToken,
		inbox:      inbox,
		release:    release,
		done:       make(chan struct{}),
		rto:        newRTOEstimator(config.Timeout, config.MinTimeout, config.MaxTimeout),
		metrics:    config.Metrics,
		startedAt:  time.Now(),
	}

	session.metrics.onRTOChange(session.currentRTO())
	if ownsConn {
		session.metrics.onSessionDialed()
	} else {
		session.metrics.onSessionAccepted()
	}

	session.logf("session opened current_rto=%s", session.currentRTO().Truncate(time.Millisecond))

	return session
}

func controlPacket(packetType protocol.PacketType, sequence uint32, peerAddr *net.UDPAddr, sessionToken uint64) protocol.Packet {
	return protocol.Packet{
		Type:     packetType,
		Seq:      sequence,
		PeerIP:   cloneIP(peerAddr.IP),
		PeerPort: uint16(peerAddr.Port),
		Payload:  marshalPayloadFrame(packetType, sequence, peerAddr, sessionToken, nil),
	}
}

func clonePacket(packet protocol.Packet) protocol.Packet {
	packet.PeerIP = cloneIP(packet.PeerIP)
	packet.Payload = append([]byte(nil), packet.Payload...)
	return packet
}

func segmentPayload(payload []byte, startSeq uint32, peerAddr *net.UDPAddr, sessionToken uint64) []protocol.Packet {
	if len(payload) == 0 {
		return nil
	}

	maxChunkSize := protocol.MaxPayloadSize - frameHeaderSize
	packets := make([]protocol.Packet, 0, (len(payload)+maxChunkSize-1)/maxChunkSize)
	sequence := startSeq

	for offset := 0; offset < len(payload); offset += maxChunkSize {
		limit := offset + maxChunkSize
		if limit > len(payload) {
			limit = len(payload)
		}

		chunk := marshalPayloadFrame(protocol.TypeData, sequence, peerAddr, sessionToken, payload[offset:limit])
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

func sessionKey(routerAddr *net.UDPAddr, peerAddr *net.UDPAddr, sessionToken uint64) string {
	return fmt.Sprintf("%s|%s|%016x", routerAddr.String(), peerAddr.String(), sessionToken)
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

func waitDurationFromContext(ctx context.Context, fallback time.Duration) time.Duration {
	if fallback <= 0 {
		fallback = 200 * time.Millisecond
	}

	if ctx == nil {
		return fallback
	}

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Millisecond
		}
		if remaining < fallback {
			return remaining
		}
	}

	return fallback
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

func isAckPacket(packetType protocol.PacketType) bool {
	switch packetType {
	case protocol.TypeSYNACK, protocol.TypeDataACK, protocol.TypeFINACK:
		return true
	default:
		return false
	}
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
