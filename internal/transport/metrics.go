package transport

import (
	"fmt"
	"sync/atomic"
	"time"
)

type Metrics struct {
	startedAt            time.Time
	sessionsAccepted     atomic.Uint64
	sessionsDialed       atomic.Uint64
	sessionsClosed       atomic.Uint64
	activeSessions       atomic.Int64
	packetsSent          atomic.Uint64
	packetsReceived      atomic.Uint64
	packetsDropped       atomic.Uint64
	packetsRetransmitted atomic.Uint64
	ackPacketsReceived   atomic.Uint64
	bytesSent            atomic.Uint64
	bytesReceived        atomic.Uint64
	rttSamples           atomic.Uint64
	lastRTONanos         atomic.Int64
}

type Snapshot struct {
	Uptime               time.Duration
	SessionsAccepted     uint64
	SessionsDialed       uint64
	SessionsClosed       uint64
	ActiveSessions       int64
	PacketsSent          uint64
	PacketsReceived      uint64
	PacketsDropped       uint64
	PacketsRetransmitted uint64
	AckPacketsReceived   uint64
	BytesSent            uint64
	BytesReceived        uint64
	RTTSamples           uint64
	LastRTO              time.Duration
}

func NewMetrics() *Metrics {
	return &Metrics{
		startedAt: time.Now(),
	}
}

func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}

	return Snapshot{
		Uptime:               time.Since(m.startedAt),
		SessionsAccepted:     m.sessionsAccepted.Load(),
		SessionsDialed:       m.sessionsDialed.Load(),
		SessionsClosed:       m.sessionsClosed.Load(),
		ActiveSessions:       m.activeSessions.Load(),
		PacketsSent:          m.packetsSent.Load(),
		PacketsReceived:      m.packetsReceived.Load(),
		PacketsDropped:       m.packetsDropped.Load(),
		PacketsRetransmitted: m.packetsRetransmitted.Load(),
		AckPacketsReceived:   m.ackPacketsReceived.Load(),
		BytesSent:            m.bytesSent.Load(),
		BytesReceived:        m.bytesReceived.Load(),
		RTTSamples:           m.rttSamples.Load(),
		LastRTO:              time.Duration(m.lastRTONanos.Load()),
	}
}

func (s Snapshot) String() string {
	return fmt.Sprintf(
		"uptime=%s active_sessions=%d accepted=%d dialed=%d closed=%d packets_sent=%d packets_received=%d packets_dropped=%d retransmissions=%d ack_packets=%d bytes_sent=%d bytes_received=%d rtt_samples=%d last_rto=%s",
		s.Uptime.Truncate(time.Millisecond),
		s.ActiveSessions,
		s.SessionsAccepted,
		s.SessionsDialed,
		s.SessionsClosed,
		s.PacketsSent,
		s.PacketsReceived,
		s.PacketsDropped,
		s.PacketsRetransmitted,
		s.AckPacketsReceived,
		s.BytesSent,
		s.BytesReceived,
		s.RTTSamples,
		s.LastRTO.Truncate(time.Millisecond),
	)
}

func (m *Metrics) onSessionAccepted() {
	if m == nil {
		return
	}

	m.sessionsAccepted.Add(1)
	m.activeSessions.Add(1)
}

func (m *Metrics) onSessionDialed() {
	if m == nil {
		return
	}

	m.sessionsDialed.Add(1)
	m.activeSessions.Add(1)
}

func (m *Metrics) onSessionClosed() {
	if m == nil {
		return
	}

	m.sessionsClosed.Add(1)
	m.activeSessions.Add(-1)
}

func (m *Metrics) onPacketSent(packetBytes int, retransmission bool) {
	if m == nil {
		return
	}

	m.packetsSent.Add(1)
	m.bytesSent.Add(uint64(packetBytes))
	if retransmission {
		m.packetsRetransmitted.Add(1)
	}
}

func (m *Metrics) onPacketReceived(packetBytes int, ack bool) {
	if m == nil {
		return
	}

	m.packetsReceived.Add(1)
	m.bytesReceived.Add(uint64(packetBytes))
	if ack {
		m.ackPacketsReceived.Add(1)
	}
}

func (m *Metrics) onPacketDropped() {
	if m == nil {
		return
	}

	m.packetsDropped.Add(1)
}

func (m *Metrics) onRTTSample(rto time.Duration) {
	if m == nil {
		return
	}

	m.rttSamples.Add(1)
	m.onRTOChange(rto)
}

func (m *Metrics) onRTOChange(rto time.Duration) {
	if m == nil {
		return
	}

	m.lastRTONanos.Store(rto.Nanoseconds())
}
