package router

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"selective-repeat-implementation/internal/protocol"
)

type Config struct {
	Port     int
	DropRate float64
	MaxDelay time.Duration
	Seed     int64
	Logger   *log.Logger
}

type Router struct {
	conn      *net.UDPConn
	logger    *log.Logger
	dropRate  float64
	maxDelay  time.Duration
	random    *rand.Rand
	randomMu  sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
	errCh     chan error
}

func Listen(config Config) (*Router, error) {
	if config.Logger == nil {
		config.Logger = log.New(io.Discard, "", 0)
	}
	if config.DropRate < 0 || config.DropRate > 1 {
		return nil, fmt.Errorf("drop rate must be between 0 and 1")
	}

	seed := config.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: config.Port})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	router := &Router{
		conn:     conn,
		logger:   config.Logger,
		dropRate: config.DropRate,
		maxDelay: config.MaxDelay,
		random:   rand.New(rand.NewSource(seed)),
		errCh:    make(chan error, 1),
	}

	go router.serve()

	return router, nil
}

func (r *Router) Addr() *net.UDPAddr {
	if r == nil || r.conn == nil {
		return nil
	}

	addr, _ := r.conn.LocalAddr().(*net.UDPAddr)
	return cloneUDPAddr(addr)
}

func (r *Router) Close() error {
	var closeErr error

	r.closeOnce.Do(func() {
		closeErr = r.conn.Close()
	})

	return closeErr
}

func (r *Router) Err() <-chan error {
	return r.errCh
}

func (r *Router) serve() {
	var buffer [protocol.MaxPacketSize]byte

	for {
		n, sender, err := r.conn.ReadFromUDP(buffer[:])
		if err != nil {
			if isClosedError(err) {
				return
			}

			select {
			case r.errCh <- err:
			default:
			}
			return
		}

		packet, err := protocol.UnmarshalPacket(buffer[:n])
		if err != nil {
			r.logger.Printf("dropping malformed packet from %s: %v", sender, err)
			continue
		}

		if r.shouldDrop() {
			r.logger.Printf("dropping packet type=%s seq=%d from %s to %s", packet.Type, packet.Seq, sender, packet.PeerAddr())
			continue
		}

		destination := packet.PeerAddr()
		packet.PeerIP = append(net.IP(nil), sender.IP.To4()...)
		packet.PeerPort = uint16(sender.Port)
		raw, err := packet.MarshalBinary()
		if err != nil {
			r.logger.Printf("dropping unmarshalable packet from %s: %v", sender, err)
			continue
		}

		delay := r.sampleDelay()
		if delay > 0 {
			time.AfterFunc(delay, func() {
				r.forward(raw, destination, packet.Type, packet.Seq)
			})
			continue
		}

		r.forward(raw, destination, packet.Type, packet.Seq)
	}
}

func (r *Router) forward(raw []byte, destination *net.UDPAddr, packetType protocol.PacketType, sequence uint32) {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	if _, err := r.conn.WriteToUDP(raw, destination); err != nil {
		r.logger.Printf("forward failed type=%s seq=%d to %s: %v", packetType, sequence, destination, err)
		return
	}

	r.logger.Printf("forwarded type=%s seq=%d to %s", packetType, sequence, destination)
}

func (r *Router) shouldDrop() bool {
	if r.dropRate <= 0 {
		return false
	}

	r.randomMu.Lock()
	defer r.randomMu.Unlock()

	return r.random.Float64() < r.dropRate
}

func (r *Router) sampleDelay() time.Duration {
	if r.maxDelay <= 0 {
		return 0
	}

	r.randomMu.Lock()
	defer r.randomMu.Unlock()

	return time.Duration(r.random.Int63n(int64(r.maxDelay) + 1))
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}

	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
