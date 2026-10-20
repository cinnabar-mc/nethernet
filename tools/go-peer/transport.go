package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

// lossyConn drops datagrams in either direction while a deadline is in the future.
type lossyConn struct {
	net.PacketConn
	dropIn, dropOut atomic.Int64 // unix nanoseconds until which traffic is dropped
}

func (c *lossyConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil || time.Now().UnixNano() >= c.dropIn.Load() {
			return n, addr, err
		}
	}
}

func (c *lossyConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if time.Now().UnixNano() < c.dropOut.Load() {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, addr)
}

// drop blackholes the chosen directions for d.
func (c *lossyConn) drop(in, out bool, d time.Duration) {
	until := time.Now().Add(d).UnixNano()
	if in {
		c.dropIn.Store(until)
	}
	if out {
		c.dropOut.Store(until)
	}
}

// loopbackAPI returns a WebRTC API whose ICE uses one 127.0.0.1 socket, so every
// candidate is reachable from a loopback Rust peer and the socket can drop traffic.
func loopbackAPI() (*webrtc.API, *lossyConn, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	conn := &lossyConn{PacketConn: pc}
	var s webrtc.SettingEngine
	s.SetIncludeLoopbackCandidate(true)
	s.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	s.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	s.SetICEUDPMux(webrtc.NewICEUDPMux(nil, conn))
	return webrtc.NewAPI(webrtc.WithSettingEngine(s)), conn, nil
}

// memorySignaling delivers signals between endpoints of one in-process bus.
type memorySignaling struct {
	id  string
	bus *memoryBus
	ctx context.Context

	mu        sync.Mutex
	next      int
	notifiers map[int]nethernet.Notifier
}

type memoryBus struct {
	mu        sync.Mutex
	endpoints map[string]*memorySignaling
	tap       func(from string, s nethernet.Signal) // observes every signal before delivery
}

func (b *memoryBus) endpoint(ctx context.Context, id string) *memorySignaling {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.endpoints == nil {
		b.endpoints = map[string]*memorySignaling{}
	}
	s := &memorySignaling{id: id, bus: b, ctx: ctx, notifiers: map[int]nethernet.Notifier{}}
	b.endpoints[id] = s
	return s
}

func (s *memorySignaling) Signal(_ context.Context, signal *nethernet.Signal) error {
	s.bus.mu.Lock()
	peer, tap := s.bus.endpoints[signal.NetworkID], s.bus.tap
	s.bus.mu.Unlock()
	if tap != nil {
		tap(s.id, *signal)
	}
	if peer == nil {
		return nil
	}
	delivered := *signal
	delivered.NetworkID = s.id
	peer.deliver(&delivered)
	return nil
}

func (s *memorySignaling) deliver(signal *nethernet.Signal) {
	s.mu.Lock()
	notifiers := make([]nethernet.Notifier, 0, len(s.notifiers))
	for _, n := range s.notifiers {
		notifiers = append(notifiers, n)
	}
	s.mu.Unlock()
	for _, n := range notifiers {
		copied := *signal
		n.NotifySignal(&copied)
	}
}

func (s *memorySignaling) Notify(n nethernet.Notifier) func() {
	s.mu.Lock()
	id := s.next
	s.next++
	s.notifiers[id] = n
	s.mu.Unlock()
	return sync.OnceFunc(func() {
		s.mu.Lock()
		delete(s.notifiers, id)
		s.mu.Unlock()
	})
}

func (s *memorySignaling) Context() context.Context { return s.ctx }

func (*memorySignaling) Credentials(context.Context) (*nethernet.Credentials, error) {
	return nil, nil
}

func (s *memorySignaling) NetworkID() string { return s.id }

func (*memorySignaling) PongData([]byte) {}

// connectedPair returns a dialed and an accepted connection over in-process signaling.
func connectedPair(ctx context.Context, trickle bool, tap func(string, nethernet.Signal)) (client, server *nethernet.Conn, closeAll func(), err error) {
	clientAPI, _, err := loopbackAPI()
	if err != nil {
		return nil, nil, nil, err
	}
	serverAPI, _, err := loopbackAPI()
	if err != nil {
		return nil, nil, nil, err
	}
	bus := &memoryBus{tap: tap}
	sigCtx, cancel := context.WithCancel(context.Background())
	clientSig, serverSig := bus.endpoint(sigCtx, "client"), bus.endpoint(sigCtx, "server")

	l, err := nethernet.ListenConfig{
		API:               serverAPI,
		AllowAnonymous:    true,
		DisableTrickleICE: !trickle,
		Log:               quietLog,
	}.Listen(serverSig)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	client, err = nethernet.Dialer{
		API:                     clientAPI,
		AllowIdentitylessServer: true,
		DisableTrickleICE:       !trickle,
		Log:                     quietLog,
	}.DialContext(ctx, "server", clientSig)
	if err != nil {
		_ = l.Close()
		cancel()
		return nil, nil, nil, fmt.Errorf("dial: %w", err)
	}
	select {
	case c := <-accepted:
		server = c.(*nethernet.Conn)
	case <-ctx.Done():
		_ = client.Close()
		_ = l.Close()
		cancel()
		return nil, nil, nil, ctx.Err()
	}
	return client, server, func() {
		_ = client.Close()
		_ = server.Close()
		_ = l.Close()
		cancel()
	}, nil
}
