package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

// events are JSON lines on stdout that the Rust interop tests wait on.
var events = struct {
	sync.Mutex
	enc *json.Encoder
}{enc: json.NewEncoder(os.Stdout)}

func emit(event string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["event"] = event
	events.Lock()
	_ = events.enc.Encode(fields)
	events.Unlock()
}

// runPeer dials or accepts one connection over loopback LAN signaling and serves it.
//
// Reliable messages starting with '!' are commands (see serve); others are echoed.
// Unreliable messages starting with "u:" are counted; others are echoed.
func runPeer(args []string) error {
	fs := flag.NewFlagSet("peer", flag.ContinueOnError)
	role := fs.String("role", "listen", "listen or dial")
	networkID := fs.Uint64("network-id", 0, "local NetherNet network ID")
	remoteID := fs.Uint64("remote-id", 0, "network ID to dial")
	lanAddr := fs.String("lan-addr", "127.0.0.1:0", "LAN discovery bind address")
	broadcast := fs.String("broadcast", "", "where discovery requests go when dialing")
	pong := fs.String("pong", "", "RakNet pong string advertised when listening")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bind, err := freeUDPAddr(*lanAddr)
	if err != nil {
		return err
	}
	// Without a target, requests go to this listener itself, which ignores them,
	// instead of the limited broadcast address.
	conf := discovery.ListenConfig{NetworkID: *networkID, Log: quietLog, BroadcastAddress: bind}
	if *broadcast != "" {
		if conf.BroadcastAddress, err = net.ResolveUDPAddr("udp4", *broadcast); err != nil {
			return err
		}
	}
	lan, err := conf.Listen(bind.String())
	if err != nil {
		return err
	}
	defer lan.Close()
	if *pong != "" {
		lan.PongData([]byte(*pong))
	} else {
		lan.ServerData(&discovery.ServerData{
			ServerName: "go-peer", LevelName: "go-peer", MaxPlayerCount: 8,
			AcceptsOnlineAuth: true, AcceptsSelfSignedAuth: true, ConnectionType: 4,
		})
	}
	api, lossy, err := loopbackAPI()
	if err != nil {
		return err
	}

	var conn *nethernet.Conn
	switch *role {
	case "listen":
		l, err := nethernet.ListenConfig{API: api, AllowAnonymous: true, Log: quietLog}.Listen(lan)
		if err != nil {
			return err
		}
		defer l.Close()
		emit("ready", map[string]any{"addr": bind.String(), "network_id": lan.NetworkID()})
		c, err := l.Accept()
		if err != nil {
			return err
		}
		conn = c.(*nethernet.Conn)
	case "dial":
		emit("ready", map[string]any{"addr": bind.String(), "network_id": lan.NetworkID()})
		data, err := awaitResponse(lan, *remoteID, 20*time.Second)
		if err != nil {
			return err
		}
		var d discovery.ServerData
		if err := d.UnmarshalBinary(data); err != nil {
			emit("discovered", map[string]any{"error": err.Error()})
		} else {
			sd := serverData(d)
			emit("discovered", map[string]any{"server_data": sd})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		conn, err = nethernet.Dialer{API: api, AllowIdentitylessServer: true, Log: quietLog}.
			DialContext(ctx, strconv.FormatUint(*remoteID, 10), lan)
		if err != nil {
			return fmt.Errorf("dial: %w", err)
		}
	default:
		return fmt.Errorf("unknown role %q", *role)
	}
	emit("connected", nil)
	serve(conn, lossy)
	return nil
}

// awaitResponse polls the discovery listener until the remote network answers a request.
func awaitResponse(lan *discovery.Listener, remoteID uint64, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, ok := lan.Responses()[remoteID]; ok {
			return data, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil, fmt.Errorf("network %d never answered discovery", remoteID)
}

// pattern fills n bytes with the payload both sides of the harness expect.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func serve(conn *nethernet.Conn, lossy *lossyConn) {
	var unreliable atomic.Int64
	go func() {
		for {
			pk, err := conn.Receive(nethernet.MessageReliabilityUnreliable)
			if err != nil {
				return
			}
			if bytes.HasPrefix(pk, []byte("u:")) {
				unreliable.Add(1)
				continue
			}
			_, _ = conn.Send(pk, nethernet.MessageReliabilityUnreliable)
		}
	}()
	reply := func(text string) { _, _ = conn.Write([]byte(text)) }
	for {
		pk, err := conn.ReadPacket()
		if err != nil {
			emit("closed", map[string]any{"cause": context.Cause(conn.Context()).Error()})
			return
		}
		if len(pk) == 0 || pk[0] != '!' {
			if _, err := conn.Write(pk); err != nil {
				emit("echo_failed", map[string]any{"size": len(pk), "error": err.Error()})
			}
			continue
		}
		cmd := strings.Fields(string(pk[1:]))
		arg := func(i int) int {
			if i >= len(cmd) {
				return 0
			}
			v, _ := strconv.Atoi(cmd[i])
			return v
		}
		switch cmd[0] {
		case "send": // !send <size>: send a pattern payload, then report the outcome.
			_, err := conn.Write(pattern(arg(1)))
			emit("sent", map[string]any{"size": arg(1), "ok": err == nil})
		case "mark": // !mark: an ordering fence for whatever was sent before it.
			reply("!mark")
		case "close":
			_ = conn.Close()
		case "drop-in": // !drop-in <ms>: drop inbound datagrams while still sending.
			lossy.drop(true, false, time.Duration(arg(1))*time.Millisecond)
			reply("!dropping")
			go func(ms int) {
				time.Sleep(time.Duration(ms) * time.Millisecond)
				reply("!resumed")
			}(arg(1))
		case "blackhole": // !blackhole <ms>: drop all datagrams, then report survival.
			lossy.drop(true, true, time.Duration(arg(1))*time.Millisecond)
			go func(ms int) {
				time.Sleep(time.Duration(ms) * time.Millisecond)
				alive := conn.Context().Err() == nil
				emit("blackhole_over", map[string]any{"alive": alive})
				reply("!resumed")
			}(arg(1))
		case "count-unreliable": // !count-unreliable <want> <ms>: wait for counted messages.
			deadline := time.Now().Add(time.Duration(arg(2)) * time.Millisecond)
			for unreliable.Load() < int64(arg(1)) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			reply("!counted " + strconv.FormatInt(unreliable.Load(), 10))
		default:
			emit("unknown_command", map[string]any{"command": cmd[0]})
		}
	}
}

// freeUDPAddr resolves a zero port to a currently free one, since discovery.Listener
// does not report the address it bound.
func freeUDPAddr(addr string) (*net.UDPAddr, error) {
	udp, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil || udp.Port != 0 {
		return udp, err
	}
	pc, err := net.ListenUDP("udp4", udp)
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr), nil
}
