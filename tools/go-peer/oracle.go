package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

var quietLog = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// request is one oracle call; fields not used by an op are left zero.
type request struct {
	Op          string      `json:"op"`
	Packet      string      `json:"packet,omitempty"` // request, response or message
	SenderID    uint64      `json:"sender_id,omitempty"`
	RecipientID uint64      `json:"recipient_id,omitempty"`
	Data        []byte      `json:"data,omitempty"`
	Text        string      `json:"text,omitempty"`
	ServerData  *serverData `json:"server_data,omitempty"`
	Signal      *signal     `json:"signal,omitempty"`
	Candidates  []string    `json:"candidates,omitempty"`
	Trickle     bool        `json:"trickle,omitempty"`
}

type response struct {
	Error       string      `json:"error,omitempty"`
	Bytes       []byte      `json:"bytes,omitempty"`
	Packet      string      `json:"packet,omitempty"`
	SenderID    uint64      `json:"sender_id,omitempty"`
	RecipientID uint64      `json:"recipient_id,omitempty"`
	Data        []byte      `json:"data,omitempty"`
	Text        string      `json:"text,omitempty"`
	ServerData  *serverData `json:"server_data,omitempty"`
	Signal      *signal     `json:"signal,omitempty"`
	Signals     []signal    `json:"signals,omitempty"`
	Max         int         `json:"max,omitempty"`
}

type serverData struct {
	ServerName            string `json:"server_name"`
	Protocol              int32  `json:"protocol"`
	Version               string `json:"version"`
	LevelName             string `json:"level_name"`
	GameType              int32  `json:"game_type"`
	PlayerCount           int32  `json:"player_count"`
	MaxPlayerCount        int32  `json:"max_player_count"`
	EditorWorld           bool   `json:"editor_world"`
	Hardcore              bool   `json:"hardcore"`
	AcceptsOnlineAuth     bool   `json:"accepts_online_auth"`
	AcceptsSelfSignedAuth bool   `json:"accepts_self_signed_auth"`
	Nonce                 string `json:"nonce"`
	ConnectionType        int32  `json:"connection_type"`
}

func (d *serverData) lib() *discovery.ServerData { v := discovery.ServerData(*d); return &v }

type signal struct {
	Type         string `json:"type"`
	ConnectionID uint64 `json:"connection_id"`
	Data         string `json:"data"`
	From         string `json:"from,omitempty"`
}

// serveOracle answers big-endian u32 length-prefixed JSON requests until EOF.
func serveOracle(in io.Reader, out io.Writer) error {
	r, w := bufio.NewReader(in), bufio.NewWriter(out)
	for {
		var n uint32
		if err := binary.Read(r, binary.BigEndian, &n); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return err
		}
		var req request
		var resp response
		if err := json.Unmarshal(body, &req); err != nil {
			resp.Error = "bad request: " + err.Error()
		} else {
			resp = handle(req)
		}
		b, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		_ = binary.Write(w, binary.BigEndian, uint32(len(b)))
		_, _ = w.Write(b)
		if err := w.Flush(); err != nil {
			return err
		}
	}
}

func handle(req request) (resp response) {
	fail := func(err error) response { return response{Error: err.Error()} }
	switch req.Op {
	case "lan_marshal":
		pk, err := packetOf(req)
		if err != nil {
			return fail(err)
		}
		return response{Bytes: discovery.Marshal(pk, req.SenderID)}
	case "lan_unmarshal":
		pk, sender, err := discovery.Unmarshal(req.Data)
		if err != nil {
			return fail(err)
		}
		resp.SenderID = sender
		switch pk := pk.(type) {
		case *discovery.RequestPacket:
			resp.Packet = "request"
		case *discovery.ResponsePacket:
			resp.Packet, resp.Data = "response", pk.ApplicationData
		case *discovery.MessagePacket:
			resp.Packet, resp.RecipientID, resp.Data = "message", pk.RecipientID, []byte(pk.Data)
		}
		return resp
	case "lan_seal":
		return response{Bytes: seal(req.Data)}
	case "lan_open":
		payload, err := open(req.Data)
		if err != nil {
			return fail(err)
		}
		return response{Bytes: payload}
	case "server_data_marshal":
		if req.ServerData == nil {
			return fail(errors.New("missing server_data"))
		}
		b, err := req.ServerData.lib().MarshalBinary()
		if err != nil {
			return fail(err)
		}
		return response{Bytes: b}
	case "server_data_unmarshal":
		var d discovery.ServerData
		if err := d.UnmarshalBinary(req.Data); err != nil {
			return fail(err)
		}
		sd := serverData(d)
		return response{ServerData: &sd}
	case "signal_parse":
		var s nethernet.Signal
		if err := s.UnmarshalText([]byte(req.Text)); err != nil {
			return fail(err)
		}
		return response{Signal: &signal{Type: s.Type, ConnectionID: s.ConnectionID, Data: s.Data}}
	case "signal_format":
		if req.Signal == nil {
			return fail(errors.New("missing signal"))
		}
		s := nethernet.Signal{Type: req.Signal.Type, ConnectionID: req.Signal.ConnectionID, Data: req.Signal.Data}
		return response{Text: s.String()}
	case "error_codes":
		return response{Max: nethernet.ErrorCodeIdentityNotAllowed}
	case "sdp_capture":
		signals, err := captureNegotiation(req.Trickle)
		if err != nil {
			return fail(err)
		}
		return response{Signals: signals}
	case "sdp_answer":
		reply, err := answerOffer(req.Text, req.Candidates, req.Trickle)
		if err != nil {
			return fail(err)
		}
		return response{Signal: reply}
	default:
		return fail(fmt.Errorf("unknown op %q", req.Op))
	}
}

func packetOf(req request) (discovery.Packet, error) {
	switch req.Packet {
	case "request":
		return &discovery.RequestPacket{}, nil
	case "response":
		return &discovery.ResponsePacket{ApplicationData: req.Data}, nil
	case "message":
		return &discovery.MessagePacket{RecipientID: req.RecipientID, Data: string(req.Data)}, nil
	}
	return nil, fmt.Errorf("unknown packet %q", req.Packet)
}

// lanKey is the discovery key: SHA-256 of 0xdeadbeef as a little-endian u64.
var lanKey = sha256.Sum256(binary.LittleEndian.AppendUint64(nil, 0xdeadbeef))

// seal wraps an arbitrary plaintext payload the way discovery.Marshal wraps a
// well-formed one (HMAC-SHA256, then AES-ECB with PKCS#7), so tests can send
// payloads Marshal cannot produce. TestSealMatchesMarshal keeps it equivalent.
func seal(payload []byte) []byte {
	block, _ := aes.NewCipher(lanKey[:])
	pad := aes.BlockSize - len(payload)%aes.BlockSize
	src := append(bytes.Clone(payload), bytes.Repeat([]byte{byte(pad)}, pad)...)
	for i := 0; i < len(src); i += aes.BlockSize {
		block.Encrypt(src[i:], src[i:])
	}
	mac := hmac.New(sha256.New, lanKey[:])
	mac.Write(payload)
	return append(mac.Sum(nil), src...)
}

// open decrypts a datagram's payload without checking its HMAC.
func open(datagram []byte) ([]byte, error) {
	if len(datagram) < 32 || (len(datagram)-32)%aes.BlockSize != 0 {
		return nil, errors.New("invalid datagram length")
	}
	block, _ := aes.NewCipher(lanKey[:])
	dst := bytes.Clone(datagram[32:])
	for i := 0; i < len(dst); i += aes.BlockSize {
		block.Decrypt(dst[i:], dst[i:])
	}
	pad := int(dst[len(dst)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(dst) {
		return nil, errors.New("invalid padding")
	}
	return dst[:len(dst)-pad], nil
}

// captureNegotiation records every signal of one Go dialer/listener negotiation.
func captureNegotiation(trickle bool) ([]signal, error) {
	var (
		mu       sync.Mutex
		captured []signal
	)
	tap := func(from string, s nethernet.Signal) {
		mu.Lock()
		captured = append(captured, signal{Type: s.Type, ConnectionID: s.ConnectionID, Data: s.Data, From: from})
		mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, closeAll, err := connectedPair(ctx, trickle, tap)
	if err != nil {
		return nil, err
	}
	closeAll()
	mu.Lock()
	defer mu.Unlock()
	return captured, nil
}

// answerOffer hands a foreign offer to a Go listener and returns its first reply signal.
func answerOffer(offer string, candidates []string, trickle bool) (*signal, error) {
	api, _, err := loopbackAPI()
	if err != nil {
		return nil, err
	}
	replies := make(chan signal, 16)
	bus := &memoryBus{tap: func(from string, s nethernet.Signal) {
		if from == "server" {
			select {
			case replies <- signal{Type: s.Type, ConnectionID: s.ConnectionID, Data: s.Data, From: from}:
			default:
			}
		}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverSig := bus.endpoint(ctx, "server")
	l, err := nethernet.ListenConfig{API: api, AllowAnonymous: true, DisableTrickleICE: !trickle, Log: quietLog}.Listen(serverSig)
	if err != nil {
		return nil, err
	}
	defer l.Close()
	const connectionID = 7
	serverSig.deliver(&nethernet.Signal{Type: nethernet.SignalTypeOffer, ConnectionID: connectionID, Data: offer, NetworkID: "rust"})
	for _, c := range candidates {
		serverSig.deliver(&nethernet.Signal{Type: nethernet.SignalTypeCandidate, ConnectionID: connectionID, Data: c, NetworkID: "rust"})
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case reply := <-replies:
			if reply.Type != nethernet.SignalTypeCandidate {
				return &reply, nil
			}
		case <-deadline:
			return nil, errors.New("listener sent no answer or error")
		}
	}
}
