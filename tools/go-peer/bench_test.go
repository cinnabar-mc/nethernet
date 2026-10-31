package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
)

// Payload sizes shared with the criterion benches; the largest stays under the Rust send cap.
var segmentSizes = []int{64, 1024, 16384, 262144, 1048576, 2500000}

// benchInput reads a committed file from the repository's testdata/bench.
func benchInput(tb testing.TB, name string) []byte {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "bench", name))
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// goSegmentPayload is go-nethernet's segment payload once a peer advertises max-message-size 262144.
const goSegmentPayload = 262143

// splitSegments frames data as Conn.Send does: a remaining-segment count byte, then the fragment.
// Conn.Send is not callable without a live data channel, so this copies its loop.
func splitSegments(data []byte) [][]byte {
	total := 0
	if len(data) != 0 {
		total = (len(data)-1)/goSegmentPayload + 1
	}
	out := make([][]byte, 0, total)
	remaining := total - 1
	for i := 0; i < len(data); i += goSegmentPayload {
		frag := data[i:min(len(data), i+goSegmentPayload)]
		out = append(out, append([]byte{uint8(remaining)}, frag...))
		remaining--
	}
	return out
}

// reassemble copies dataChannel.handleMessage's reassembly for one complete message.
func reassemble(segments [][]byte) []byte {
	var count uint8
	var data []byte
	for _, b := range segments {
		if len(b) < 2 || (count > 0 && count-1 != b[0]) {
			return nil
		}
		count = b[0]
		data = append(data, b[1:]...)
	}
	return data
}

// copiedFrom is the go-nethernet version the framing copies above were taken from.
const copiedFrom = "v1.0.27-0.20261030105925-88d6df3de353"

// A go-nethernet pin change must re-check the copied framing before this passes.
func TestCopiedFramingMatchesPin(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info")
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/df-mc/go-nethernet" {
			version := dep.Version
			if dep.Replace != nil {
				version = dep.Replace.Version
			}
			if version != copiedFrom {
				t.Fatalf("go-nethernet is %s; re-check splitSegments/reassemble against it and update copiedFrom", version)
			}
			return
		}
	}
	t.Fatal("go-nethernet missing from build info")
}

func BenchmarkSegment(b *testing.B) {
	for _, size := range segmentSizes {
		data := pattern(size)
		b.Run("split/"+strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				_ = splitSegments(data)
			}
		})
		segments := splitSegments(data)
		b.Run("reassemble/"+strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if len(reassemble(segments)) != size {
					b.Fatal("reassembly lost data")
				}
			}
		})
	}
}

func BenchmarkLan(b *testing.B) {
	const sender, recipient = 0x1122334455667788, 0x8877665544332211
	packets := map[string]discovery.Packet{
		"request":  &discovery.RequestPacket{},
		"response": &discovery.ResponsePacket{ApplicationData: benchInput(b, "server_data.bin")},
		"message":  &discovery.MessagePacket{RecipientID: recipient, Data: string(benchInput(b, "signal.txt"))},
	}
	for _, name := range []string{"request", "response", "message"} {
		pk := packets[name]
		wire := discovery.Marshal(pk, sender)
		b.Run("encode/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(wire)))
			b.ReportAllocs()
			for b.Loop() {
				_ = discovery.Marshal(pk, sender)
			}
		})
		b.Run("decode/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(wire)))
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := discovery.Unmarshal(wire); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkServer_data(b *testing.B) {
	wire := benchInput(b, "server_data.bin")
	var d discovery.ServerData
	if err := d.UnmarshalBinary(wire); err != nil {
		b.Fatal(err)
	}
	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_, _ = d.MarshalBinary()
		}
	})
	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var v discovery.ServerData
			if err := v.UnmarshalBinary(wire); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkDatachannel measures reliable messages over loopback DTLS and SCTP.
func BenchmarkDatachannel(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, server, closeAll, err := connectedPair(ctx, true, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer closeAll()

	echo := func(conn *nethernet.Conn) {
		for {
			pk, err := conn.ReadPacket()
			if err != nil {
				return
			}
			if _, err := conn.Write(pk); err != nil {
				return
			}
		}
	}
	go echo(server)
	for _, size := range []int{64, 1024, 16384, 262144} {
		data := pattern(size)
		b.Run("roundtrip/"+strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := client.Write(data); err != nil {
					b.Fatal(err)
				}
				pk, err := client.ReadPacket()
				if err != nil || !bytes.Equal(pk, data) {
					b.Fatalf("echo failed: %v", err)
				}
			}
		})
	}

	// Throughput reverses direction so the echo loop above keeps only the server busy.
	for _, size := range []int{1024, 65536, 1048576} {
		data := pattern(size)
		b.Run("throughput/"+strconv.Itoa(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			done := make(chan error, 1)
			n := b.N
			go func() {
				for range n {
					if _, err := client.ReadPacket(); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			b.ResetTimer()
			for range n {
				if _, err := server.Send(data, nethernet.MessageReliabilityReliable); err != nil {
					b.Fatal(err)
				}
			}
			if err := <-done; err != nil {
				b.Fatal(err)
			}
		})
	}
}
