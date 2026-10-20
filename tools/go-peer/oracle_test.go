package main

import (
	"bytes"
	"testing"

	"github.com/df-mc/go-nethernet/discovery"
)

// seal and open must stay byte-compatible with discovery.Marshal for well-formed packets.
func TestSealMatchesMarshal(t *testing.T) {
	for _, pk := range []discovery.Packet{
		&discovery.RequestPacket{},
		&discovery.ResponsePacket{ApplicationData: []byte{7, 1, 'a'}},
		&discovery.MessagePacket{RecipientID: 9, Data: string(benchInput(t, "signal.txt"))},
	} {
		wire := discovery.Marshal(pk, 42)
		payload, err := open(wire)
		if err != nil {
			t.Fatal(err)
		}
		if got := seal(payload); !bytes.Equal(got, wire) {
			t.Fatalf("seal(open(%T)) differs from Marshal", pk)
		}
	}
}
