// Command go-peer is the go-nethernet side of the Rust golden, interop and benchmark harness.
//
//	go-peer oracle           serve length-prefixed JSON requests on stdin/stdout
//	go-peer peer [flags]     dial or accept one NetherNet connection over loopback LAN signaling
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go-peer oracle | peer [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "oracle":
		err = serveOracle(os.Stdin, os.Stdout)
	case "peer":
		err = runPeer(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "go-peer:", err)
		os.Exit(1)
	}
}
