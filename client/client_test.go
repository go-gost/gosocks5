package client_test

import (
	"context"
	"net"
	"testing"
	"time"

	gosocks5 "github.com/go-gost/gosocks5"
	"github.com/go-gost/gosocks5/client"
	"github.com/go-gost/gosocks5/server"
)

// startTestServer starts a local SOCKS5 server and returns its address.
func startTestServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}
	go srv.Serve(server.DefaultHandler)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestDial(t *testing.T) {
	addr := startTestServer(t)
	conn, err := client.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn == nil {
		t.Fatal("nil conn")
	}
}

func TestDial_WithTimeout(t *testing.T) {
	addr := startTestServer(t)
	conn, err := client.Dial(addr, client.TimeoutDialOption(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
}

func TestDial_WithSelector(t *testing.T) {
	addr := startTestServer(t)
	conn, err := client.Dial(addr,
		client.SelectorDialOption(client.DefaultSelector),
		client.TimeoutDialOption(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
}

func TestDialContext(t *testing.T) {
	addr := startTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
}

func TestDialContext_WithOptions(t *testing.T) {
	addr := startTestServer(t)
	ctx := context.Background()

	conn, err := client.DialContext(ctx, addr,
		client.TimeoutDialOption(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
}

func TestDialContext_Canceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := client.DialContext(ctx, "127.0.0.1:19999") // non-existent
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
}

func TestSelectorDialOption(t *testing.T) {
	opt := client.SelectorDialOption(client.DefaultSelector)
	var opts client.DialOptions
	opt(&opts)
	if opts.Selector == nil {
		t.Fatal("expected Selector to be set")
	}
}

func TestTimeoutDialOption(t *testing.T) {
	opt := client.TimeoutDialOption(3 * time.Second)
	var opts client.DialOptions
	opt(&opts)
	if opts.Timeout != 3*time.Second {
		t.Fatalf("expected 3s timeout, got %v", opts.Timeout)
	}
}

func TestDial_ConnectAndRequest(t *testing.T) {
	// Full flow: dial SOCKS5 server, send CONNECT request, read reply
	addr := startTestServer(t)
	conn, err := client.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	target, _ := gosocks5.NewAddr("example.com:80")
	req := gosocks5.NewRequest(gosocks5.CmdConnect, target)
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	reply, err := gosocks5.ReadReply(conn)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Rep != gosocks5.Succeeded {
		t.Fatalf("expected Succeeded, got %d", reply.Rep)
	}
}

func TestDial_HandshakeError(t *testing.T) {
	// Connect to a server that will reject during OnSelected
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Accept but immediately close — handshake will fail
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	_, err = client.Dial(ln.Addr().String(),
		client.TimeoutDialOption(2*time.Second),
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDialContext_HandshakeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	ctx := context.Background()
	_, err = client.DialContext(ctx, ln.Addr().String(),
		client.TimeoutDialOption(2*time.Second),
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDial_DialTimeoutError(t *testing.T) {
	// Use a non-routable IP with a very short timeout to force dial error
	_, err := client.Dial("10.255.255.1:12345",
		client.TimeoutDialOption(1*time.Nanosecond),
	)
	if err == nil {
		t.Fatal("expected dial timeout error")
	}
	t.Logf("error: %v", err)
}

func TestDial_Auth(t *testing.T) {
	// Start server with no-auth (uses DefaultHandler which calls DefaultSelector)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}
	go srv.Serve(server.DefaultHandler)
	defer srv.Close()

	conn, err := client.Dial(ln.Addr().String(),
		client.TimeoutDialOption(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
}
