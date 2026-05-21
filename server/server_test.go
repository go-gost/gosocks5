package server_test

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	gosocks5 "github.com/go-gost/gosocks5"
	"github.com/go-gost/gosocks5/client"
	"github.com/go-gost/gosocks5/server"
)

func TestServer_Addr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srv := &server.Server{Listener: ln}
	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Addr() nil")
	}
	if _, ok := addr.(*net.TCPAddr); !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", addr)
	}
}

func TestServer_Close(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	// Listener should be closed
	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected error from closed listener")
	}
}

func TestServer_Serve_NoListener(t *testing.T) {
	// Serve with nil listener should create one
	srv := &server.Server{}
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(server.DefaultHandler)
	}()
	// Wait for auto-created listener (poll with timeout)
	deadline := time.Now().Add(2 * time.Second)
	for srv.Listener == nil {
		if time.Now().After(deadline) {
			t.Fatal("expected auto-created listener")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("expected non-nil Addr()")
	}
	srv.Close()
	<-done
}

func TestServer_ServeAndAccept(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(server.DefaultHandler)
	}()

	// Connect to server
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	time.Sleep(50 * time.Millisecond)
	srv.Close()
	wg.Wait()
}

func TestServer_Serve_DefaultHandler(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(nil) // nil handler should use DefaultHandler
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	time.Sleep(50 * time.Millisecond)
	srv.Close()
	wg.Wait()
}

// Test handler Handle method via a proper SOCKS5 client connection.
func TestHandler_Handle_Connect(t *testing.T) {
	// Start a target echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()

	// Start SOCKS5 server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(server.DefaultHandler)
	}()
	defer func() { srv.Close(); wg.Wait() }()

	// Connect to SOCKS5 server and do a proper CONNECT handshake
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cc := gosocks5.ClientConn(conn, client.DefaultSelector)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	// Send CONNECT request to the echo server
	echoHost, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())
	echoAddr := &gosocks5.Addr{}
	echoAddr.ParseFrom(net.JoinHostPort(echoHost, echoPort))
	req := gosocks5.NewRequest(gosocks5.CmdConnect, echoAddr)
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	reply, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Rep != gosocks5.Succeeded {
		t.Fatalf("expected Succeeded, got %d", reply.Rep)
	}

	// Exchange data through the tunnel
	go func() {
		cc.Write([]byte("ping"))
	}()
	buf := make([]byte, 4)
	n, err := cc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("expected 'ping', got %q", buf[:n])
	}
}

// Test selector Methods and AddMethod from server
func TestServerSelector_Methods(t *testing.T) {
	sel := server.NewServerSelector(nil, gosocks5.MethodNoAuth, gosocks5.MethodUserPass)
	methods := sel.Methods()
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(methods))
	}
}

// We can't test AddMethod on the interface, but we can test the concrete type
// by wrapping in a test in the server package.

// Test handler with unsupported command (CmdUdp)
func TestHandler_Handle_UnsupportedCmd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(server.DefaultHandler)
	}()
	defer func() { srv.Close(); wg.Wait() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cc := gosocks5.ClientConn(conn, client.DefaultSelector)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	// Send unsupported CmdUdp request
	req := gosocks5.NewRequest(gosocks5.CmdUdp, &gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "1.1.1.1", Port: 53})
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	// Handler returns error without sending Reply for unsupported cmd.
	// Connection will be closed by the server. Read should get an error.
	cc.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = gosocks5.ReadReply(cc)
	if err == nil {
		t.Fatal("expected error")
	}
	t.Logf("expected error: %v", err)
}

// Test handleConnect with unreachable target
func TestHandler_HandleConnect_Unreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(server.DefaultHandler)
	}()
	defer func() { srv.Close(); wg.Wait() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cc := gosocks5.ClientConn(conn, client.DefaultSelector)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	// Request to localhost with a closed port — should fail quickly
	req := gosocks5.NewRequest(gosocks5.CmdConnect,
		&gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "127.0.0.1", Port: 19999})
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	reply, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatalf("expected SOCKS5 reply, got error: %v", err)
	}
	if reply.Rep == gosocks5.Succeeded {
		t.Fatalf("expected non-Succeeded reply for unreachable target, got Succeeded")
	}
	t.Logf("unreachable target reply: %d", reply.Rep)
}


// Test handler with BIND command
func TestHandler_Handle_Bind(t *testing.T) {
	// Start SOCKS5 server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(server.DefaultHandler)
	}()
	defer func() { srv.Close(); wg.Wait() }()

	// Connect to SOCKS5 server
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cc := gosocks5.ClientConn(conn, client.DefaultSelector)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	// Send BIND request for localhost:0 (random port)
	req := gosocks5.NewRequest(gosocks5.CmdBind,
		&gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "127.0.0.1", Port: 0})
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	// Read first reply (bind address)
	reply1, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatal(err)
	}
	if reply1.Rep != gosocks5.Succeeded {
		t.Fatalf("expected Succeeded, got %d", reply1.Rep)
	}
	t.Logf("bind address: %s", reply1.Addr.String())

	// Connect as peer to the bind address
	peerConn, err := net.Dial("tcp", reply1.Addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()

	// Read second reply (peer address notification)
	reply2, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatal(err)
	}
	if reply2.Rep != gosocks5.Succeeded {
		t.Fatalf("expected Succeeded for second reply, got %d", reply2.Rep)
	}
	t.Logf("peer address: %s", reply2.Addr.String())

	// Exchange data through the relay
	go cc.Write([]byte("hello-from-client"))
	go peerConn.Write([]byte("hello-from-peer"))

	buf1 := make([]byte, 100)
	n1, _ := peerConn.Read(buf1)
	t.Logf("peer received: %q", buf1[:n1])

	buf2 := make([]byte, 100)
	n2, _ := cc.Read(buf2)
	t.Logf("client received: %q", buf2[:n2])
}

// Test BIND with pipe error: close client after sending BIND request
func TestHandler_Handle_Bind_PipeError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(server.DefaultHandler)
	}()
	defer func() { srv.Close(); wg.Wait() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	cc := gosocks5.ClientConn(conn, client.DefaultSelector)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	req := gosocks5.NewRequest(gosocks5.CmdBind,
		&gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "127.0.0.1", Port: 0})
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	// Read first reply
	reply1, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bind address: %s", reply1.Addr.String())

	// Close the client connection — triggers pipe error in handleBind.
	// Verify the server does not panic and can still shut down cleanly.
	done := make(chan struct{})
	go func() {
		conn.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection close")
	}
}

// Test Serve with listener closed mid-accept (covers error return path)
func TestServer_Serve_ListenerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(server.DefaultHandler)
	}()

	// Close listener to trigger error in Accept loop
	time.Sleep(20 * time.Millisecond)
	srv.Close()

	err = <-done
	if err != nil {
		t.Logf("Serve returned error: %v", err)
	}
}

// Test BIND with port already in use
func TestHandler_Handle_Bind_PortInUse(t *testing.T) {
	// Occupy a port first
	occupyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupyLn.Close()
	_, occupyPort, _ := net.SplitHostPort(occupyLn.Addr().String())

	// Start SOCKS5 server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &server.Server{Listener: ln}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srv.Serve(server.DefaultHandler)
	}()
	defer func() { srv.Close(); wg.Wait() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	cc := gosocks5.ClientConn(conn, client.DefaultSelector)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	// BIND to the occupied port
	req := gosocks5.NewRequest(gosocks5.CmdBind,
		&gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "127.0.0.1", Port: uint16(0)})
	req.Addr.ParseFrom(net.JoinHostPort("127.0.0.1", occupyPort))
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	// Should get Failure reply or connection close
	reply, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatalf("expected SOCKS5 reply for port-in-use, got error: %v", err)
	}
	if reply.Rep == gosocks5.Succeeded {
		t.Fatalf("expected Failure for occupied port, got Succeeded")
	}
	t.Logf("port-in-use reply: %d (expected Failure=%d)", reply.Rep, gosocks5.Failure)
}

// mockTempError implements net.Error with Temporary() == true
type mockTempError struct{}

func (e *mockTempError) Error() string   { return "mock temporary error" }
func (e *mockTempError) Timeout() bool   { return false }
func (e *mockTempError) Temporary() bool { return true }

// mockListener wraps a net.Listener and returns temporary errors for the first N accepts.
type mockListener struct {
	net.Listener
	tempErrCount int
}

func (l *mockListener) Accept() (net.Conn, error) {
	if l.tempErrCount > 0 {
		l.tempErrCount--
		return nil, &mockTempError{}
	}
	return l.Listener.Accept()
}

// Test Serve with temporary accept errors (covers backoff path)
func TestServer_Serve_TemporaryError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mockLn := &mockListener{Listener: ln, tempErrCount: 2}
	srv := &server.Server{Listener: mockLn}

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(server.DefaultHandler)
	}()

	// Connect after temp errors are exhausted
	time.Sleep(100 * time.Millisecond)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	time.Sleep(50 * time.Millisecond)
	srv.Close()
	<-done
}

// Test Serve with many temporary accept errors (covers max backoff cap at 1s).
func TestServer_Serve_TemporaryErrorMaxBackoff(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow temp error backoff test")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// 12 temp errors → delay will exceed 1s cap (9th error hits cap)
	mockLn := &mockListener{Listener: ln, tempErrCount: 12}
	srv := &server.Server{Listener: mockLn}

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(server.DefaultHandler)
	}()

	// Wait for temp errors to trigger backoff cap (~1.3s to reach error #9)
	time.Sleep(1500 * time.Millisecond)
	srv.Close()
	<-done
}
