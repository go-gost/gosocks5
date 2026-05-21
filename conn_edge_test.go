package gosocks5_test

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	gosocks5 "github.com/go-gost/gosocks5"
	"github.com/go-gost/gosocks5/client"
)

// errorSelector always returns an error in OnSelected.
type errorSelector struct{}

func (s *errorSelector) Methods() []uint8 { return []uint8{gosocks5.MethodNoAuth} }
func (s *errorSelector) Select(methods ...uint8) uint8 {
	return gosocks5.MethodNoAuth
}
func (s *errorSelector) OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) {
	return "", nil, errors.New("forced error")
}

// errorConn is a mock net.Conn that fails writes.
type errorConn struct {
	net.Conn
	failWrite bool
	failRead  bool
}

func (c *errorConn) Write(b []byte) (n int, err error) {
	if c.failWrite {
		return 0, errors.New("write error")
	}
	return c.Conn.Write(b)
}

func (c *errorConn) Read(b []byte) (n int, err error) {
	if c.failRead {
		return 0, errors.New("read error")
	}
	return c.Conn.Read(b)
}

// Test conn Read/Write with handshake error replay
func TestConn_ReadAfterFailedHandshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	cc := gosocks5.ClientConn(cli, &errorSelector{})
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	// Server handshake succeeds
	go sc.Handleshake()

	// Client handshake fails (OnSelected returns error)
	if err := cc.Handleshake(); err == nil {
		t.Fatal("expected handshake error")
	}

	// Subsequent Read/Write should return the cached handshake error
	buf := make([]byte, 10)
	_, err := cc.Read(buf)
	if err == nil {
		t.Fatal("expected error from Read after failed handshake")
	}
	t.Logf("Read error: %v", err)

	_, err = cc.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error from Write after failed handshake")
	}
	t.Logf("Write error: %v", err)
}

// Test serverHandshake with ReadMethods error
func TestConn_ServerHandshake_ReadMethodsError(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	srv.Close() // closed before handshake

	sc := gosocks5.ServerConn(srv, &noAuthSelector{})
	if err := sc.Handleshake(); err == nil {
		t.Fatal("expected error from closed connection")
	}
}

// Test clientHandshake with write error
func TestConn_ClientHandshake_WriteError(t *testing.T) {
	cli, srv := net.Pipe()
	cli.Close()
	srv.Close()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	if err := cc.Handleshake(); err == nil {
		t.Fatal("expected write error")
	}
}

// Test clientHandshake with OnSelected error
func TestConn_ClientHandshake_OnSelectedError(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	// Server sends back a method the client can't handle
	sel := &badMethodSelector{}
	cc := gosocks5.ClientConn(cli, sel)
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	go sc.Handleshake()
	if err := cc.Handleshake(); err == nil {
		t.Fatal("expected error")
	}
}

type badMethodSelector struct{}

func (s *badMethodSelector) Methods() []uint8 { return []uint8{gosocks5.MethodNoAuth} }
func (s *badMethodSelector) Select(methods ...uint8) uint8 {
	return gosocks5.MethodNoAuth
}
func (s *badMethodSelector) OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) {
	return "", nil, errors.New("forced error")
}

// Test serverHandshake with WriteMethod error
func TestConn_ServerHandshake_WriteError(t *testing.T) {
	cli, srv := net.Pipe()
	srv.Close() // close server-side so Write fails
	cli.Close()

	sc := gosocks5.ServerConn(srv, &noAuthSelector{})
	if err := sc.Handleshake(); err == nil {
		t.Fatal("expected error")
	}
}

// Test serverHandshake with OnSelected error
func TestConn_ServerHandshake_OnSelectedError(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	sc := gosocks5.ServerConn(srv, &errorSelector{})
	cc := gosocks5.ClientConn(cli, client.DefaultSelector)

	errCh := make(chan error, 2)
	go func() { errCh <- sc.Handleshake() }()
	go func() { errCh <- cc.Handleshake() }()

	err1 := <-errCh
	err2 := <-errCh
	if err1 == nil && err2 == nil {
		t.Fatal("expected at least one error")
	}
	t.Logf("errors: %v / %v", err1, err2)
}

// Test clientHandshake with nil selector
func TestConn_ClientHandshake_NilSelector(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	cc := gosocks5.ClientConn(cli, nil)
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	go sc.Handleshake()
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}
}

// Test serverHandshake with nil selector
func TestConn_ServerHandshake_NilSelector(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	sc := gosocks5.ServerConn(srv, nil)

	go sc.Handleshake()
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}
}

// Test Handleshake error replay (cached error returned)
func TestConn_HandshakeErrorReplay(t *testing.T) {
	cli, srv := net.Pipe()
	srv.Close()
	cli.Close()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	// First call fails
	err1 := cc.Handleshake()
	// Second call replays cached error
	err2 := cc.Handleshake()
	if err1 == nil || err2 == nil {
		t.Fatal("expected both calls to return error")
	}
	if err1 != err2 {
		t.Fatalf("expected same error: %v vs %v", err1, err2)
	}
}

// Test Conn with nil selector — clientHandshake still works (no auth)
func TestConn_ServerConnNoMethods(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	sc := gosocks5.ServerConn(srv, nil)
	cc := gosocks5.ClientConn(cli, client.DefaultSelector)

	go sc.Handleshake()
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
}

// Test Read/Write after handshake propagates data correctly
func TestConn_ReadWriteAfterHandshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	go sc.Handleshake()
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	// Now exchange data
	go func() {
		cc.Write([]byte("hello"))
	}()

	buf := make([]byte, 5)
	n, err := sc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("got %q", buf[:n])
	}
}

// Test clientHandshake readFull error on method response (server sends < 2 bytes).
func TestConn_ClientHandshake_ShortResponse(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	go func() {
		var b [3]byte
		io.ReadFull(srv, b[:])
		srv.Write([]byte{gosocks5.Ver5})
		srv.Close()
	}()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	err := cc.Handleshake()
	if err == nil {
		t.Fatal("expected readFull error on short method response")
	}
	t.Logf("error: %v", err)
}

// Test clientHandshake bad version in server response.
func TestConn_ClientHandshake_BadVersion(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	go func() {
		var b [3]byte
		io.ReadFull(srv, b[:])
		srv.Write([]byte{0x00, gosocks5.MethodNoAuth})
		srv.Close()
	}()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	err := cc.Handleshake()
	if err != gosocks5.ErrBadVersion {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

// Test serverHandshake write error on method selection response.
func TestConn_ServerHandshake_MethodWriteError(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()

	ec := &errorConn{Conn: srv, failWrite: true}
	sc := gosocks5.ServerConn(ec, &noAuthSelector{})

	go func() {
		cc := gosocks5.ClientConn(cli, client.DefaultSelector)
		cc.Handleshake()
	}()

	err := sc.Handleshake()
	if err == nil {
		t.Fatal("expected write error on method response")
	}
	t.Logf("error: %v", err)
}
