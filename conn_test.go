package gosocks5_test

import (
	"net"
	"net/url"
	"testing"
	"time"

	gosocks5 "github.com/go-gost/gosocks5"
	"github.com/go-gost/gosocks5/client"
	"github.com/go-gost/gosocks5/server"
)

// noAuthSelector accepts MethodNoAuth only.
type noAuthSelector struct{}

func (s *noAuthSelector) Methods() []uint8 { return []uint8{gosocks5.MethodNoAuth} }
func (s *noAuthSelector) Select(methods ...uint8) uint8 {
	return gosocks5.MethodNoAuth
}
func (s *noAuthSelector) OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) {
	return "", conn, nil
}

// idSelector returns a fixed client ID.
type idSelector struct {
	noAuthSelector
}

func (s *idSelector) OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) {
	return "client-123", conn, nil
}

func TestConn_HandshakeNoAuth(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	serverErr := make(chan error, 1)
	go func() { serverErr <- sc.Handleshake() }()

	if err := cc.Handleshake(); err != nil {
		t.Fatalf("client Handleshake() = %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server Handleshake() = %v", err)
	}
}

func TestConn_ReadTriggersHandshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	go sc.Handleshake()

	// Write triggers client handshake, then data flows
	go cc.Write([]byte("ping"))

	var buf [4]byte
	n, err := sc.Read(buf[:])
	if err != nil {
		t.Fatalf("server Read() = %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("got %q", buf[:n])
	}
}

func TestConn_DoubleHandshake(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	go sc.Handleshake()

	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}
	// Second call is idempotent
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}
}

func TestConn_DelegatesToUnderlying(t *testing.T) {
	cli, _ := net.Pipe()
	defer cli.Close()

	cc := gosocks5.ClientConn(cli, client.DefaultSelector)

	if cc.LocalAddr() == nil {
		t.Fatal("LocalAddr nil")
	}
	if cc.RemoteAddr() == nil {
		t.Fatal("RemoteAddr nil")
	}
	if err := cc.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := cc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := cc.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestConn_ID(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	sc := gosocks5.ServerConn(srv, &idSelector{})
	cc := gosocks5.ClientConn(cli, client.DefaultSelector)

	go sc.Handleshake()
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)

	if id := sc.ID(); id != "client-123" {
		t.Fatalf("expected client-123, got %q", id)
	}
}

func TestConn_ServerAuthRejection(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	user, _ := url.Parse("http://user:pass@")
	users := []*url.Userinfo{user.User}
	sel := server.NewServerSelector(users, gosocks5.MethodUserPass)

	sc := gosocks5.ServerConn(srv, sel)
	cc := gosocks5.ClientConn(cli, client.DefaultSelector) // only has MethodNoAuth

	errCh := make(chan error, 2)
	go func() { errCh <- sc.Handleshake() }()
	go func() { errCh <- cc.Handleshake() }()

	err1 := <-errCh
	err2 := <-errCh
	if err1 == nil && err2 == nil {
		t.Fatal("expected handshake failure")
	}
	t.Logf("errors: %v / %v", err1, err2)
}

func TestConn_Close(t *testing.T) {
	c1, c2 := net.Pipe()
	cc := gosocks5.ClientConn(c1, client.DefaultSelector)
	if err := cc.Close(); err != nil {
		t.Fatal(err)
	}
	c2.Close()
}
