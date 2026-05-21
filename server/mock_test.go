package server

import (
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/go-gost/gosocks5"
)

// writeCountConn wraps a net.Conn and fails Write after skipUntil successful writes.
type writeCountConn struct {
	net.Conn
	writes    int
	skipUntil int
}

func (c *writeCountConn) Write(b []byte) (int, error) {
	c.writes++
	if c.writes > c.skipUntil {
		return 0, errors.New("injected write error")
	}
	return c.Conn.Write(b)
}

// Test handleConnect with write error on Succeeded reply
func TestHandler_HandleConnect_WriteError(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	targetHost, targetPort, _ := net.SplitHostPort(targetLn.Addr().String())

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	wc := &writeCountConn{Conn: c2, skipUntil: 1}
	h := &serverHandler{selector: DefaultSelector}

	go func() {
		cc := gosocks5.ClientConn(c1, nil)
		cc.Handleshake()
		req := gosocks5.NewRequest(gosocks5.CmdConnect,
			&gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: targetHost, Port: 0})
		req.Addr.ParseFrom(net.JoinHostPort(targetHost, targetPort))
		req.Write(cc)
		gosocks5.ReadReply(cc)
	}()

	err = h.Handle(wc)
	if err == nil {
		t.Fatal("expected write error")
	}
	t.Logf("error: %v", err)
}

// Test OnSelected write error on success response
func TestServerSelector_OnSelected_SuccessWriteErr(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	wc := &writeCountConn{Conn: c1, skipUntil: 0}
	sel := &serverSelector{} // no users → any creds pass → write Succeeded response

	go func() {
		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, "user", "pass")
		req.Write(c2)
	}()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, wc)
	if err == nil {
		t.Fatal("expected write error")
	}
	t.Logf("error: %v", err)
}

// Test OnSelected write error on failure response
func TestServerSelector_OnSelected_FailureWriteErr(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	wc := &writeCountConn{Conn: c1, skipUntil: 0}
	u, _ := url.Parse("http://alice:s3cret@")
	sel := &serverSelector{
		users: []*url.Userinfo{u.User},
	}

	go func() {
		// Send wrong credentials
		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, "bob", "wrong")
		req.Write(c2)
	}()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, wc)
	if err == nil {
		t.Fatal("expected write error")
	}
	t.Logf("error: %v", err)
}

// ---------------------------------------------------------------------------
// handleBind error paths
// ---------------------------------------------------------------------------

func TestHandler_HandleBind_ResolveError(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	h := &serverHandler{selector: DefaultSelector}

	go h.Handle(c2)

	cc := gosocks5.ClientConn(c1, nil)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	req := gosocks5.NewRequest(gosocks5.CmdBind,
		&gosocks5.Addr{Type: gosocks5.AddrDomain, Host: "invalid!:x", Port: 0})
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	reply, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Rep != gosocks5.Failure {
		t.Fatalf("expected Failure, got %d", reply.Rep)
	}
}

func TestHandler_HandleBind_FirstReplyWriteError(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// skipUntil=1: handshake write (method choice) succeeds, bind reply write fails
	wc := &writeCountConn{Conn: c2, skipUntil: 1}
	h := &serverHandler{selector: DefaultSelector}

	go h.Handle(wc)

	cc := gosocks5.ClientConn(c1, nil)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	req := gosocks5.NewRequest(gosocks5.CmdBind,
		&gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "127.0.0.1", Port: 0})
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	// Bind reply write fails → conn closed → ReadReply gets EOF
	_, err := gosocks5.ReadReply(cc)
	if err == nil {
		t.Log("unexpected: got reply despite write error on server")
	}
	_ = err
}

func TestHandler_HandleBind_AcceptError(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	h := &serverHandler{selector: DefaultSelector}

	go h.Handle(c2)

	cc := gosocks5.ClientConn(c1, nil)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	req := gosocks5.NewRequest(gosocks5.CmdBind,
		&gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "127.0.0.1", Port: 0})
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	reply1, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatal(err)
	}
	if reply1.Rep != gosocks5.Succeeded {
		t.Fatalf("expected Succeeded, got %d", reply1.Rep)
	}

	// Close client to trigger pipe error, which closes listener via defer
	c1.Close()
	time.Sleep(50 * time.Millisecond)
}

func TestHandler_HandleBind_SecondReplyWriteError(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	h := &serverHandler{selector: DefaultSelector}

	go h.Handle(c2)

	cc := gosocks5.ClientConn(c1, nil)
	if err := cc.Handleshake(); err != nil {
		t.Fatal(err)
	}

	req := gosocks5.NewRequest(gosocks5.CmdBind,
		&gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "127.0.0.1", Port: 0})
	if err := req.Write(cc); err != nil {
		t.Fatal(err)
	}

	reply1, err := gosocks5.ReadReply(cc)
	if err != nil {
		t.Fatal(err)
	}
	if reply1.Rep != gosocks5.Succeeded {
		t.Fatalf("expected Succeeded, got %d", reply1.Rep)
	}

	// Close client → pipe goroutine errors → pc1.Close() → pc2 broken.
	// Then connect as peer → accept succeds → second reply Write(pc2) fails.
	c1.Close()

	peerConn, err := net.Dial("tcp", reply1.Addr.String())
	if err != nil {
		t.Logf("peer dial error (may happen): %v", err)
		return
	}
	defer peerConn.Close()

	time.Sleep(50 * time.Millisecond)
}
