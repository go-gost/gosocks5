package server

import (
	"errors"
	"net"
	"net/url"
	"testing"

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
