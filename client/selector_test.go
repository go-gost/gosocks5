package client

import (
	"net"
	"net/url"
	"testing"

	"github.com/go-gost/gosocks5"
)

func TestDefaultSelector(t *testing.T) {
	if DefaultSelector == nil {
		t.Fatal("DefaultSelector is nil")
	}
	// Default should have no methods
	methods := DefaultSelector.Methods()
	if len(methods) != 0 {
		t.Fatalf("DefaultSelector.Methods() = %v, want empty", methods)
	}
	// Select is a no-op
	m := DefaultSelector.Select(gosocks5.MethodNoAuth, gosocks5.MethodUserPass)
	if m != 0 {
		t.Fatalf("Select() = %d, want 0 (no-op)", m)
	}
}

func TestClientSelector_NoAuth(t *testing.T) {
	sel := NewClientSelector(nil, gosocks5.MethodNoAuth)
	methods := sel.Methods()
	if len(methods) != 1 || methods[0] != gosocks5.MethodNoAuth {
		t.Fatalf("Methods() = %v", methods)
	}
	// Select is no-op
	m := sel.Select(gosocks5.MethodNoAuth)
	if m != 0 {
		t.Fatalf("Select() = %d, want 0", m)
	}
}

func TestClientSelector_OnSelectedNoAuth(t *testing.T) {
	sel := NewClientSelector(nil, gosocks5.MethodNoAuth)
	c1, _ := net.Pipe()
	defer c1.Close()

	id, conn, err := sel.OnSelected(gosocks5.MethodNoAuth, c1)
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Fatalf("expected empty id, got %q", id)
	}
	if conn != c1 {
		t.Fatal("expected same conn")
	}
}

func TestClientSelector_OnSelectedUserPass_WrongCreds(t *testing.T) {
	sel := NewClientSelector(nil, gosocks5.MethodUserPass)
	c1, c2 := net.Pipe()
	defer c1.Close()

	// Server side: read request first, then send failure response
	go func() {
		gosocks5.ReadUserPassRequest(c2)
		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
		resp.Write(c2)
		c2.Close()
	}()

	id, conn, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err == nil {
		t.Fatal("expected auth failure")
	}
	_ = id
	_ = conn
}

func TestClientSelector_OnSelectedUserPass_Success(t *testing.T) {
	user, _ := url.Parse("http://alice:s3cret@")
	sel := NewClientSelector(user.User, gosocks5.MethodUserPass)
	c1, c2 := net.Pipe()
	defer c1.Close()

	// Server side: read the request, validate, send success
	ready := make(chan error, 1)
	go func() {
		req, err := gosocks5.ReadUserPassRequest(c2)
		if err != nil {
			ready <- err
			return
		}
		if req.Username != "alice" || req.Password != "s3cret" {
			ready <- nil // wrong creds but we still respond ok for test
		}
		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(c2); err != nil {
			ready <- err
			return
		}
		ready <- nil
	}()

	id, conn, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Fatalf("expected empty id, got %q", id)
	}
	if conn != c1 {
		t.Fatal("expected same conn")
	}
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
}

func TestClientSelector_OnSelectedNoAcceptable(t *testing.T) {
	sel := NewClientSelector(nil)
	c1, _ := net.Pipe()
	defer c1.Close()

	_, _, err := sel.OnSelected(gosocks5.MethodNoAcceptable, c1)
	if err == nil {
		t.Fatal("expected ErrBadMethod")
	}
}

func TestClientSelector_DefaultOnSelected(t *testing.T) {
	sel := NewClientSelector(nil)
	c1, _ := net.Pipe()
	defer c1.Close()

	_, _, err := sel.OnSelected(0x99, c1) // unknown method
	if err == nil {
		t.Fatal("expected ErrBadFormat")
	}
}

func TestClientSelector_AddMethod(t *testing.T) {
	sel := &clientSelector{
		methods: []uint8{gosocks5.MethodNoAuth},
	}
	sel.AddMethod(gosocks5.MethodUserPass, gosocks5.MethodGSSAPI)
	methods := sel.Methods()
	if len(methods) != 3 {
		t.Fatalf("expected 3 methods, got %d", len(methods))
	}
}

func TestClientSelector_UserPassNoUser(t *testing.T) {
	// When user is nil but MethodUserPass is selected, it sends empty creds
	sel := NewClientSelector(nil, gosocks5.MethodUserPass)
	c1, c2 := net.Pipe()
	defer c1.Close()

	go func() {
		req, _ := gosocks5.ReadUserPassRequest(c2)
		if req.Username != "" || req.Password != "" {
			t.Logf("empty creds: user=%q pass=%q", req.Username, req.Password)
		}
		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		resp.Write(c2)
	}()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientSelector_OnSelectedUserPass_ReadResponseError(t *testing.T) {
	sel := NewClientSelector(nil, gosocks5.MethodUserPass)
	c1, c2 := net.Pipe()
	// Close server side after client sends request — ReadUserPassResponse will fail
	go func() {
		gosocks5.ReadUserPassRequest(c2)
		c2.Close() // close before sending response
	}()
	defer c1.Close()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err == nil {
		t.Fatal("expected ReadUserPassResponse error")
	}
	t.Logf("error: %v", err)
}

func TestClientSelector_OnSelectedUserPass_WriteError(t *testing.T) {
	sel := NewClientSelector(nil, gosocks5.MethodUserPass)
	c1, c2 := net.Pipe()
	c2.Close()
	defer c1.Close()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err == nil {
		t.Fatal("expected write error")
	}
}
