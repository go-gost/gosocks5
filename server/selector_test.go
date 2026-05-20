package server

import (
	"net"
	"net/url"
	"testing"

	"github.com/go-gost/gosocks5"
)

func TestDefaultServerSelector(t *testing.T) {
	if DefaultSelector == nil {
		t.Fatal("DefaultSelector is nil")
	}
	m := DefaultSelector.Select(gosocks5.MethodNoAuth, gosocks5.MethodUserPass)
	if m != gosocks5.MethodNoAuth {
		t.Fatalf("default Select() = %d, want MethodNoAuth", m)
	}
}

func TestServerSelector_SelectNoAuth(t *testing.T) {
	sel := NewServerSelector(nil)
	m := sel.Select(gosocks5.MethodNoAuth, gosocks5.MethodGSSAPI)
	if m != gosocks5.MethodNoAuth {
		t.Fatalf("Select() = %d, want MethodNoAuth", m)
	}
}

func TestServerSelector_SelectUserPass_ClientOffers(t *testing.T) {
	user, _ := url.Parse("http://user:pass@")
	users := []*url.Userinfo{user.User}
	sel := NewServerSelector(users, gosocks5.MethodUserPass)

	// Client offers MethodUserPass -> select it
	m := sel.Select(gosocks5.MethodNoAuth, gosocks5.MethodUserPass)
	if m != gosocks5.MethodUserPass {
		t.Fatalf("Select() = %d, want MethodUserPass", m)
	}
}

func TestServerSelector_SelectUserPass_ClientDoesNotOffer(t *testing.T) {
	user, _ := url.Parse("http://user:pass@")
	users := []*url.Userinfo{user.User}
	sel := NewServerSelector(users, gosocks5.MethodUserPass)

	// Client does not offer MethodUserPass -> MethodNoAcceptable
	m := sel.Select(gosocks5.MethodNoAuth, gosocks5.MethodGSSAPI)
	if m != gosocks5.MethodNoAcceptable {
		t.Fatalf("Select() = %d, want MethodNoAcceptable", m)
	}
}

func TestServerSelector_OnSelectedNoAuth(t *testing.T) {
	sel := NewServerSelector(nil)
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

func TestServerSelector_OnSelectedNoAcceptable(t *testing.T) {
	sel := NewServerSelector(nil)
	c1, _ := net.Pipe()
	defer c1.Close()

	_, _, err := sel.OnSelected(gosocks5.MethodNoAcceptable, c1)
	if err == nil {
		t.Fatal("expected ErrBadMethod")
	}
}

func TestServerSelector_OnSelectedDefaultBadMethod(t *testing.T) {
	sel := NewServerSelector(nil)
	c1, _ := net.Pipe()
	defer c1.Close()

	_, _, err := sel.OnSelected(0x99, c1)
	if err == nil {
		t.Fatal("expected ErrBadFormat")
	}
}

func TestServerSelector_OnSelectedUserPass_Success(t *testing.T) {
	user, _ := url.Parse("http://alice:s3cret@")
	users := []*url.Userinfo{user.User}
	sel := NewServerSelector(users, gosocks5.MethodUserPass)

	c1, c2 := net.Pipe()
	defer c1.Close()

	go func() {
		// Write user/pass request from server-side auth
		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, "alice", "s3cret")
		req.Write(c2)
		// Read response
		resp, err := gosocks5.ReadUserPassResponse(c2)
		if err != nil {
			t.Logf("server read resp: %v", err)
			return
		}
		if resp.Status != gosocks5.Succeeded {
			t.Errorf("expected Succeeded, got %d", resp.Status)
		}
	}()

	id, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Fatalf("expected empty id, got %q", id)
	}
}

func TestServerSelector_OnSelectedUserPass_Failure(t *testing.T) {
	user, _ := url.Parse("http://alice:s3cret@")
	users := []*url.Userinfo{user.User}
	sel := NewServerSelector(users, gosocks5.MethodUserPass)

	c1, c2 := net.Pipe()
	defer c1.Close()

	go func() {
		// Send wrong credentials
		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, "bob", "wrong")
		req.Write(c2)
		// Server should send Failure response
		resp, _ := gosocks5.ReadUserPassResponse(c2)
		if resp != nil && resp.Status != gosocks5.Failure {
			t.Errorf("expected Failure, got %d", resp.Status)
		}
	}()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestServerSelector_OnSelectedUserPass_EmptyPassword(t *testing.T) {
	// Password match when stored password is empty
	user, _ := url.Parse("http://alice@")
	users := []*url.Userinfo{user.User}
	sel := NewServerSelector(users, gosocks5.MethodUserPass)

	c1, c2 := net.Pipe()
	defer c1.Close()

	go func() {
		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, "alice", "any")
		req.Write(c2)
		resp, _ := gosocks5.ReadUserPassResponse(c2)
		if resp == nil || resp.Status != gosocks5.Succeeded {
			t.Errorf("expected Succeeded, got %v", resp)
		}
	}()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestServerSelector_UserPassNoUsersButMethod(t *testing.T) {
	// When users list is empty but MethodUserPass is selected, any creds pass
	sel := NewServerSelector(nil)

	c1, c2 := net.Pipe()
	defer c1.Close()

	go func() {
		req := gosocks5.NewUserPassRequest(gosocks5.UserPassVer, "any", "thing")
		req.Write(c2)
		resp, _ := gosocks5.ReadUserPassResponse(c2)
		if resp == nil || resp.Status != gosocks5.Succeeded {
			t.Errorf("expected Succeeded, got %v", resp)
		}
	}()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err != nil {
		t.Fatal(err)
	}
}
