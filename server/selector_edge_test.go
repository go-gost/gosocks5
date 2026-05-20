package server

import (
	"net"
	"testing"

	"github.com/go-gost/gosocks5"
)

func TestServerSelector_AddMethod(t *testing.T) {
	sel := &serverSelector{
		methods: []uint8{gosocks5.MethodNoAuth},
	}
	sel.AddMethod(gosocks5.MethodUserPass, gosocks5.MethodGSSAPI)
	methods := sel.Methods()
	if len(methods) != 3 {
		t.Fatalf("expected 3 methods, got %d", len(methods))
	}
}

func TestServerSelector_Methods(t *testing.T) {
	sel := &serverSelector{
		methods: []uint8{gosocks5.MethodNoAuth, gosocks5.MethodUserPass},
	}
	m := sel.Methods()
	if len(m) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(m))
	}
}

// Test OnSelected UserPass with read error
func TestServerSelector_OnSelectedUserPass_ReadError(t *testing.T) {
	sel := &serverSelector{}
	c1, c2 := net.Pipe()
	c2.Close() // close peer so read fails
	defer c1.Close()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err == nil {
		t.Fatal("expected read error")
	}
}
