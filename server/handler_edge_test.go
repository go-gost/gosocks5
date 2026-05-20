package server

import (
	"net"
	"testing"

	"github.com/go-gost/gosocks5"
)

// Test OnSelected UserPass read error when connection closed
func TestServerSelector_OnSelectedUserPass_ReadErr(t *testing.T) {
	sel := &serverSelector{}
	c1, c2 := net.Pipe()
	c2.Close()
	defer c1.Close()

	_, _, err := sel.OnSelected(gosocks5.MethodUserPass, c1)
	if err == nil {
		t.Fatal("expected read error")
	}
}
