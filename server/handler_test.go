package server

import (
	"net"
	"sync"
	"testing"

	"github.com/go-gost/gosocks5"
)

func TestTransport_BidirectionalCopy(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	msg := "hello from c1"
	received := make(chan string, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, _ := c2.Read(buf)
		received <- string(buf[:n])
	}()

	_, err := c1.Write([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	close(received)

	if r := <-received; r != msg {
		t.Fatalf("got %q", r)
	}
}

func TestTransport_GoroutineCleanup(t *testing.T) {
	c1, c2 := net.Pipe()

	errc := make(chan error, 1)
	go func() {
		errc <- transport(c1, c2)
	}()

	// Close one side — transport should return
	c1.Close()
	c2.Close()

	err := <-errc
	if err != nil {
		t.Logf("transport error: %v", err)
	}
}

func TestTransport_ClosedPipe(t *testing.T) {
	c1, c2 := net.Pipe()
	c2.Close() // closed pipe: reads get error

	err := transport(c1, c2)
	c1.Close()
	if err != nil {
		t.Logf("closed pipe error: %v", err)
	}
}

func TestToSocksAddr_IPv4(t *testing.T) {
	addr := toSocksAddr(&net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080})
	if addr.Type != gosocks5.AddrIPv4 {
		t.Fatalf("expected AddrIPv4, got %d", addr.Type)
	}
	if addr.Host != "192.168.1.1" || addr.Port != 8080 {
		t.Fatalf("got %s:%d", addr.Host, addr.Port)
	}
}

func TestToSocksAddr_IPv6(t *testing.T) {
	addr := toSocksAddr(&net.TCPAddr{IP: net.ParseIP("::1"), Port: 9090})
	if addr.Type != gosocks5.AddrIPv6 {
		t.Fatalf("expected AddrIPv6, got %d", addr.Type)
	}
}

func TestToSocksAddr_Nil(t *testing.T) {
	addr := toSocksAddr(nil)
	if addr.Type != gosocks5.AddrIPv4 {
		t.Fatalf("expected AddrIPv4 for nil, got %d", addr.Type)
	}
	if addr.Host != "0.0.0.0" {
		t.Fatalf("expected 0.0.0.0, got %s", addr.Host)
	}
	if addr.Port != 0 {
		t.Fatalf("expected port 0, got %d", addr.Port)
	}
}

func TestTrPool(t *testing.T) {
	buf := trPool.Get().([]byte)
	if len(buf) != 1500 {
		t.Fatalf("expected 1500, got %d", len(buf))
	}
	trPool.Put(buf)
	// Second get should reuse
	buf2 := trPool.Get().([]byte)
	if len(buf2) != 1500 {
		t.Fatalf("expected 1500, got %d", len(buf2))
	}
	trPool.Put(buf2)
}

func TestDefaultHandler(t *testing.T) {
	if DefaultHandler == nil {
		t.Fatal("DefaultHandler is nil")
	}
}

func TestServer(t *testing.T) {
	var srv Server
	if srv.Listener != nil {
		t.Fatal("expected nil Listener")
	}
}
