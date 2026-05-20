package gosocks5_test

import (
	"net"
	"testing"

	gosocks5 "github.com/go-gost/gosocks5"
	"github.com/go-gost/gosocks5/client"
)

// noAuthSelector is defined in conn_test.go — reuse it.

func BenchmarkConn_Handshake(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cli, srv := net.Pipe()
		cc := gosocks5.ClientConn(cli, client.DefaultSelector)
		sc := gosocks5.ServerConn(srv, &noAuthSelector{})

		errCh := make(chan error, 2)
		go func() { errCh <- sc.Handleshake() }()
		go func() { errCh <- cc.Handleshake() }()

		<-errCh
		<-errCh

		cli.Close()
		srv.Close()
	}
}

func BenchmarkConn_Read(b *testing.B) {
	cli, srv := net.Pipe()
	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	// Pre-handshake
	go sc.Handleshake()
	if err := cc.Handleshake(); err != nil {
		b.Fatal(err)
	}

	// Write data from server side so client can read it
	go func() {
		data := make([]byte, 1500)
		for i := 0; i < b.N; i++ {
			srv.Write(data)
		}
		srv.Close()
	}()

	buf := make([]byte, 1500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc.Read(buf)
	}
}

func BenchmarkConn_Write(b *testing.B) {
	cli, srv := net.Pipe()
	cc := gosocks5.ClientConn(cli, client.DefaultSelector)
	sc := gosocks5.ServerConn(srv, &noAuthSelector{})

	// Pre-handshake
	go sc.Handleshake()
	if err := cc.Handleshake(); err != nil {
		b.Fatal(err)
	}

	// Drain server side
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, err := srv.Read(buf); err != nil {
				return
			}
		}
	}()

	data := make([]byte, 1500)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc.Write(data)
	}
	cli.Close()
	srv.Close()
}
