package client

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/gosocks5"
)

// Dial connects to the SOCKS5 server.
func Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, o := range options {
		o(opts)
	}

	conn, err := net.DialTimeout("tcp", addr, opts.Timeout)
	if err != nil {
		return nil, err
	}

	selector := opts.Selector
	if selector == nil {
		selector = DefaultSelector
	}

	cc := gosocks5.ClientConn(conn, selector)
	if err := cc.Handleshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

// DialContext connects to the SOCKS5 server with the given context.
func DialContext(ctx context.Context, addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, o := range options {
		o(opts)
	}

	conn, err := (&net.Dialer{Timeout: opts.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	selector := opts.Selector
	if selector == nil {
		selector = DefaultSelector
	}

	cc := gosocks5.ClientConn(conn, selector)
	if err := cc.Handleshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

// DialOptions describes the options for Transporter.Dial.
type DialOptions struct {
	Selector gosocks5.Selector
	Timeout  time.Duration
}

// DialOption allows a common way to set dial options.
type DialOption func(opts *DialOptions)

func SelectorDialOption(selector gosocks5.Selector) DialOption {
	return func(opts *DialOptions) {
		opts.Selector = selector
	}
}

func TimeoutDialOption(timeout time.Duration) DialOption {
	return func(opts *DialOptions) {
		opts.Timeout = timeout
	}
}
