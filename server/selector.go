package server

import (
	"net"
	"net/url"

	"github.com/go-gost/gosocks5"
)

var (
	// DefaultSelector is the default server selector.
	// It only supports No-Auth Method.
	DefaultSelector gosocks5.Selector = &serverSelector{}
)

type serverSelector struct {
	methods []uint8
	users   []*url.Userinfo
}

func NewServerSelector(users []*url.Userinfo, methods ...uint8) gosocks5.Selector {
	return &serverSelector{
		methods: methods,
		users:   users,
	}
}

func (selector *serverSelector) Methods() []uint8 {
	return selector.methods
}

func (selector *serverSelector) AddMethod(methods ...uint8) {
	selector.methods = append(selector.methods, methods...)
}

func (selector *serverSelector) Select(methods ...uint8) (method uint8) {
	method = gosocks5.MethodNoAuth

	// when user/pass is set, auth is mandatory
	if len(selector.users) > 0 {
		method = gosocks5.MethodNoAcceptable
		for _, m := range methods {
			if m == gosocks5.MethodUserPass {
				method = gosocks5.MethodUserPass
				return
			}
		}
		return
	}

	return
}

func (selector *serverSelector) OnSelected(method uint8, conn net.Conn) (string, net.Conn, error) {
	switch method {
	case gosocks5.MethodNoAuth:
		return "", conn, nil

	case gosocks5.MethodUserPass:
		req, err := gosocks5.ReadUserPassRequest(conn)
		if err != nil {
			return "", nil, err
		}

		valid := false
		for _, user := range selector.users {
			username := user.Username()
			password, _ := user.Password()
			if (req.Username == username && req.Password == password) ||
				(req.Username == username && password == "") {
				valid = true
				break
			}
		}
		if len(selector.users) > 0 && !valid {
			resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Failure)
			if err := resp.Write(conn); err != nil {
				return "", nil, err
			}
			return "", nil, gosocks5.ErrAuthFailure
		}

		resp := gosocks5.NewUserPassResponse(gosocks5.UserPassVer, gosocks5.Succeeded)
		if err := resp.Write(conn); err != nil {
			return "", nil, err
		}
		return "", conn, nil

	case gosocks5.MethodNoAcceptable:
		return "", nil, gosocks5.ErrBadMethod
	default:
		return "", nil, gosocks5.ErrBadFormat
	}
}
