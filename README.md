# gosocks5

A zero-dependency SOCKS5 protocol library for Go, implementing [RFC 1928](https://tools.ietf.org/html/rfc1928) and [RFC 1929](https://tools.ietf.org/html/rfc1929) (username/password authentication).

## Usage

### Server

```go
package main

import (
    "log"
    "net"

    "github.com/go-gost/gosocks5/server"
)

func main() {
    ln, err := net.Listen("tcp", ":1080")
    if err != nil {
        log.Fatal(err)
    }
    srv := &server.Server{Listener: ln}
    log.Fatal(srv.Serve(server.DefaultHandler))
}
```

With authentication:

```go
import "net/url"

user, _ := url.Parse("http://user:pass@host")
users := []*url.Userinfo{user.User}
selector := server.NewServerSelector(users, gosocks5.MethodUserPass)

handler := &server.ServerHandler{Selector: selector}
srv.Serve(handler)
```

### Client

```go
import (
    "github.com/go-gost/gosocks5"
    "github.com/go-gost/gosocks5/client"
)

conn, err := client.Dial("server:1080")
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

addr, _ := gosocks5.NewAddr("example.com:80")
req := gosocks5.NewRequest(gosocks5.CmdConnect, addr)
req.Write(conn)

reply, _ := gosocks5.ReadReply(conn)
// read/write conn as a normal net.Conn from here
```

With authentication and timeout:

```go
import "net/url"

user, _ := url.Parse("http://user:pass@host")
selector := client.NewClientSelector(user.User, gosocks5.MethodUserPass)

conn, err := client.Dial("server:1080",
    client.SelectorDialOption(selector),
    client.TimeoutDialOption(30*time.Second),
)
```

## Supported auth methods

| Method | Constant |
|--------|----------|
| No authentication | `MethodNoAuth` |
| GSSAPI (reserved) | `MethodGSSAPI` |
| Username/password | `MethodUserPass` |

## License

MIT
