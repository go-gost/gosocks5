// SOCKS Protocol Version 5
// http://tools.ietf.org/html/rfc1928
// http://tools.ietf.org/html/rfc1929
package gosocks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Ver5        = 5
	UserPassVer = 1
)

const (
	MethodNoAuth uint8 = iota
	MethodGSSAPI
	MethodUserPass
	// X'03' to X'7F' IANA ASSIGNED
	// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	MethodNoAcceptable = 0xFF
)

const (
	CmdConnect uint8 = 1
	CmdBind    uint8 = 2
	CmdUdp     uint8 = 3
)

const (
	AddrIPv4   uint8 = 1
	AddrDomain uint8 = 3
	AddrIPv6   uint8 = 4
)

const (
	Succeeded uint8 = iota
	Failure
	NotAllowed
	NetUnreachable
	HostUnreachable
	ConnRefused
	TTLExpired
	CmdUnsupported
	AddrUnsupported
)

var (
	ErrBadVersion  = errors.New("bad version")
	ErrBadFormat   = errors.New("bad format")
	ErrBadAddrType = errors.New("bad address type")
	ErrShortBuffer = errors.New("short buffer")
	ErrBadMethod   = errors.New("bad method")
	ErrAuthFailure = errors.New("auth failure")
)

/*
Method selection

	+----+----------+----------+
	|VER | NMETHODS | METHODS  |
	+----+----------+----------+
	| 1  |    1     | 1 to 255 |
	+----+----------+----------+
*/
func ReadMethods(r io.Reader) ([]uint8, error) {
	var b [257]byte

	if _, err := io.ReadFull(r, b[:2]); err != nil {
		return nil, err
	}

	if b[0] != Ver5 {
		return nil, ErrBadVersion
	}

	if b[1] == 0 {
		return nil, ErrBadMethod
	}

	if _, err := io.ReadFull(r, b[2:2+int(b[1])]); err != nil {
		return nil, err
	}

	methods := make([]byte, int(b[1]))
	copy(methods, b[2:])

	return methods, nil
}

func WriteMethod(method uint8, w io.Writer) error {
	_, err := w.Write([]byte{Ver5, method})
	return err
}

/*
Username/Password authentication request

	+----+------+----------+------+----------+
	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	+----+------+----------+------+----------+
	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	+----+------+----------+------+----------+
*/
type UserPassRequest struct {
	Version  byte
	Username string
	Password string
}

func NewUserPassRequest(ver byte, u, p string) *UserPassRequest {
	return &UserPassRequest{
		Version:  ver,
		Username: u,
		Password: p,
	}
}

func ReadUserPassRequest(r io.Reader) (*UserPassRequest, error) {
	var b [255]byte

	if _, err := io.ReadFull(r, b[:2]); err != nil {
		return nil, err
	}

	if b[0] != UserPassVer {
		return nil, ErrBadVersion
	}

	req := &UserPassRequest{
		Version: b[0],
	}

	ulen := int(b[1])
	if ulen > 0 {
		if _, err := io.ReadFull(r, b[:ulen]); err != nil {
			return nil, err
		}
	}
	req.Username = string(b[:ulen])

	if _, err := io.ReadFull(r, b[:1]); err != nil {
		return nil, err
	}
	plen := int(b[0])
	if plen > 0 {
		if _, err := io.ReadFull(r, b[:plen]); err != nil {
			return nil, err
		}
	}
	req.Password = string(b[:plen])
	return req, nil
}

func (req *UserPassRequest) Write(w io.Writer) error {
	var b [513]byte

	b[0] = req.Version
	ulen := len(req.Username)
	b[1] = byte(ulen)
	length := 2 + ulen
	copy(b[2:length], req.Username)

	plen := len(req.Password)
	b[length] = byte(plen)
	length++
	copy(b[length:length+plen], req.Password)
	length += plen

	_, err := w.Write(b[:length])
	return err
}

func (req *UserPassRequest) String() string {
	return fmt.Sprintf("%d %s:%s",
		req.Version, req.Username, req.Password)
}

/*
Username/Password authentication response

	+----+--------+
	|VER | STATUS |
	+----+--------+
	| 1  |   1    |
	+----+--------+
*/
type UserPassResponse struct {
	Version byte
	Status  byte
}

func NewUserPassResponse(ver, status byte) *UserPassResponse {
	return &UserPassResponse{
		Version: ver,
		Status:  status,
	}
}

func ReadUserPassResponse(r io.Reader) (*UserPassResponse, error) {
	var b [2]byte

	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}

	if b[0] != UserPassVer {
		return nil, ErrBadVersion
	}

	res := &UserPassResponse{
		Version: b[0],
		Status:  b[1],
	}

	return res, nil
}

func (res *UserPassResponse) Write(w io.Writer) error {
	_, err := w.Write([]byte{res.Version, res.Status})
	return err
}

func (res *UserPassResponse) String() string {
	return fmt.Sprintf("%d %d",
		res.Version, res.Status)
}

/*
Address

	+------+----------+----------+
	| ATYP |   ADDR   |   PORT   |
	+------+----------+----------+
	|  1   | Variable |    2     |
	+------+----------+----------+
*/
type Addr struct {
	Type uint8
	Host string
	Port uint16
}

func NewAddr(sa string) (addr *Addr, err error) {
	addr = &Addr{}
	err = addr.ParseFrom(sa)
	return
}

func (addr *Addr) ParseFrom(saddr string) error {
	host, sport, err := net.SplitHostPort(saddr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return err
	}

	addr.Host = host
	addr.Port = uint16(port)
	addr.checkType()

	return nil
}

func (addr *Addr) ReadFrom(r io.Reader) (n int64, err error) {
	var b [255]byte

	_, err = io.ReadFull(r, b[:1])
	if err != nil {
		return
	}
	addr.Type = b[0]
	n++

	switch addr.Type {
	case AddrIPv4:
		_, err = io.ReadFull(r, b[:net.IPv4len])
		addr.Host = net.IP(b[:net.IPv4len]).String()
		n += net.IPv4len
	case AddrIPv6:
		_, err = io.ReadFull(r, b[:net.IPv6len])
		addr.Host = net.IP(b[:net.IPv6len]).String()
		n += net.IPv6len
	case AddrDomain:
		if _, err = io.ReadFull(r, b[:1]); err != nil {
			return
		}
		addrlen := int(b[0])
		n++

		_, err = io.ReadFull(r, b[:addrlen])
		addr.Host = string(b[:addrlen])
		n += int64(addrlen)
	default:
		err = ErrBadAddrType
		return
	}
	if err != nil {
		return
	}

	_, err = io.ReadFull(r, b[:2])
	addr.Port = binary.BigEndian.Uint16(b[:2])
	n += 2

	return
}

func (addr *Addr) WriteTo(w io.Writer) (int64, error) {
	var b [259]byte
	nn, err := addr.Encode(b[:])
	if err != nil {
		return int64(nn), err
	}

	nn, err = w.Write(b[:nn])
	return int64(nn), err
}

func (addr *Addr) Decode(b []byte) error {
	_, err := addr.ReadFrom(bytes.NewReader(b))
	return err
}

func (addr *Addr) Encode(b []byte) (int, error) {
	addr.checkType()

	b[0] = addr.Type
	pos := 1
	switch addr.Type {
	case AddrIPv4:
		ip4 := net.ParseIP(addr.Host).To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		pos += copy(b[pos:], ip4)
	case AddrIPv6:
		ip16 := net.ParseIP(addr.Host).To16()
		if ip16 == nil {
			ip16 = net.IPv6zero.To16()
		}
		pos += copy(b[pos:], ip16)
	case AddrDomain:
		b[pos] = byte(len(addr.Host))
		pos++
		pos += copy(b[pos:], []byte(addr.Host))
	default:
		b[0] = AddrIPv4
		copy(b[pos:pos+net.IPv4len], net.IPv4zero.To4())
		pos += net.IPv4len
	}
	binary.BigEndian.PutUint16(b[pos:], addr.Port)
	pos += 2

	return pos, nil
}

func (addr *Addr) checkType() {
	switch addr.Type {
	case AddrIPv4, AddrIPv6, AddrDomain:
	default:
		addr.Type = AddrIPv4
		if addr.Host != "" {
			addr.Type = AddrDomain
			if ip := net.ParseIP(addr.Host); ip != nil {
				if ip.To4() != nil {
					addr.Type = AddrIPv4
				} else {
					addr.Type = AddrIPv6
				}
			}
		}
	}
}

func (addr *Addr) Length() (n int) {
	addr.checkType()

	switch addr.Type {
	case AddrIPv4:
		n = 7
	case AddrIPv6:
		n = 19
	case AddrDomain:
		n = 4 + len(addr.Host)
	default:
		n = 7
	}
	return
}

func (addr *Addr) String() string {
	return net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port)))
}

/*
The SOCKSv5 request

	+----+-----+-------+------+----------+----------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
*/
type Request struct {
	Cmd  uint8
	Addr *Addr
}

func NewRequest(cmd uint8, addr *Addr) *Request {
	return &Request{
		Cmd:  cmd,
		Addr: addr,
	}
}

func ReadRequest(r io.Reader) (*Request, error) {
	var b [262]byte

	n, err := io.ReadAtLeast(r, b[:], 5)
	if err != nil {
		return nil, err
	}

	if b[0] != Ver5 {
		return nil, ErrBadVersion
	}

	request := &Request{
		Cmd: b[1],
	}

	atype := b[3]
	length := 0
	switch atype {
	case AddrIPv4:
		length = 10
	case AddrIPv6:
		length = 22
	case AddrDomain:
		length = 7 + int(b[4])
	default:
		return nil, ErrBadAddrType
	}

	if n < length {
		if _, err := io.ReadFull(r, b[n:length]); err != nil {
			return nil, err
		}
	}
	addr := new(Addr)
	if err := addr.Decode(b[3:length]); err != nil {
		return nil, err
	}
	request.Addr = addr

	return request, nil
}

func (r *Request) Write(w io.Writer) (err error) {
	var b [262]byte

	b[0] = Ver5
	b[1] = r.Cmd
	b[2] = 0        //rsv
	b[3] = AddrIPv4 // default

	addr := r.Addr
	if addr == nil {
		addr = &Addr{}
	}
	n, _ := addr.Encode(b[3:])
	length := 3 + n

	_, err = w.Write(b[:length])
	return
}

func (r *Request) String() string {
	addr := r.Addr
	if addr == nil {
		addr = &Addr{}
	}
	return fmt.Sprintf("5 %d 0 %d %s",
		r.Cmd, addr.Type, addr.String())
}

/*
The SOCKSv5 reply

	+----+-----+-------+------+----------+----------+
	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+
*/
type Reply struct {
	Rep  uint8
	Addr *Addr
}

func NewReply(rep uint8, addr *Addr) *Reply {
	return &Reply{
		Rep:  rep,
		Addr: addr,
	}
}

func ReadReply(r io.Reader) (*Reply, error) {
	var b [262]byte

	n, err := io.ReadAtLeast(r, b[:], 5)
	if err != nil {
		return nil, err
	}

	if b[0] != Ver5 {
		return nil, ErrBadVersion
	}

	reply := &Reply{
		Rep: b[1],
	}

	atype := b[3]
	length := 0
	switch atype {
	case AddrIPv4:
		length = 10
	case AddrIPv6:
		length = 22
	case AddrDomain:
		length = 7 + int(b[4])
	default:
		return nil, ErrBadAddrType
	}

	if n < length {
		if _, err := io.ReadFull(r, b[n:length]); err != nil {
			return nil, err
		}
	}

	addr := new(Addr)
	if err := addr.Decode(b[3:length]); err != nil {
		return nil, err
	}
	reply.Addr = addr

	return reply, nil
}

func (r *Reply) Write(w io.Writer) (err error) {
	var b [262]byte

	b[0] = Ver5
	b[1] = r.Rep
	b[2] = 0        //rsv
	b[3] = AddrIPv4 // default
	length := 10
	b[4], b[5], b[6], b[7], b[8], b[9] = 0, 0, 0, 0, 0, 0 // reset address field

	if r.Addr != nil {
		n, _ := r.Addr.Encode(b[3:])
		length = 3 + n
	}
	_, err = w.Write(b[:length])

	return
}

func (r *Reply) String() string {
	addr := r.Addr
	if addr == nil {
		addr = &Addr{}
	}
	return fmt.Sprintf("5 %d 0 %d %s",
		r.Rep, addr.Type, addr.String())
}

/*
UDP request

	+----+------+------+----------+----------+----------+
	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	+----+------+------+----------+----------+----------+
	| 2  |  1   |  1   | Variable |    2     | Variable |
	+----+------+------+----------+----------+----------+
*/
type UDPHeader struct {
	Rsv  uint16
	Frag uint8
	Addr *Addr
}

func NewUDPHeader(rsv uint16, frag uint8, addr *Addr) *UDPHeader {
	return &UDPHeader{
		Rsv:  rsv,
		Frag: frag,
		Addr: addr,
	}
}

func (h *UDPHeader) ReadFrom(r io.Reader) (n int64, err error) {
	var b [3]byte

	nn, err := io.ReadFull(r, b[:])
	n += int64(nn)
	if err != nil {
		return
	}

	h.Rsv = binary.BigEndian.Uint16(b[:2])
	h.Frag = b[2]

	if h.Addr == nil {
		h.Addr = &Addr{}
	}
	v, err := h.Addr.ReadFrom(r)
	n += v
	if err != nil {
		return
	}

	return
}

func (h *UDPHeader) WriteTo(w io.Writer) (int64, error) {
	var b [3]byte
	binary.BigEndian.PutUint16(b[:2], h.Rsv)
	b[2] = h.Frag

	if n, err := w.Write(b[:]); err != nil {
		return int64(n), err
	}

	addr := h.Addr
	if addr == nil {
		addr = &Addr{}
	}
	nn, err := addr.WriteTo(w)
	return 3 + nn, err
}

func (h *UDPHeader) String() string {
	return fmt.Sprintf("%d %d %d %s",
		h.Rsv, h.Frag, h.Addr.Type, h.Addr.String())
}

type UDPDatagram struct {
	Header *UDPHeader
	Data   []byte
}

func NewUDPDatagram(header *UDPHeader, data []byte) *UDPDatagram {
	return &UDPDatagram{
		Header: header,
		Data:   data,
	}
}

// ReadFrom reads UDP datagram from r.
func (d *UDPDatagram) ReadFrom(r io.Reader) (n int64, err error) {
	if d.Header == nil {
		d.Header = &UDPHeader{}
	}
	n, err = d.Header.ReadFrom(r)
	if err != nil {
		return
	}

	dlen := int64(d.Header.Rsv)
	if dlen == 0 { // standard SOCKS5 UDP datagram
		buf := bytes.NewBuffer(d.Data[:0])
		if _, err = io.Copy(buf, r); err != nil {
			return
		}
		d.Data = buf.Bytes()

		dlen = int64(len(d.Data))
	} else { // extended feature, for UDP over TCP, using reserved field as data length
		if len(d.Data) >= int(dlen) {
			d.Data = d.Data[:dlen]
		} else {
			d.Data = make([]byte, dlen)
		}
		if _, err = io.ReadFull(r, d.Data[:]); err != nil {
			return
		}
	}

	n += dlen

	return
}

func (d *UDPDatagram) WriteTo(w io.Writer) (n int64, err error) {
	h := d.Header
	if h == nil {
		h = &UDPHeader{}
	}
	n, err = h.WriteTo(w)
	if err != nil {
		return
	}
	nn, err := w.Write(d.Data)
	n += int64(nn)
	if err != nil {
		return
	}

	return
}
