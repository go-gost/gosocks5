package gosocks5

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func mkAddr(atyp uint8, addr []byte, port uint16) []byte {
	buf := []byte{Ver5, CmdConnect, 0, atyp}
	buf = append(buf, addr...)
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, port)
	return append(buf, p...)
}

// FuzzAddrDecode parses the SOCKS5 address wire format from a raw slice.
// Input is attacker-controlled; a panic is a remote DoS. Seeds cover IPv4,
// domain, IPv6, and the short-buffer / bad-type error paths.
func FuzzAddrDecode(f *testing.F) {
	ipv4 := []byte{AddrIPv4, 127, 0, 0, 1, 0, 80}
	domain := []byte{AddrDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 1, 0xBB}
	ipv6 := make([]byte, 1+net.IPv6len+2)
	ipv6[0] = AddrIPv6
	binary.BigEndian.PutUint16(ipv6[1+net.IPv6len:], 8080)

	f.Add([]byte{})              // empty
	f.Add(ipv4)
	f.Add(domain)
	f.Add(ipv6)
	f.Add([]byte{AddrIPv4})      // too short
	f.Add([]byte{0x07, 0, 0})    // bad addr type
	f.Add([]byte{AddrDomain})    // domain, no length byte
	f.Add([]byte{AddrDomain, 5, 'a', 'b'}) // domain, short data
	f.Fuzz(func(t *testing.T, b []byte) {
		var a Addr
		_ = a.Decode(b) // must not panic / read out of bounds
	})
}

// FuzzReadRequest parses a SOCKS5 request stream.
func FuzzReadRequest(f *testing.F) {
	f.Add(mkAddr(AddrIPv4, net.ParseIP("10.0.0.1").To4(), 8080))
	f.Add(mkAddr(AddrDomain, append([]byte{9}, []byte("localhost")...), 443))
	f.Add(mkAddr(AddrIPv6, net.ParseIP("::1").To16(), 8080))
	f.Add([]byte{Ver5, CmdConnect, 0, 0x07, 0, 0, 0, 0, 0, 0}) // bad addr type
	f.Add([]byte{Ver5, CmdConnect})                            // readAtLeast error
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadRequest(bytes.NewReader(b))
	})
}

// FuzzReadReply parses a SOCKS5 reply stream.
func FuzzReadReply(f *testing.F) {
	f.Add(mkAddr(AddrIPv4, net.ParseIP("10.0.0.1").To4(), 8080))
	f.Add(mkAddr(AddrDomain, append([]byte{9}, []byte("localhost")...), 443))
	f.Add(mkAddr(AddrIPv6, net.ParseIP("::1").To16(), 8080))
	f.Add([]byte{Ver5, Succeeded, 0, 0x07, 0, 0, 0, 0, 0, 0}) // bad addr type
	f.Add([]byte{Ver5, Succeeded})                           // readAtLeast error
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadReply(bytes.NewReader(b))
	})
}

// mkUDP builds a SOCKS5 UDP datagram wire frame: 3-byte header (Rsv, Frag,
// ATYP) + address body (host bytes + 2-byte port) + data.
func mkUDP(rsv uint16, frag uint8, atyp uint8, addrBody, data []byte) []byte {
	buf := []byte{byte(rsv >> 8), byte(rsv), frag, atyp}
	buf = append(buf, addrBody...)
	return append(buf, data...)
}

// FuzzUDPHeaderReadFrom parses the 3-byte UDP header + address from a stream.
// Input is attacker-controlled (SOCKS5 UDP relay). A panic is a DoS. Seeds cover
// IPv4/domain/IPv6 addresses and the short-header error paths.
func FuzzUDPHeaderReadFrom(f *testing.F) {
	domainBody := []byte{9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x01, 0xBB}
	f.Add(mkUDP(0, 0, AddrIPv4, []byte{127, 0, 0, 1, 0, 80}, nil))
	f.Add(mkUDP(0, 0, AddrDomain, domainBody, nil))
	f.Add(mkUDP(0, 0, AddrIPv6, append(net.ParseIP("::1").To16(), 0, 80), nil))
	f.Add([]byte{0})       // short header
	f.Add([]byte{0, 0, 0}) // header only, no address
	f.Fuzz(func(t *testing.T, b []byte) {
		var h UDPHeader
		_, _ = h.ReadFrom(bytes.NewReader(b))
	})
}

// FuzzUDPDatagramReadFrom parses a full SOCKS5 UDP datagram. In the
// UDP-over-TCP "extended" mode the Rsv field is repurposed as the data length,
// so a hostile Rsv drives a large allocation + readFull — it must stay
// panic/OOB-free. Seeds cover standard mode (Rsv=0), extended mode (Rsv=N
// matching the data length), an oversized Rsv with no data, and short input.
func FuzzUDPDatagramReadFrom(f *testing.F) {
	domainBody := []byte{9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x01, 0xBB}
	f.Add(mkUDP(0, 0, AddrIPv4, []byte{127, 0, 0, 1, 0, 80}, []byte("payload")))
	f.Add(mkUDP(0, 0, AddrDomain, domainBody, []byte("data")))
	f.Add(mkUDP(0, 0, AddrIPv6, append(net.ParseIP("::1").To16(), 0, 80), []byte("data")))
	f.Add(mkUDP(5, 0, AddrIPv4, []byte{127, 0, 0, 1, 0, 80}, []byte("hello")))   // extended, exact len
	f.Add(mkUDP(0xFF, 0xFF, AddrIPv4, []byte{127, 0, 0, 1, 0, 80}, nil))         // extended, huge Rsv, no data
	f.Add([]byte{0})                                                                  // short header
	f.Fuzz(func(t *testing.T, b []byte) {
		var d UDPDatagram
		_, _ = d.ReadFrom(bytes.NewReader(b))
	})
}
