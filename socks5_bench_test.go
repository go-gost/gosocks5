package gosocks5

import (
	"bytes"
	"io"
	"testing"
)

// ---------------------------------------------------------------------------
// Addr.Encode
// ---------------------------------------------------------------------------

func BenchmarkAddr_Encode_IPv4(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 8080}
	var buf [259]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr.Encode(buf[:])
	}
}

func BenchmarkAddr_Encode_IPv6(b *testing.B) {
	addr := &Addr{Type: AddrIPv6, Host: "2001:db8::1", Port: 443}
	var buf [259]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr.Encode(buf[:])
	}
}

func BenchmarkAddr_Encode_Domain(b *testing.B) {
	addr := &Addr{Type: AddrDomain, Host: "example.com", Port: 443}
	var buf [259]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr.Encode(buf[:])
	}
}

// ---------------------------------------------------------------------------
// Addr.Decode
// ---------------------------------------------------------------------------

func BenchmarkAddr_Decode_IPv4(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 8080}
	var buf [259]byte
	n, _ := addr.Encode(buf[:])
	wire := make([]byte, n)
	copy(wire, buf[:n])

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var a Addr
		a.Decode(wire)
	}
}

func BenchmarkAddr_Decode_IPv6(b *testing.B) {
	addr := &Addr{Type: AddrIPv6, Host: "2001:db8::1", Port: 443}
	var buf [259]byte
	n, _ := addr.Encode(buf[:])
	wire := make([]byte, n)
	copy(wire, buf[:n])

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var a Addr
		a.Decode(wire)
	}
}

func BenchmarkAddr_Decode_Domain(b *testing.B) {
	addr := &Addr{Type: AddrDomain, Host: "example.com", Port: 443}
	var buf [259]byte
	n, _ := addr.Encode(buf[:])
	wire := make([]byte, n)
	copy(wire, buf[:n])

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var a Addr
		a.Decode(wire)
	}
}

// ---------------------------------------------------------------------------
// ReadRequest
// ---------------------------------------------------------------------------

func BenchmarkReadRequest_IPv4(b *testing.B) {
	req := NewRequest(CmdConnect, &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 8080})
	var buf bytes.Buffer
	req.Write(&buf)
	wire := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadRequest(bytes.NewReader(wire))
	}
}

func BenchmarkReadRequest_Domain(b *testing.B) {
	req := NewRequest(CmdConnect, &Addr{Type: AddrDomain, Host: "example.com", Port: 443})
	var buf bytes.Buffer
	req.Write(&buf)
	wire := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadRequest(bytes.NewReader(wire))
	}
}

// ---------------------------------------------------------------------------
// Request.Write
// ---------------------------------------------------------------------------

func BenchmarkRequest_Write(b *testing.B) {
	req := NewRequest(CmdConnect, &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 8080})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Write(io.Discard)
	}
}

// ---------------------------------------------------------------------------
// ReadReply
// ---------------------------------------------------------------------------

func BenchmarkReadReply_IPv4(b *testing.B) {
	rep := NewReply(Succeeded, &Addr{Type: AddrIPv4, Host: "0.0.0.0", Port: 0})
	var buf bytes.Buffer
	rep.Write(&buf)
	wire := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadReply(bytes.NewReader(wire))
	}
}

// ---------------------------------------------------------------------------
// Reply.Write
// ---------------------------------------------------------------------------

func BenchmarkReply_Write(b *testing.B) {
	rep := NewReply(Succeeded, &Addr{Type: AddrIPv4, Host: "0.0.0.0", Port: 0})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep.Write(io.Discard)
	}
}

// ---------------------------------------------------------------------------
// UDPHeader ReadFrom / WriteTo
// ---------------------------------------------------------------------------

func BenchmarkUDPHeader_ReadFrom(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 5555}
	h := NewUDPHeader(0, 0, addr)
	var buf bytes.Buffer
	h.WriteTo(&buf)
	wire := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var h2 UDPHeader
		h2.ReadFrom(bytes.NewReader(wire))
	}
}

func BenchmarkUDPHeader_WriteTo(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 5555}
	h := NewUDPHeader(0, 0, addr)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.WriteTo(io.Discard)
	}
}

// ---------------------------------------------------------------------------
// UDPDatagram ReadFrom / WriteTo
// ---------------------------------------------------------------------------

func BenchmarkUDPDatagram_ReadFrom(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 9999}
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	h := NewUDPHeader(0, 0, addr)
	dg := NewUDPDatagram(h, payload)
	var buf bytes.Buffer
	dg.WriteTo(&buf)
	wire := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dg2 UDPDatagram
		dg2.ReadFrom(bytes.NewReader(wire))
	}
}

func BenchmarkUDPDatagram_WriteTo(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 9999}
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	h := NewUDPHeader(0, 0, addr)
	dg := NewUDPDatagram(h, payload)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dg.WriteTo(io.Discard)
	}
}

// ---------------------------------------------------------------------------
// ReadMethods / WriteMethod
// ---------------------------------------------------------------------------

func BenchmarkReadMethods(b *testing.B) {
	wire := []byte{Ver5, 1, MethodNoAuth}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadMethods(bytes.NewReader(wire))
	}
}

func BenchmarkWriteMethod(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		WriteMethod(MethodNoAuth, io.Discard)
	}
}

// ---------------------------------------------------------------------------
// UserPassRequest roundtrip
// ---------------------------------------------------------------------------

func BenchmarkUserPassRequest_Roundtrip(b *testing.B) {
	req := NewUserPassRequest(UserPassVer, "alice", "s3cret")
	var buf bytes.Buffer
	req.Write(&buf)
	wire := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadUserPassRequest(bytes.NewReader(wire))
	}
}

func BenchmarkUserPassRequest_Write(b *testing.B) {
	req := NewUserPassRequest(UserPassVer, "alice", "s3cret")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Write(io.Discard)
	}
}

// ---------------------------------------------------------------------------
// UserPassResponse roundtrip
// ---------------------------------------------------------------------------

func BenchmarkUserPassResponse_Roundtrip(b *testing.B) {
	resp := NewUserPassResponse(UserPassVer, Succeeded)
	var buf bytes.Buffer
	resp.Write(&buf)
	wire := buf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ReadUserPassResponse(bytes.NewReader(wire))
	}
}

func BenchmarkUserPassResponse_Write(b *testing.B) {
	resp := NewUserPassResponse(UserPassVer, Succeeded)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp.Write(io.Discard)
	}
}

// ---------------------------------------------------------------------------
// NewAddr (ParseFrom)
// ---------------------------------------------------------------------------

func BenchmarkNewAddr_IPv4(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewAddr("10.0.0.1:8080")
	}
}

func BenchmarkNewAddr_IPv6(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewAddr("[2001:db8::1]:443")
	}
}

func BenchmarkNewAddr_Domain(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewAddr("example.com:443")
	}
}

// ---------------------------------------------------------------------------
// Addr String
// ---------------------------------------------------------------------------

func BenchmarkAddr_String(b *testing.B) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 8080}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = addr.String()
	}
}

// ---------------------------------------------------------------------------
// Addr Length
// ---------------------------------------------------------------------------

func BenchmarkAddr_Length(b *testing.B) {
	addr := &Addr{Type: AddrDomain, Host: "example.com", Port: 443}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = addr.Length()
	}
}

// ---------------------------------------------------------------------------
// toSocksAddr-like conversion
// ---------------------------------------------------------------------------

func BenchmarkAddr_Encode_WithCheckType(b *testing.B) {
	// Simulate parsing an address string then encoding (full hot path)
	addr := &Addr{Host: "example.com", Port: 443}
	var buf [259]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr.Encode(buf[:])
	}
}
