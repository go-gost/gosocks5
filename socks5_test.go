package gosocks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ReadMethods / WriteMethod
// ---------------------------------------------------------------------------

func TestReadMethods(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []uint8
		wantErr error
	}{
		{
			name:    "no auth",
			data:    []byte{Ver5, 1, MethodNoAuth},
			want:    []uint8{MethodNoAuth},
			wantErr: nil,
		},
		{
			name:    "multiple methods",
			data:    []byte{Ver5, 3, MethodNoAuth, MethodGSSAPI, MethodUserPass},
			want:    []uint8{MethodNoAuth, MethodGSSAPI, MethodUserPass},
			wantErr: nil,
		},
		{
			name:    "bad version",
			data:    []byte{4, 1, MethodNoAuth},
			want:    nil,
			wantErr: ErrBadVersion,
		},
		{
			name:    "zero methods",
			data:    []byte{Ver5, 0},
			want:    nil,
			wantErr: ErrBadMethod,
		},
		{
			name:    "short read",
			data:    []byte{Ver5},
			want:    nil,
			wantErr: io.ErrUnexpectedEOF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadMethods(bytes.NewReader(tt.data))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ReadMethods() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.want != nil && len(got) != len(tt.want) {
				t.Fatalf("ReadMethods() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteMethod(t *testing.T) {
	var buf bytes.Buffer
	err := WriteMethod(MethodNoAuth, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 2 || buf.Bytes()[0] != Ver5 || buf.Bytes()[1] != MethodNoAuth {
		t.Fatalf("WriteMethod() wrote %v", buf.Bytes())
	}
}

// ---------------------------------------------------------------------------
// UserPassRequest
// ---------------------------------------------------------------------------

func TestUserPassRequestRoundtrip(t *testing.T) {
	req := NewUserPassRequest(UserPassVer, "alice", "s3cret")
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatal(err)
	}
	r, err := ReadUserPassRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Username != req.Username || r.Password != req.Password || r.Version != req.Version {
		t.Fatalf("roundtrip mismatch: got %s:%s ver=%d", r.Username, r.Password, r.Version)
	}
}

func TestUserPassRequest_String(t *testing.T) {
	req := NewUserPassRequest(UserPassVer, "alice", "s3cret")
	if s := req.String(); s != "1 alice:s3cret" {
		t.Fatalf("String() = %q", s)
	}
}

func TestReadUserPassRequest_BadVersion(t *testing.T) {
	data := []byte{2, 5, 'a', 'l', 'i', 'c', 'e', 0}
	_, err := ReadUserPassRequest(bytes.NewReader(data))
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

func TestReadUserPassRequest_EmptyCreds(t *testing.T) {
	data := []byte{UserPassVer, 0, 0}
	r, err := ReadUserPassRequest(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if r.Username != "" || r.Password != "" {
		t.Fatalf("expected empty creds, got %q:%q", r.Username, r.Password)
	}
}

// ---------------------------------------------------------------------------
// UserPassResponse
// ---------------------------------------------------------------------------

func TestUserPassResponseRoundtrip(t *testing.T) {
	resp := NewUserPassResponse(UserPassVer, Succeeded)
	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		t.Fatal(err)
	}
	r, err := ReadUserPassResponse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != resp.Version || r.Status != resp.Status {
		t.Fatalf("roundtrip mismatch: got %+v", r)
	}
}

func TestUserPassResponse_String(t *testing.T) {
	resp := NewUserPassResponse(UserPassVer, Failure)
	if s := resp.String(); s != "1 1" {
		t.Fatalf("String() = %q", s)
	}
}

func TestReadUserPassResponse_BadVersion(t *testing.T) {
	_, err := ReadUserPassResponse(bytes.NewReader([]byte{2, 0}))
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Addr
// ---------------------------------------------------------------------------

func TestNewAddr(t *testing.T) {
	tests := []struct {
		addr    string
		want    string
		wantErr bool
	}{
		{"192.168.1.1:80", "192.168.1.1:80", false},
		{"[::1]:1080", "[::1]:1080", false},
		{"example.com:443", "example.com:443", false},
		{"invalid", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			a, err := NewAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewAddr(%q) error = %v", tt.addr, err)
			}
			if err == nil && a.String() != tt.want {
				t.Fatalf("NewAddr(%q) = %q, want %q", tt.addr, a.String(), tt.want)
			}
		})
	}
}

func TestAddr_ReadFrom_IPv4(t *testing.T) {
	// Build wire-format: ATYP=1, 4 bytes IP, 2 bytes port
	var buf bytes.Buffer
	buf.WriteByte(AddrIPv4)
	buf.Write(net.ParseIP("10.0.0.1").To4())
	binary.Write(&buf, binary.BigEndian, uint16(8080))

	var a Addr
	n, err := a.ReadFrom(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("read %d bytes, want 7", n)
	}
	if a.String() != "10.0.0.1:8080" {
		t.Fatalf("got %q", a.String())
	}
}

func TestAddr_ReadFrom_IPv6(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(AddrIPv6)
	buf.Write(net.ParseIP("::1").To16())
	binary.Write(&buf, binary.BigEndian, uint16(9090))

	var a Addr
	n, err := a.ReadFrom(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 19 {
		t.Fatalf("read %d bytes, want 19", n)
	}
	if a.String() != "[::1]:9090" {
		t.Fatalf("got %q", a.String())
	}
}

func TestAddr_ReadFrom_Domain(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(AddrDomain)
	buf.WriteByte(9)
	buf.WriteString("localhost")
	binary.Write(&buf, binary.BigEndian, uint16(443))

	var a Addr
	n, err := a.ReadFrom(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 13 {
		t.Fatalf("read %d bytes, want 13", n)
	}
	if a.String() != "localhost:443" {
		t.Fatalf("got %q", a.String())
	}
}

func TestAddr_ReadFrom_BadType(t *testing.T) {
	buf := bytes.NewReader([]byte{0x07})
	var a Addr
	_, err := a.ReadFrom(buf)
	if !errors.Is(err, ErrBadAddrType) {
		t.Fatalf("expected ErrBadAddrType, got %v", err)
	}
}

func TestAddr_Encode(t *testing.T) {
	tests := []struct {
		name string
		addr *Addr
	}{
		{"ipv4", &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 80}},
		{"ipv6", &Addr{Type: AddrIPv6, Host: "::1", Port: 443}},
		{"domain", &Addr{Type: AddrDomain, Host: "example.com", Port: 8080}},
		{"auto-detect ipv4", &Addr{Host: "192.168.1.1", Port: 22}},
		{"auto-detect domain", &Addr{Host: "example.com", Port: 22}},
		{"auto-detect ipv6", &Addr{Host: "2001:db8::1", Port: 22}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b [259]byte
			n, err := tt.addr.Encode(b[:])
			if err != nil {
				t.Fatal(err)
			}
			var decoded Addr
			if err := decoded.Decode(b[:n]); err != nil {
				t.Fatal(err)
			}
			if decoded.String() != tt.addr.String() {
				t.Fatalf("Encode/Decode mismatch: %q vs %q", decoded.String(), tt.addr.String())
			}
		})
	}
}

func TestAddr_Length(t *testing.T) {
	tests := []struct {
		addr *Addr
		want int
	}{
		{&Addr{Type: AddrIPv4, Host: "1.1.1.1", Port: 80}, 7},
		{&Addr{Type: AddrIPv6, Host: "::1", Port: 80}, 19},
		{&Addr{Type: AddrDomain, Host: "ab.cd", Port: 80}, 9}, // 4 + len("ab.cd") = 4+5
		{&Addr{Type: 99, Host: "", Port: 0}, 7},               // unknown type -> default 7
	}
	for _, tt := range tests {
		n := tt.addr.Length()
		if n != tt.want {
			t.Fatalf("Length(%+v) = %d, want %d", tt.addr, n, tt.want)
		}
	}
}

func TestAddr_WriteTo(t *testing.T) {
	a := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 9090}
	var buf bytes.Buffer
	n, err := a.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("wrote %d bytes, want 7", n)
	}
	var decoded Addr
	if err := decoded.Decode(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if decoded.String() != a.String() {
		t.Fatalf("%q != %q", decoded.String(), a.String())
	}
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

func TestRequestRoundtrip(t *testing.T) {
	addr := &Addr{Type: AddrDomain, Host: "example.com", Port: 443}
	req := NewRequest(CmdConnect, addr)

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatal(err)
	}
	r, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Cmd != req.Cmd || r.Addr.String() != req.Addr.String() {
		t.Fatalf("roundtrip mismatch: %+v", r)
	}
}

func TestRequest_IPv6Roundtrip(t *testing.T) {
	addr := &Addr{Type: AddrIPv6, Host: "2001:db8::1", Port: 80}
	req := NewRequest(CmdConnect, addr)

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatal(err)
	}
	r, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Addr.String() != "[2001:db8::1]:80" {
		t.Fatalf("got %q", r.Addr.String())
	}
}

func TestRequest_NilAddr(t *testing.T) {
	req := NewRequest(CmdConnect, nil)
	// nil addr writes as AddrIPv4 zero
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		t.Fatal(err)
	}
	r, err := ReadRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Addr == nil {
		t.Fatal("expected non-nil Addr after read")
	}
}

func TestRequest_String(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "1.2.3.4", Port: 80}
	req := NewRequest(CmdConnect, addr)
	s := req.String()
	if !strings.Contains(s, "1.2.3.4") {
		t.Fatalf("String() = %q", s)
	}
}

func TestReadRequest_BadVersion(t *testing.T) {
	buf := []byte{4, 0, 0, AddrIPv4, 0, 0, 0, 0, 0, 0}
	_, err := ReadRequest(bytes.NewReader(buf))
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

func TestReadRequest_BadAddrType(t *testing.T) {
	buf := []byte{Ver5, 0, 0, 0x07, 0, 0}
	_, err := ReadRequest(bytes.NewReader(buf))
	if !errors.Is(err, ErrBadAddrType) {
		t.Fatalf("expected ErrBadAddrType, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Reply
// ---------------------------------------------------------------------------

func TestReplyRoundtrip(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "0.0.0.0", Port: 0}
	rep := NewReply(Succeeded, addr)

	var buf bytes.Buffer
	if err := rep.Write(&buf); err != nil {
		t.Fatal(err)
	}
	r, err := ReadReply(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rep != rep.Rep {
		t.Fatalf("roundtrip mismatch: %+v", r)
	}
}

func TestReply_NilAddr(t *testing.T) {
	rep := NewReply(Succeeded, nil)
	var buf bytes.Buffer
	if err := rep.Write(&buf); err != nil {
		t.Fatal(err)
	}
	// nil Addr writes as IPv4 zeroes — should read back cleanly
	r, err := ReadReply(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rep != Succeeded {
		t.Fatalf("rep %d", r.Rep)
	}
}

func TestReply_String(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 1080}
	rep := NewReply(Succeeded, addr)
	s := rep.String()
	if !strings.Contains(s, "10.0.0.1") {
		t.Fatalf("String() = %q", s)
	}
}

func TestReply_Failure(t *testing.T) {
	rep := NewReply(Failure, nil)
	var buf bytes.Buffer
	if err := rep.Write(&buf); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if b[0] != Ver5 || b[1] != Failure {
		t.Fatalf("expected failure reply, got %v", b)
	}
}

func TestReadReply_BadVersion(t *testing.T) {
	buf := []byte{4, 0, 0, AddrIPv4, 0, 0, 0, 0, 0, 0}
	_, err := ReadReply(bytes.NewReader(buf))
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// UDPHeader
// ---------------------------------------------------------------------------

func TestUDPHeaderRoundtrip(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 5555}
	h := NewUDPHeader(0, 0, addr)
	var buf bytes.Buffer
	if _, err := h.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	var h2 UDPHeader
	if _, err := h2.ReadFrom(&buf); err != nil {
		t.Fatal(err)
	}
	if h2.Rsv != h.Rsv || h2.Frag != h.Frag || h2.Addr.String() != h.Addr.String() {
		t.Fatalf("roundtrip mismatch: got %+v", h2)
	}
}

func TestUDPHeader_ReadFromNilAddr(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "1.1.1.1", Port: 53}
	h := NewUDPHeader(0, 0, addr)
	var buf bytes.Buffer
	h.WriteTo(&buf)

	var h2 UDPHeader // h2.Addr is nil
	if _, err := h2.ReadFrom(&buf); err != nil {
		t.Fatal(err)
	}
	if h2.Addr.String() != "1.1.1.1:53" {
		t.Fatalf("Addr not populated: %v", h2.Addr)
	}
}

func TestUDPHeader_WriteToNilAddr(t *testing.T) {
	h := &UDPHeader{Rsv: 1, Frag: 2, Addr: nil}
	var buf bytes.Buffer
	_, err := h.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	// Should encode with empty Addr (IPv4 zeroes)
	if buf.Len() < 3+7 {
		t.Fatalf("too short: %d bytes", buf.Len())
	}
}

func TestUDPHeader_StringNilAddr(t *testing.T) {
	h := &UDPHeader{Rsv: 0, Frag: 0, Addr: nil}
	// Must not panic
	s := h.String()
	if s == "" {
		t.Fatal("empty String()")
	}
}

// ---------------------------------------------------------------------------
// UDPDatagram
// ---------------------------------------------------------------------------

func TestUDPDatagramRoundtrip(t *testing.T) {
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 9999}
	header := NewUDPHeader(0, 0, addr)
	data := []byte("hello")
	dg := NewUDPDatagram(header, data)
	var buf bytes.Buffer
	if _, err := dg.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	var dg2 UDPDatagram
	if _, err := dg2.ReadFrom(&buf); err != nil {
		t.Fatal(err)
	}
	if dg2.Header.Addr.String() != addr.String() {
		t.Fatalf("Addr mismatch: %q", dg2.Header.Addr.String())
	}
	if !bytes.Equal(dg2.Data, data) {
		t.Fatalf("data mismatch: %q", dg2.Data)
	}
}

func TestUDPDatagram_NilHeader(t *testing.T) {
	dg := NewUDPDatagram(nil, []byte("data"))
	// WriteTo should handle nil header
	var buf bytes.Buffer
	_, err := dg.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var dg2 UDPDatagram
	// should also handle nil Header on read
	dg2.Header = nil
	if _, err := dg2.ReadFrom(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dg2.Data, []byte("data")) {
		t.Fatalf("data mismatch: %q", dg2.Data)
	}
}

func TestUDPDatagram_ExtendedLength(t *testing.T) {
	// Extended feature: Rsv field as data length (used over TCP)
	addr := &Addr{Type: AddrIPv4, Host: "10.0.0.1", Port: 9999}
	header := NewUDPHeader(uint16(4), 0, addr) // Rsv = 4
	data := []byte("test")
	dg := NewUDPDatagram(header, data)
	var buf bytes.Buffer
	if _, err := dg.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	// Read back with insufficient buffer
	var dg2 UDPDatagram
	dg2.Data = make([]byte, 2) // shorter than Rsv=4
	if _, err := dg2.ReadFrom(&buf); err != nil {
		t.Fatal(err)
	}
	if len(dg2.Data) != 4 {
		t.Fatalf("expected Data length 4, got %d", len(dg2.Data))
	}
}

// ---------------------------------------------------------------------------
// Error sentinels
// ---------------------------------------------------------------------------

func TestErrors(t *testing.T) {
	if ErrBadVersion.Error() == "" {
		t.Fatal("ErrBadVersion empty")
	}
	if ErrBadFormat.Error() == "" {
		t.Fatal("ErrBadFormat empty")
	}
	if ErrBadAddrType.Error() == "" {
		t.Fatal("ErrBadAddrType empty")
	}
	if ErrBadMethod.Error() == "" {
		t.Fatal("ErrBadMethod empty")
	}
	if ErrAuthFailure.Error() == "" {
		t.Fatal("ErrAuthFailure empty")
	}
	if ErrShortBuffer.Error() == "" {
		t.Fatal("ErrShortBuffer empty")
	}
}
