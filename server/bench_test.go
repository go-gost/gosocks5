package server

import (
	"io"
	"net"
	"testing"
)

func BenchmarkTransport(b *testing.B) {
	data := make([]byte, 65536)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c1, c2 := net.Pipe()

		// Write data to c1 then close it (signals EOF to CopyBuffer).
		go func() {
			c1.Write(data)
			c1.Close()
		}()

		// Drain c2 so CopyBuffer's writes to c2 don't block.
		go func() {
			io.Copy(io.Discard, c2)
		}()

		// One-way copy through the trPool buffer, matching transport() internals.
		buf := trPool.Get().([]byte)
		io.CopyBuffer(c2, c1, buf)
		trPool.Put(buf)

		c2.Close()
	}
}
