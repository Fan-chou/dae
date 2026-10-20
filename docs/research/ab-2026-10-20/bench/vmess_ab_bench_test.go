package vmess

import (
	"testing"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func BenchmarkReqInstructionDataFromPool(b *testing.B) {
	md := Metadata{
		Metadata: protocol.Metadata{Type: protocol.MetadataTypeDomain, Hostname: "www.example.com", Port: 443, Cipher: "aes-128-gcm", IsClient: true},
		Network:  "tcp",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := ReqInstructionDataFromPool(md)
		pool.Put(buf)
	}
}
