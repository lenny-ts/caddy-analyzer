package analysis

import (
	"fmt"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func BenchmarkGrepCompileCached(b *testing.B) {
	for i := 0; i < b.N; i++ {
		grepCompile(fmt.Sprintf("/api/%d", i%compiledPatternCacheCap))
	}
}

func BenchmarkTouchIP(b *testing.B) {
	d := NewDetector()
	d.SetIPCap(b.N + 1)
	for i := 0; i < b.N; i++ {
		d.DetectAll(&types.LogEntry{RemoteIP: fmt.Sprintf("192.0.2.%d", i%256), URI: "/", Status: 200})
	}
}
