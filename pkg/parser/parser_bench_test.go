package parser

import (
	"testing"
)

const benchHTTPLine = `{"level":"info","ts":1700000000.123,"logger":"http.log.access","msg":"handled request","request":{"method":"GET","uri":"/index.html","host":"example.com","remote_addr":"1.2.3.4:5678","remote_ip":"1.2.3.4","proto":"HTTP/2.0","headers":{"User-Agent":["curl/8.0"],"Referer":["https://ref.example.com"]}},"status":200,"size":1024,"duration":0.005,"resp_headers":{"Content-Type":["text/html"]}}`

const benchOperationalLine = `{"level":"error","ts":1700000000.789,"logger":"http","msg":"dialing upstream","upstream":"10.0.0.5:8080","error":"context deadline exceeded","config_file":"/etc/caddy/Caddyfile"}`

func BenchmarkParseHTTP(b *testing.B) {
	b.SetBytes(int64(len(benchHTTPLine)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Parse(benchHTTPLine)
	}
}

func BenchmarkParseOperational(b *testing.B) {
	b.SetBytes(int64(len(benchOperationalLine)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Parse(benchOperationalLine)
	}
}
