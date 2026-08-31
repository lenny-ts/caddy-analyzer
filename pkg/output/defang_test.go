package output

import "testing"

func TestDefang(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"185.220.101.42", "185[.]220[.]101[.]42"},
		{"https://evil.com", "hxxps://evil[.]com"},
		{"http://169.254.169.254/", "hxxp://169[.]254[.]169[.]254/"},
		{"http://evil.com/path?q=1.2.3", "hxxp://evil[.]com/path?q=1.2.3"},
		{"192.168.1.1:8080", "192[.]168[.]1[.]1:8080"},
		{"Caddy/2.7.4", "Caddy/2.7.4"},
		{"/api/v2.1/users", "/api/v2.1/users"},
		{"evil.com", "evil.com"},
		{"2001:db8::1", "2001:db8::1"},
		{"", ""},
		{"no-dots-here", "no-dots-here"},
	}
	for _, tt := range tests {
		if got := Defang(tt.in); got != tt.want {
			t.Errorf("Defang(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDefangIPv4Validation(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"lowest valid address", "0.0.0.0", "0[.]0[.]0[.]0"},
		{"highest valid address", "255.255.255.255", "255[.]255[.]255[.]255"},
		{"octets above 255", "999.999.999.999", "999.999.999.999"},
		{"last octet above 255", "192.168.1.256", "192.168.1.256"},
		{"octets with leading zeroes", "010.000.015.001", "010.000.015.001"},
		{"five component dotted sequence", "1.2.3.4.5", "1.2.3.4.5"},
		{"version prefix", "v1.2.3.4", "v1.2.3.4"},
		{"version suffix", "1.2.3.4beta", "1.2.3.4beta"},
		{"version in URL path", "https://example.com/releases/1.2.3.4.5", "hxxps://example[.]com/releases/1.2.3.4.5"},
		{"valid address in URL with port and path", "http://192.0.2.1:8080/admin", "hxxp://192[.]0[.]2[.]1:8080/admin"},
		{"invalid address in URL", "http://999.999.999.999/path", "hxxp://999.999.999.999/path"},
		{"valid addresses next to punctuation", "client=(192.0.2.1); upstream=198.51.100.255:443", "client=(192[.]0[.]2[.]1); upstream=198[.]51[.]100[.]255:443"},
		{"invalid candidate followed by valid address", "invalid=999.999.999.999, valid=203.0.113.5", "invalid=999.999.999.999, valid=203[.]0[.]113[.]5"},
		{"address before sentence punctuation", "Observed 192.0.2.1.", "Observed 192[.]0[.]2[.]1."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Defang(tt.in); got != tt.want {
				t.Errorf("Defang(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDefangIP(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"10.0.0.1", "10[.]0[.]0[.]1"},
		{"2001:db8::1", "2001:db8::1"},
	}
	for _, tt := range tests {
		if got := DefangIP(tt.in); got != tt.want {
			t.Errorf("DefangIP(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
