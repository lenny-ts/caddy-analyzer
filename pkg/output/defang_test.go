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
