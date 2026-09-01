package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lenny-ts/caddy-analyzer/pkg/enrich"
	"github.com/lenny-ts/caddy-analyzer/pkg/types"
)

func TestValidateFlags(t *testing.T) {
	tests := []struct {
		name        string
		watch       bool
		follow      bool
		interval    string
		noBots      bool
		botsOnly    bool
		format      string
		wantErr     bool
		errContains string
	}{
		{name: "all defaults", format: "table"},
		{name: "watch and follow conflict", watch: true, follow: true, format: "table", wantErr: true, errContains: "mutually exclusive"},
		{name: "watch and interval conflict", watch: true, interval: "5m", format: "table", wantErr: true, errContains: "mutually exclusive"},
		{name: "follow and interval conflict", follow: true, interval: "5m", format: "table", wantErr: true, errContains: "mutually exclusive"},
		{name: "no-bots and bots-only conflict", noBots: true, botsOnly: true, format: "table", wantErr: true, errContains: "mutually exclusive"},
		{name: "unsupported format", format: "xml", wantErr: true, errContains: "unsupported --format"},
		{name: "json format ok", format: "json"},
		{name: "csv format ok", format: "csv"},
		{name: "html format ok", format: "html"},
		{name: "elasticsearch format ok", format: "elasticsearch"},
		{name: "loki requires endpoint", format: "loki", wantErr: true, errContains: "--remote-url"},
		{name: "uppercase format ok", format: "TABLE"},
	}

	orig := func() (bool, bool, string, bool, bool, string, string) {
		return flagWatch, flagFollow, flagInterval, flagNoBots, flagBotsOnly, flagFormat, flagRemoteURL
	}
	ow, of, oi, onb, obo, ofmt, ourl := orig()
	defer func() {
		flagWatch, flagFollow, flagInterval, flagNoBots, flagBotsOnly, flagFormat, flagRemoteURL = ow, of, oi, onb, obo, ofmt, ourl
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flagWatch, flagFollow, flagInterval = tt.watch, tt.follow, tt.interval
			flagNoBots, flagBotsOnly, flagFormat = tt.noBots, tt.botsOnly, tt.format
			flagRemoteURL = ""
			if tt.format == "elasticsearch" {
				flagRemoteURL = "http://localhost:9200"
			}

			err := validateFlags()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error containing %q, got %v", tt.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestBuildFiltersFromToValidation(t *testing.T) {
	origFrom, origTo := flagFrom, flagTo
	defer func() { flagFrom, flagTo = origFrom, origTo }()

	flagFrom = "2025-01-02T00:00:00Z"
	flagTo = "2025-01-01T00:00:00Z"
	if _, err := buildFilters(); err == nil {
		t.Fatal("expected error when --from is later than --to")
	}

	flagFrom = "2025-01-01T00:00:00Z"
	flagTo = "2025-01-02T00:00:00Z"
	if _, err := buildFilters(); err != nil {
		t.Fatalf("expected no error for valid range, got %v", err)
	}
}

func TestSubcommandPersistentFlagMergeNoPanic(t *testing.T) {
	subs := []string{"tail", "top", "diff", "config", "guard", "block", "unban"}
	for _, s := range subs {
		sub, _, err := rootCmd.Find([]string{s})
		if err != nil {
			t.Fatalf("%s: Find failed: %v", s, err)
		}
		if sub == nil || sub.Name() != s {
			t.Fatalf("%s: expected subcommand, got %v", s, sub)
		}
	}
}

func TestConfigNamespaceFlagParsing(t *testing.T) {
	sub, args, err := rootCmd.Find([]string{"config", "k8s://test-pod", "-n", "production", "show"})
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}
	if sub == nil || sub.Name() != "config" {
		t.Fatalf("expected config subcommand, got %v (args %v)", sub, args)
	}
	if err := sub.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if got := sub.Flag("namespace").Value.String(); got != "production" {
		t.Fatalf("expected namespace=production, got %q", got)
	}
}

func TestSubcommandInheritsPersistentFlags(t *testing.T) {
	for _, s := range []string{"top", "diff", "tail"} {
		sub, _, err := rootCmd.Find([]string{s, "--format", "json", "--output", "x.json", "--top", "5"})
		if err != nil {
			t.Fatalf("%s: Find failed: %v", s, err)
		}
		if f := sub.Flag("format"); f == nil {
			t.Fatalf("%s: expected inherited --format flag", s)
		}
		if f := sub.Flag("output"); f == nil {
			t.Fatalf("%s: expected inherited --output flag", s)
		}
		if f := sub.Flag("top"); f == nil {
			t.Fatalf("%s: expected inherited --top flag", s)
		}
	}
}

func TestSharedFlagsParsing(t *testing.T) {
	sub, args, err := rootCmd.Find([]string{"diff", "--from", "2025-01-01T00:00:00Z", "--to", "2025-01-02T00:00:00Z", "-c"})
	if err != nil {
		t.Fatalf("Find failed: %v", err)
	}
	if err := sub.ParseFlags(args); err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if f := sub.Flag("compact"); f == nil || f.Value.String() != "true" {
		t.Fatalf("expected compact=true, got %v", f)
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		in   string
		want int64
		err  bool
	}{
		{"512", 512, false},
		{"1kb", 1 << 10, false},
		{"1KB", 1 << 10, false},
		{"1mb", 1 << 20, false},
		{"2gb", 2 << 30, false},
		{"1k", 1 << 10, false},
		{"2m", 2 << 20, false},
		{"3g", 3 << 30, false},
		{"", 0, true},
		{"abc", 0, true},
		{"-1kb", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseSize(tt.in)
			if tt.err {
				if err == nil {
					t.Fatalf("expected error for %q, got %d", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseSize(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildFiltersSizeAndLatency(t *testing.T) {
	origSlow, origMaxLat, origMin, origMax := flagSlow, flagMaxLatency, flagMinSize, flagMaxSize
	defer func() { flagSlow, flagMaxLatency, flagMinSize, flagMaxSize = origSlow, origMaxLat, origMin, origMax }()

	// Valid: min-size + max-size + max-latency wired through.
	flagSlow = "100ms"
	flagMaxLatency = "1s"
	flagMinSize = "1kb"
	flagMaxSize = "1mb"
	f, err := buildFilters()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if f.MinSize != 1<<10 {
		t.Errorf("MinSize = %d, want %d", f.MinSize, 1<<10)
	}
	if f.MaxSize != 1<<20 {
		t.Errorf("MaxSize = %d, want %d", f.MaxSize, 1<<20)
	}
	if f.MinLatency <= 0 || f.MaxLatency <= 0 {
		t.Errorf("latency not set: min=%v max=%v", f.MinLatency, f.MaxLatency)
	}
	if f.MinLatency > f.MaxLatency {
		t.Errorf("min latency %v > max latency %v", f.MinLatency, f.MaxLatency)
	}

	// min-size > max-size must error.
	flagSlow, flagMaxLatency = "", ""
	flagMinSize = "2mb"
	flagMaxSize = "1mb"
	if _, err := buildFilters(); err == nil {
		t.Fatal("expected error when --min-size > --max-size")
	}

	// slow > max-latency must error.
	flagMinSize, flagMaxSize = "", ""
	flagSlow = "2s"
	flagMaxLatency = "1s"
	if _, err := buildFilters(); err == nil {
		t.Fatal("expected error when --slow > --max-latency")
	}

	// Bad size must error.
	flagSlow, flagMaxLatency = "", ""
	flagMinSize = "not-a-size"
	if _, err := buildFilters(); err == nil {
		t.Fatal("expected error for invalid --min-size")
	}
}

func TestBuildFiltersHost(t *testing.T) {
	origHost := flagHost
	defer func() { flagHost = origHost }()

	flagHost = "api.example.com"
	f, err := buildFilters()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Host != "api.example.com" {
		t.Errorf("Host = %q, want api.example.com", f.Host)
	}
}

func TestHelpTextCategoryCount(t *testing.T) {
	if !strings.Contains(rootCmd.Long, "26 attack categories") {
		t.Errorf("root help: expected '26 attack categories', got Long=%q", rootCmd.Long)
	}
	if strings.Contains(rootCmd.Long, "22 attack categories") || strings.Contains(rootCmd.Long, "23 attack categories") {
		t.Errorf("root help: still says old category count")
	}
	if !strings.Contains(guardCmd.Long, "26 categories") {
		t.Errorf("guard help: expected '26 categories', got Long=%q", guardCmd.Long)
	}
	if strings.Contains(guardCmd.Long, "22 categories") || strings.Contains(guardCmd.Long, "23 categories") {
		t.Errorf("guard help: still says old category count")
	}
}

func TestBuildFiltersCountryASN(t *testing.T) {
	origIP, origCountry, origExCty, origASN, origExASN, origGeoDB, origNoAutoDL :=
		flagExcludeIP, flagCountry, flagExcludeCountry, flagASN, flagExcludeASN, flagGeoIPDB, flagNoAutoDL
	defer func() {
		flagExcludeIP, flagCountry, flagExcludeCountry, flagASN, flagExcludeASN, flagGeoIPDB, flagNoAutoDL =
			origIP, origCountry, origExCty, origASN, origExASN, origGeoDB, origNoAutoDL
	}()

	// Existing dummy db so geo-requiring cases pass validation on any machine.
	validDB := filepath.Join(t.TempDir(), "GeoIP.mmdb")
	if err := os.WriteFile(validDB, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		country     []string
		excludeCty  []string
		asn         []int
		excludeASN  []int
		geoDB       string
		wantErr     bool
		errContains string
		check       func(t *testing.T, f types.Filters)
	}{
		{
			name:    "lowercase countries normalized",
			country: []string{"it", "Us"},
			geoDB:   validDB,
			check: func(t *testing.T, f types.Filters) {
				t.Helper()
				if len(f.Country) != 2 || f.Country[0] != "IT" || f.Country[1] != "US" {
					t.Fatalf("Country = %v, want [IT US]", f.Country)
				}
			},
		},
		{
			name:  "asn parsed",
			asn:   []int{12345, 67890},
			geoDB: validDB,
			check: func(t *testing.T, f types.Filters) {
				t.Helper()
				if len(f.ASN) != 2 || f.ASN[0] != 12345 || f.ASN[1] != 67890 {
					t.Fatalf("ASN = %v, want [12345 67890]", f.ASN)
				}
			},
		},
		{
			name:        "country pair mutually exclusive",
			country:     []string{"IT"},
			excludeCty:  []string{"US"},
			wantErr:     true,
			errContains: "--country and --exclude-country are mutually exclusive",
		},
		{
			name:        "asn pair mutually exclusive",
			asn:         []int{12345},
			excludeASN:  []int{67890},
			wantErr:     true,
			errContains: "--asn and --exclude-asn are mutually exclusive",
		},
		{
			name:        "invalid country code rejected",
			country:     []string{"ITA"},
			geoDB:       validDB,
			wantErr:     true,
			errContains: "invalid --country",
		},
		{
			name:        "non-numeric country code rejected",
			excludeCty:  []string{"U1"},
			geoDB:       validDB,
			wantErr:     true,
			errContains: "invalid --exclude-country",
		},
		{
			name:        "zero asn rejected",
			asn:         []int{0},
			wantErr:     true,
			errContains: "invalid --asn",
		},
		{
			name:        "negative exclude-asn rejected",
			excludeASN:  []int{-1},
			wantErr:     true,
			errContains: "invalid --exclude-asn",
		},
		{
			name:       "cross dimensions allowed",
			country:    []string{"IT"},
			excludeASN: []int{12345},
			geoDB:      validDB,
			check: func(t *testing.T, f types.Filters) {
				t.Helper()
				if len(f.Country) != 1 || f.Country[0] != "IT" || len(f.ExcludeASN) != 1 || f.ExcludeASN[0] != 12345 {
					t.Fatalf("filters = %+v, want country IT + exclude-asn 12345", f)
				}
			},
		},
		{
			name:        "missing explicit geoip db fails fast",
			country:     []string{"IT"},
			geoDB:       "/nonexistent/deterministic.mmdb",
			wantErr:     true,
			errContains: "require GeoIP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flagExcludeIP, flagCountry, flagExcludeCountry = "", tt.country, tt.excludeCty
			flagASN, flagExcludeASN = tt.asn, tt.excludeASN
			flagGeoIPDB, flagNoAutoDL = tt.geoDB, true

			f, err := buildFilters()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error containing %q, got %v", tt.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tt.check != nil {
				tt.check(t, f)
			}
		})
	}
}

func TestBuildFiltersCountryName(t *testing.T) {
	origCountry, origGeoDB, origNoAutoDL :=
		flagCountry, flagGeoIPDB, flagNoAutoDL
	defer func() {
		flagCountry, flagGeoIPDB, flagNoAutoDL =
			origCountry, origGeoDB, origNoAutoDL
	}()

	dbPath := enrich.FindDB("")
	if dbPath == "" {
		t.Skip("no GeoIP mmdb found on this machine")
	}

	tests := []struct {
		name    string
		country []string
		check   func(t *testing.T, f types.Filters)
	}{
		{
			name:    "italy resolves to IT",
			country: []string{"Italy"},
			check: func(t *testing.T, f types.Filters) {
				t.Helper()
				if len(f.Country) != 1 || f.Country[0] != "IT" {
					t.Fatalf("Country = %v, want [IT]", f.Country)
				}
			},
		},
		{
			name:    "united states resolves to US",
			country: []string{"united states"},
			check: func(t *testing.T, f types.Filters) {
				t.Helper()
				if len(f.Country) != 1 || f.Country[0] != "US" {
					t.Fatalf("Country = %v, want [US]", f.Country)
				}
			},
		},
		{
			name:    "mixed code and name",
			country: []string{"it", "France"},
			check: func(t *testing.T, f types.Filters) {
				t.Helper()
				if len(f.Country) != 2 || f.Country[0] != "IT" || f.Country[1] != "FR" {
					t.Fatalf("Country = %v, want [IT FR]", f.Country)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flagCountry = tt.country
			flagGeoIPDB = dbPath
			flagNoAutoDL = false

			f, err := buildFilters()
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if tt.check != nil {
				tt.check(t, f)
			}
		})
	}
}
