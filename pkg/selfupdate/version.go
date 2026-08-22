// Package selfupdate implements the `update` subcommand: it downloads a
// release archive from GitHub, verifies it with cosign (fail closed) and a
// SHA256 checksum, and atomically replaces the running binary.
//
// The verification chain mirrors what .github/workflows/release.yml
// produces: GoReleaser emits checksums.txt with SHA256 sums of every
// artifact, then cosign keylessly signs checksums.txt and uploads
// checksums.txt.pem + checksums.txt.sig alongside the release. Verifying
// the signed manifest and matching the archive hash against it is
// therefore equivalent to verifying the archive itself.
package selfupdate

import (
	"strconv"
	"strings"
)

// CompareVersions compares two semantic-ish version strings and returns
// -1, 0, or 1. It tolerates a leading "v"/"V", ignores build metadata,
// and ranks pre-release / dev suffixes below the same core version
// ("0.5.0-dev" < "0.5.0"), mirroring SemVer precedence. Unparsable input
// sorts lowest so an unknown running version always looks outdated.
func CompareVersions(a, b string) int {
	pa, okA := parseVersion(a)
	pb, okB := parseVersion(b)

	if !okA && !okB {
		return 0
	}
	if !okA {
		return -1
	}
	if !okB {
		return 1
	}
	for i := 0; i < 3; i++ {
		if pa.core[i] != pb.core[i] {
			if pa.core[i] < pb.core[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case pa.pre == pb.pre:
		return 0
	case pa.pre == "":
		return 1 // release beats pre-release/dev at same core
	case pb.pre == "":
		return -1
	}
	return strings.Compare(pa.pre, pb.pre)
}

type parsedVersion struct {
	core [3]int
	pre  string
}

// parseVersion extracts MAJOR.MINOR.PATCH plus any pre-release suffix
// from inputs like "v0.5.0", "0.5.0-dev", "0.4.1". Returns ok=false when
// no numeric core can be recovered ("dev", "", "garbage").
func parseVersion(v string) (parsedVersion, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	// Strip build metadata and isolate the pre-release suffix.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var pre string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) == 0 || parts[0] == "" {
		return parsedVersion{}, false
	}
	var out parsedVersion
	out.pre = pre
	for i := 0; i < 3; i++ {
		if i >= len(parts) {
			break
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return parsedVersion{}, false
		}
		out.core[i] = n
	}
	return out, true
}

// NormalizeVersion renders a version for display: unknown or dev builds
// become "dev" instead of a misleading number.
func NormalizeVersion(v string) string {
	if _, ok := parseVersion(v); !ok {
		return "dev"
	}
	return v
}

// SameRelease reports whether the running version equals the target
// release tag (e.g. Version "0.5.0" vs tag "v0.5.0").
func SameRelease(current, tag string) bool {
	return CompareVersions(current, tag) == 0
}
