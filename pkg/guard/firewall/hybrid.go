package firewall

import (
	"fmt"
	"strings"
)

// HybridBackend implements Backend by applying rules to multiple backends
// simultaneously. This is useful when the network topology is uncertain
// (e.g., Docker on host with reverse proxy).
type HybridBackend struct {
	backends []Backend
	name     string
}

// NewHybridBackend creates a backend that applies to all provided backends.
func NewHybridBackend(backends ...Backend) *HybridBackend {
	names := make([]string, len(backends))
	for i, b := range backends {
		names[i] = b.Name()
	}
	return &HybridBackend{
		backends: backends,
		name:     "hybrid:" + strings.Join(names, ","),
	}
}

func (h *HybridBackend) Name() string {
	return h.name
}

func (h *HybridBackend) EnsureChain() error {
	var errs []string
	for _, b := range h.backends {
		if err := b.EnsureChain(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", b.Name(), err))
		}
	}
	if len(errs) == len(h.backends) {
		return fmt.Errorf("all backends failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (h *HybridBackend) Block(ip string) error {
	var errs []string
	success := false
	for _, b := range h.backends {
		if err := b.Block(ip); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", b.Name(), err))
		} else {
			success = true
		}
	}
	if !success {
		return fmt.Errorf("all backends failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (h *HybridBackend) Unblock(ip string) error {
	var errs []string
	for _, b := range h.backends {
		if err := b.Unblock(ip); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", b.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("partial unblock failures: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (h *HybridBackend) ListBlocked() ([]string, error) {
	seen := make(map[string]bool)
	var ips []string
	for _, b := range h.backends {
		list, err := b.ListBlocked()
		if err != nil {
			continue
		}
		for _, ip := range list {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

func (h *HybridBackend) Validate() error {
	var errs []string
	for _, b := range h.backends {
		if err := b.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", b.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("validation issues: %s", strings.Join(errs, "; "))
	}
	return nil
}
