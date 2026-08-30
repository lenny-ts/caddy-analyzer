package firewall

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
)

// BackendType represents the type of firewall backend.
type BackendType string

const (
	BackendAuto      BackendType = "auto"
	BackendIptables  BackendType = "iptables"
	BackendDocker    BackendType = "docker"
	BackendNftables  BackendType = "nftables"
	BackendHybrid    BackendType = "hybrid"
)

// Detect returns the appropriate Backend for the current environment.
// If forceType is not BackendAuto, it returns the requested backend directly.
func Detect(forceType BackendType) Backend {
	switch forceType {
	case BackendIptables:
		return NewIptablesBackend("iptables", "INPUT")
	case BackendDocker:
		return NewDockerBackend("iptables")
	case BackendNftables:
		return NewNftablesBackend("ip")
	case BackendHybrid:
		return newHybridAuto()
	default:
		return autoDetect()
	}
}

// autoDetect intelligently selects the best firewall backend.
//
// Strategy:
//  1. If Docker is running AND has Caddy containers → hybrid (INPUT + DOCKER-USER)
//  2. If Docker is running but no Caddy containers → iptables INPUT
//  3. If nftables backend → nftables
//  4. Default → iptables INPUT
//
// The hybrid approach is preferred when Docker is present because it covers
// both bare-metal and containerised Caddy without user intervention.
func autoDetect() Backend {
	if isDockerRunning() {
		if hasCaddyContainers() {
			// Docker running with Caddy containers → apply to both chains.
			// This covers bridge networking (DOCKER-USER) and host networking (INPUT).
			return newHybridAuto()
		}
		// Docker running but Caddy is bare metal → use INPUT.
		return NewIptablesBackend("iptables", "INPUT")
	}

	// No Docker — check for nftables.
	if isNftablesBackend() {
		return NewNftablesBackend("ip")
	}

	// Default: iptables with INPUT chain.
	return NewIptablesBackend("iptables", "INPUT")
}

// newHybridAuto creates a hybrid backend that applies to both INPUT and DOCKER-USER.
func newHybridAuto() Backend {
	input := NewIptablesBackend("iptables", "INPUT")
	docker := NewDockerBackend("iptables")
	return NewHybridBackend(input, docker)
}

// isDockerRunning checks if the Docker daemon is accessible.
func isDockerRunning() bool {
	// Check for Docker socket.
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return true
	}
	// Check for docker0 network interface.
	if _, err := os.Stat("/sys/class/net/docker0"); err == nil {
		return true
	}
	return false
}

// hasCaddyContainers checks if there are any running Caddy containers.
// This is the key difference from the old approach: we check for Caddy
// specifically, not whether the guard process itself is in Docker.
func hasCaddyContainers() bool {
	// Check for running containers with "caddy" in the name/image.
	out, err := exec.Command("docker", "ps", "--format", "{{.Names}} {{.Image}}").Output()
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.ToLower(scanner.Text())
		if strings.Contains(line, "caddy") {
			return true
		}
	}
	return false
}

// isNftablesBackend checks if iptables is using the nftables backend.
func isNftablesBackend() bool {
	if _, err := os.Stat("/usr/sbin/iptables-nft"); err == nil {
		return true
	}
	return false
}

// DetectForIP returns the appropriate Backend for a specific IP address.
func DetectForIP(ip string, forceType BackendType) Backend {
	if forceType != BackendAuto {
		return Detect(forceType)
	}
	return autoDetect()
}
