package vpngate

import (
	"errors"
	"slices"
	"testing"
)

func TestSummarizeOpenVPNFailurePrefersSpecificCause(t *testing.T) {
	lines := []string{
		"2026-03-26 14:19:24 TCP: connect to [AF_INET]180.181.193.197:1250 failed: Host is unreachable",
		"2026-03-26 14:19:24 SIGUSR1[connection failed(soft),connection-failed] received, process restarting",
		"2026-03-26 14:19:25 Exiting due to fatal error",
	}

	if got := SummarizeOpenVPNFailure(lines); got != "目标节点不可达" {
		t.Fatalf("SummarizeOpenVPNFailure() = %q, want %q", got, "目标节点不可达")
	}
}

func TestBuildOpenVPNConnectArgsIncludesLegacyCipherInDataCiphers(t *testing.T) {
	args := BuildOpenVPNConnectArgs("/tmp/test.ovpn", "AES-128-CBC")

	index := slices.Index(args, "--data-ciphers")
	if index < 0 || index+1 >= len(args) {
		t.Fatal("BuildOpenVPNConnectArgs() missing --data-ciphers")
	}
	if got := args[index+1]; got != "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC" {
		t.Fatalf("BuildOpenVPNConnectArgs() data ciphers = %q, want %q", got, "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC")
	}
}

func TestDetectRemoteEndpointAndProtocol(t *testing.T) {
	config := `
client
proto tcp
remote 203.0.113.10 443
cipher AES-128-CBC
`

	if got := detectRemoteProtocol(config); got != "tcp" {
		t.Fatalf("detectRemoteProtocol() = %q, want %q", got, "tcp")
	}

	host, port := detectRemoteEndpoint(config)
	if host != "203.0.113.10" || port != "443" {
		t.Fatalf("detectRemoteEndpoint() = (%q, %q), want (%q, %q)", host, port, "203.0.113.10", "443")
	}
}

func TestShouldRunTCPPrecheck(t *testing.T) {
	if !shouldRunTCPPrecheck(OpenVPNLaunch{Protocol: "tcp", RemoteHost: "203.0.113.10", RemotePort: "443"}) {
		t.Fatal("shouldRunTCPPrecheck() = false, want true")
	}
	if shouldRunTCPPrecheck(OpenVPNLaunch{Protocol: "udp", RemoteHost: "203.0.113.10", RemotePort: "443"}) {
		t.Fatal("shouldRunTCPPrecheck() = true, want false for udp")
	}
}

func TestSummarizeTCPPrecheckError(t *testing.T) {
	if got := summarizeTCPPrecheckError(errors.New("connect: host is unreachable")); got != "目标节点不可达" {
		t.Fatalf("summarizeTCPPrecheckError() = %q, want %q", got, "目标节点不可达")
	}
	if got := summarizeTCPPrecheckError(errors.New("connect: connection refused")); got != "目标节点拒绝连接" {
		t.Fatalf("summarizeTCPPrecheckError() = %q, want %q", got, "目标节点拒绝连接")
	}
}
