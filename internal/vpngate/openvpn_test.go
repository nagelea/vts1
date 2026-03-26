package vpngate

import "testing"

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
