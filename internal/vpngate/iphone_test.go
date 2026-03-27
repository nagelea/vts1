package vpngate

import (
	"strings"
	"testing"
)

func TestParseIPhoneResponseAcceptsDashNumericField(t *testing.T) {
	payload := strings.Join([]string{
		"*vpn_servers",
		"#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64",
		"dash-ping,1.2.3.4,100,-,200,Japan,JP,1,10,5,1000,2weeks,Operator One,,ZHVtbXk=",
		"*",
	}, "\n")

	servers, err := parseIPhoneResponse([]byte(payload))
	if err != nil {
		t.Fatalf("parseIPhoneResponse() error = %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("parseIPhoneResponse() len = %d, want %d", len(servers), 1)
	}
	if servers[0].Ping != 0 {
		t.Fatalf("parseIPhoneResponse() ping = %d, want %d", servers[0].Ping, 0)
	}
}
