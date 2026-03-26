package runner

import "testing"

func TestShouldMarkConnectFailure(t *testing.T) {
	tests := []struct {
		name                    string
		waitErr                 bool
		timedOutBeforeHandshake bool
		handshakeSeen           bool
		abortTriggered          bool
		want                    bool
	}{
		{name: "process error", waitErr: true, want: true},
		{name: "timeout before handshake", timedOutBeforeHandshake: true, want: true},
		{name: "aborted before handshake", abortTriggered: true, want: true},
		{name: "ignore abort after handshake", handshakeSeen: true, abortTriggered: true, want: false},
		{name: "clean exit", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.waitErr {
				err = testConnectError("connect failed")
			}

			if got := shouldMarkConnectFailure(err, tt.timedOutBeforeHandshake, tt.handshakeSeen, tt.abortTriggered); got != tt.want {
				t.Fatalf("shouldMarkConnectFailure() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testConnectError string

func (e testConnectError) Error() string {
	return string(e)
}
