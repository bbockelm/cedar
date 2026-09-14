package security

import (
	"strings"
	"testing"
)

// TestAuthorizationErrorMessage pins what the message has to say in each case,
// because the whole value of the type is which configuration it sends an
// operator to look at.
func TestAuthorizationErrorMessage(t *testing.T) {
	cases := []struct {
		name string
		err  AuthorizationError
		want []string
		lack []string
	}{
		{
			name: "denied after authenticating",
			err: AuthorizationError{
				ReturnCode: "DENIED", Command: 71, Peer: "<10.0.0.1:9618>",
				User: "api@example.org", Method: "TOKEN",
				ValidCommands: "71,5,6",
			},
			want: []string{"command 71", "DENIED", "<10.0.0.1:9618>", `"api@example.org"`, "TOKEN"},
			// Naming the identity already says authentication succeeded, so
			// saying it again is noise; the session's command list must not
			// read as a grant either.
			lack: []string{"did not authenticate us", "71,5,6", "Authentication succeeded", "ALLOW_"},
		},
		{
			name: "denied without authenticating",
			err: AuthorizationError{
				ReturnCode: "DENIED", Command: 71,
				TriedAuthentication: false, TriedAuthKnown: true,
			},
			want: []string{"did not authenticate us"},
			// Saying authentication succeeded here would be a lie.
			lack: []string{"Authentication succeeded", "authenticated as"},
		},
		{
			name: "command not registered",
			err:  AuthorizationError{ReturnCode: "CMD_NOT_FOUND", Command: 74005, User: "api@example.org"},
			want: []string{"not registered", "74005"},
			// Not a refusal, so it must not be described as one.
			lack: []string{"DENIED", "refused"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("message is missing %q: %s", w, msg)
				}
			}
			for _, l := range tc.lack {
				if strings.Contains(msg, l) {
					t.Errorf("message should not contain %q: %s", l, msg)
				}
			}
			// "authentication failed" is what this type exists to stop the
			// client from reporting.
			if strings.Contains(strings.ToLower(msg), "authentication failed") {
				t.Errorf("message calls an authorization result an authentication failure: %s", msg)
			}
		})
	}
}
