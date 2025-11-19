package security

import (
	"errors"
	"testing"
)

// TestSessionResumptionError tests the SessionResumptionError type
func TestSessionResumptionError(t *testing.T) {
	err := &SessionResumptionError{
		SessionID: "test-session-123",
		Reason:    "session not found on server",
	}

	expected := "session resumption failed for session test-session-123: session not found on server"
	if err.Error() != expected {
		t.Errorf("Expected error message %q, got %q", expected, err.Error())
	}
}

// TestIsSessionResumptionError tests the IsSessionResumptionError helper function
func TestIsSessionResumptionError(t *testing.T) {
	t.Run("is_session_resumption_error", func(t *testing.T) {
		err := &SessionResumptionError{
			SessionID: "test-session-123",
			Reason:    "session not found on server",
		}

		if !IsSessionResumptionError(err) {
			t.Error("Expected IsSessionResumptionError to return true for SessionResumptionError")
		}

		// Test with errors.As
		var sre *SessionResumptionError
		if !errors.As(err, &sre) {
			t.Error("Expected errors.As to work with SessionResumptionError")
		}
		if sre.SessionID != "test-session-123" {
			t.Errorf("Expected SessionID 'test-session-123', got %q", sre.SessionID)
		}
	})

	t.Run("not_session_resumption_error", func(t *testing.T) {
		err := errors.New("some other error")

		if IsSessionResumptionError(err) {
			t.Error("Expected IsSessionResumptionError to return false for non-SessionResumptionError")
		}
	})

	t.Run("wrapped_session_resumption_error", func(t *testing.T) {
		originalErr := &SessionResumptionError{
			SessionID: "test-session-456",
			Reason:    "connection timeout",
		}
		wrappedErr := errors.New("wrapped: " + originalErr.Error())

		// This should NOT detect the error since it's only string-wrapped, not error-wrapped
		if IsSessionResumptionError(wrappedErr) {
			t.Error("Expected IsSessionResumptionError to return false for string-wrapped error")
		}

		// But with proper error wrapping using %w, it should work
		properlyWrapped := errors.Join(errors.New("wrapper"), originalErr)
		if !IsSessionResumptionError(properlyWrapped) {
			t.Error("Expected IsSessionResumptionError to return true for properly wrapped error")
		}
	})
}
