package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectedError error
	}{
		{
			name:          "valid API key",
			authHeader:    "ApiKey abc123xyz",
			expectedKey:   "abc123xyz",
			expectedError: nil,
		},
		{
			name:          "valid API key with special characters",
			authHeader:    "ApiKey sk_test_abc123-xyz_789",
			expectedKey:   "sk_test_abc123-xyz_789",
			expectedError: nil,
		},
		{
			name:          "missing authorization header",
			authHeader:    "",
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "wrong prefix - Bearer instead of ApiKey",
			authHeader:    "Bearer abc123xyz",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "lowercase apikey prefix",
			authHeader:    "apikey abc123xyz",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "only ApiKey prefix without key",
			authHeader:    "ApiKey",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "only the key without prefix",
			authHeader:    "abc123xyz",
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "API key with multiple spaces",
			authHeader:    "ApiKey abc123 xyz789",
			expectedKey:   "abc123",
			expectedError: nil,
		},
		{
			name:          "API key with trailing spaces",
			authHeader:    "ApiKey   abc123xyz",
			expectedKey:   "  abc123xyz",
			expectedError: nil,
		},
		{
			name:          "empty API key after prefix",
			authHeader:    "ApiKey ",
			expectedKey:   "",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			key, err := GetAPIKey(headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedError)
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
