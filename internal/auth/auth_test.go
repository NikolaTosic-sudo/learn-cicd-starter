package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantKey string
		wantErr error
	}{
		{
			name:    "valid header",
			header:  "ApiKey my-secret-key",
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "missing header",
			header:  "",
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "wrong prefix",
			header:  "Bearer my-secret-key",
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "missing key",
			header:  "ApiKey",
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "extra spaces",
			header:  "ApiKey    my-secret-key",
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}
			gotKey, err := GetAPIKey(headers)
			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}
			if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
				t.Errorf("got err %v, want %v", err, tt.wantErr)
			} else if err != nil && tt.wantErr != nil && err.Error() != tt.wantErr.Error() {
				t.Errorf("got err %v, want %v", err, tt.wantErr)
			}
		})
	}
}
