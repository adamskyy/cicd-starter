package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantErr   bool
		wantErrIs error
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": {"ApiKey super-secret-key"}},
			wantKey: "super-secret-key",
		},
		{
			name:      "missing authorization header",
			headers:   http.Header{},
			wantErr:   true,
			wantErrIs: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "empty authorization header",
			headers:   http.Header{"Authorization": {""}},
			wantErr:   true,
			wantErrIs: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "missing scheme",
			headers: http.Header{"Authorization": {"super-secret-key"}},
			wantErr: true,
		},
		{
			name:    "wrong scheme",
			headers: http.Header{"Authorization": {"Bearer super-secret-key"}},
			wantErr: true,
		},
		{
			name:    "scheme is case sensitive",
			headers: http.Header{"Authorization": {"apikey super-secret-key"}},
			wantErr: true,
		},
		{
			name:    "missing key after scheme",
			headers: http.Header{"Authorization": {"ApiKey"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetAPIKey(tt.headers)

			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("GetAPIKey() error = %v, want errors.Is(_, %v)", err, tt.wantErrIs)
			}
			if tt.wantErr && err == nil {
				t.Fatal("GetAPIKey() error = nil, want non-nil error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("GetAPIKey() unexpected error = %v", err)
			}
			if got != tt.wantKey {
				t.Errorf("GetAPIKey() = %q, want %q", got, tt.wantKey)
			}
		})
	}
}

func TestGetAPIKeyFromRequest(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "ApiKey key-from-request")

	got, err := GetAPIKey(req.Header)
	if err != nil {
		t.Fatalf("GetAPIKey() unexpected error = %v", err)
	}
	if want := "key-from-request"; got != want {
		t.Errorf("GetAPIKey() = %q, want %q", got, want)
	}
}
