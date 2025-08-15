package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		want       string
		wantErr    error
		wantErrMsg string
	} {
		{
			name:    "ok - ApiKey scheme with token",
			headers: http.Header{"Authorization": []string{"ApiKey abc123"},},
			want:    "abc123",
		},
				{
			name:    "error - no Authorization header present",
			headers: http.Header{}, 
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "error - empty Authorization header value",
			headers:    http.Header{"Authorization": []string{""}},
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "error - wrong scheme (Bearer)",
			headers:    http.Header{"Authorization": []string{"Bearer abc123"}},
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "error - missing space between scheme and token",
			headers:    http.Header{"Authorization": []string{"ApiKeyabc123"}},
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "error - wrong case in scheme",
			headers:    http.Header{"Authorization": []string{"apikey abc123"}},
			wantErrMsg: "malformed authorization header",
		},
	}
	
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetAPIKey(tt.headers)

			if tt.wantErr != nil || tt.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("GetAPIKey() error = nil, want non-nil")
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Fatalf("GetAPIKey() error = %v, want errors.Is(%v)", err, tt.wantErr)
				}
				if tt.wantErrMsg != "" && err.Error() != tt.wantErrMsg {
					t.Fatalf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("GetAPIKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
