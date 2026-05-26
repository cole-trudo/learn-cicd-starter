package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "my-secret-key" {
		t.Errorf("expected key %q, got %q", "my-secret-key", got)
	}
}

func TestGetAPIKey_MissingHeader(t *testing.T) {
	headers := http.Header{}

	got, err := GetAPIKey(headers)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty key, got %q", got)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	tests := map[string]string{
		"wrong scheme":      "Bearer my-secret-key",
		"missing key part":  "ApiKey",
		"only whitespace":   " ",
		"empty after split": "",
	}

	for name, headerValue := range tests {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			if headerValue != "" {
				headers.Set("Authorization", headerValue)
			}

			got, err := GetAPIKey(headers)
			if err == nil {
				t.Errorf("expected an error, got nil (key=%q)", got)
			}
			if got != "" {
				t.Errorf("expected empty key, got %q", got)
			}
		})
	}
}
