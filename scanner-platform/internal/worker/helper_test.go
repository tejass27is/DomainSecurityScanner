package worker

import (
	"testing"
)

func TestGetBackendBaseURLUsesConfiguredURL(t *testing.T) {
	t.Setenv("BACKEND_URL", "http://example.test:8000")

	url, err := getBackendBaseURL()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if url != "http://example.test:8000" {
		t.Fatalf("expected configured backend URL, got %q", url)
	}
}

func TestGetBackendBaseURLRemovesTrailingSlash(t *testing.T) {
	t.Setenv("BACKEND_URL", "http://localhost:8000/")

	url, err := getBackendBaseURL()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := "http://localhost:8000"

	if url != expected {
		t.Fatalf("expected %q, got %q", expected, url)
	}
}
func TestGetBackendBaseURLReturnsErrorWhenNotConfigured(t *testing.T) {
	t.Setenv("BACKEND_URL", "")

	url, err := getBackendBaseURL()

	if err == nil {
		t.Fatal("expected error when BACKEND_URL is not configured")
	}

	if url != "" {
		t.Fatalf("expected empty URL, got %q", url)
	}
}
