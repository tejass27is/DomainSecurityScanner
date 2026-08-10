package worker

import (
	"os"
	"testing"
)

func TestBackendURLsUsesConfiguredURLFirst(t *testing.T) {
	t.Setenv("BACKEND_URL", "http://example.test:8000")

	urls := getBackendURLs()
	if len(urls) == 0 || urls[0] != "http://example.test:8000" {
		t.Fatalf("expected configured backend URL first, got %v", urls)
	}
}

func TestBackendURLsFallbacksIncludeLocalHosts(t *testing.T) {
	t.Setenv("BACKEND_URL", "")

	urls := getBackendURLs()
	if len(urls) < 3 {
		t.Fatalf("expected fallback backend URLs, got %v", urls)
	}

	seen := map[string]bool{}
	for _, u := range urls {
		seen[u] = true
	}

	for _, expected := range []string{"http://scanner-backend:8000", "http://localhost:8000", "http://127.0.0.1:8000"} {
		if !seen[expected] {
			t.Fatalf("expected fallback URL %s in %v", expected, urls)
		}
	}

	_ = os.Getenv("BACKEND_URL")
}
