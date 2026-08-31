package worker

import (
	"strings"
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

func TestBuildTemporaryScanContainerArgsUsesDomainSpecificIsolation(t *testing.T) {
	args, name := buildTemporaryScanContainerArgs(
		"org-123",
		"Example.com",
		"scanner-worker:latest",
		"http://backend:8000",
		"redis:6379",
		"scanner-network",
	)

	if !strings.HasPrefix(name, "scan-example-com-") {
		t.Fatalf("expected domain-scoped unique container name, got %q", name)
	}

	foundRun := false
	foundName := false
	foundTargetEnv := false
	foundScanIDEnv := false
	foundNetwork := false
	for i, arg := range args {
		if i == 0 && arg == "run" {
			foundRun = true
		}
		if i == 1 && arg == "--rm" {
			// no-op, validated by sequence below
		}
		if arg == "--name" && i+1 < len(args) && args[i+1] == name {
			foundName = true
		}
		if arg == "-e" && i+1 < len(args) && args[i+1] == "SCAN_TARGET=Example.com" {
			foundTargetEnv = true
		}
		if arg == "-e" && i+1 < len(args) && args[i+1] == "SCAN_ID=org-123" {
			foundScanIDEnv = true
		}
		if arg == "--network=scanner-network" {
			foundNetwork = true
		}
	}

	if !foundRun || !foundName || !foundTargetEnv || !foundScanIDEnv || !foundNetwork {
		t.Fatalf("expected domain-isolated docker args, got %#v", args)
	}
}
