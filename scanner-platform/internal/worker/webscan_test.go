package worker

import "testing"

func TestNormalizeAcunetixStatus(t *testing.T) {
	cases := map[string]string{
		"completed":  "completed",
		"Complete":   "completed",
		"processing": "running",
		"queued":     "running",
		"failed":     "failed",
		"aborted":    "aborted",
		"":           "running",
		"weird":      "running",
	}

	for input, expected := range cases {
		if got := normalizeAcunetixStatus(input); got != expected {
			t.Fatalf("normalizeAcunetixStatus(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestResolveAcunetixBaseURLAcceptsBareConsoleAddress(t *testing.T) {
	t.Setenv("ACUNETIX_URL", "https://acunetix.example.com:3443")
	t.Setenv("ACUNETIX_BASE_URL", "")

	if got := resolveAcunetixBaseURL(); got != "https://acunetix.example.com:3443/api/v1" {
		t.Fatalf("resolveAcunetixBaseURL() = %q, want https://acunetix.example.com:3443/api/v1", got)
	}
}

func TestResolveAcunetixBaseURLNormalizesVariants(t *testing.T) {
	cases := map[string]string{
		"https://acunetix.example.com:3443/":            "https://acunetix.example.com:3443/api/v1",
		"https://acunetix.example.com:3443/api/v1":      "https://acunetix.example.com:3443/api/v1",
		"https://acunetix.example.com:3443/api/v1/":     "https://acunetix.example.com:3443/api/v1",
		"https://acunetix.example.com:3443/api":         "https://acunetix.example.com:3443/api/v1",
		"https://acunetix.example.com:3443/#/dashboard": "https://acunetix.example.com:3443/api/v1",
		"acunetix.example.com:3443":                     "https://acunetix.example.com:3443/api/v1",
		"  https://acunetix.example.com:3443  ":         "https://acunetix.example.com:3443/api/v1",
		// A sub-path installation is preserved.
		"https://host.example.com/acunetix/api/v1": "https://host.example.com/acunetix/api/v1",
	}

	for input, expected := range cases {
		t.Setenv("ACUNETIX_URL", input)
		if got := resolveAcunetixBaseURL(); got != expected {
			t.Errorf("resolveAcunetixBaseURL() with ACUNETIX_URL=%q = %q, want %q", input, got, expected)
		}
	}
}

func TestResolveAcunetixBaseURLPrefersURLOverAlias(t *testing.T) {
	t.Setenv("ACUNETIX_URL", "https://primary:3443")
	t.Setenv("ACUNETIX_BASE_URL", "https://legacy:3443")

	if got := resolveAcunetixBaseURL(); got != "https://primary:3443/api/v1" {
		t.Fatalf("resolveAcunetixBaseURL() = %q, want the ACUNETIX_URL value", got)
	}
}

func TestResolveAcunetixBaseURLFallsBackToAlias(t *testing.T) {
	t.Setenv("ACUNETIX_URL", "")
	t.Setenv("ACUNETIX_BASE_URL", "https://legacy:3443")

	if got := resolveAcunetixBaseURL(); got != "https://legacy:3443/api/v1" {
		t.Fatalf("resolveAcunetixBaseURL() = %q, want https://legacy:3443/api/v1", got)
	}
}

func TestResolveAcunetixBaseURLEmptyWhenUnconfigured(t *testing.T) {
	t.Setenv("ACUNETIX_URL", "  ")
	t.Setenv("ACUNETIX_BASE_URL", "")

	if got := resolveAcunetixBaseURL(); got != "" {
		t.Fatalf("resolveAcunetixBaseURL() = %q, want empty", got)
	}
}

func TestNewAcunetixClientFromEnvRejectsMissingConfig(t *testing.T) {
	t.Setenv("ACUNETIX_URL", "")
	t.Setenv("ACUNETIX_BASE_URL", "")
	t.Setenv("ACUNETIX_API_KEY", "")

	if _, err := newAcunetixClientFromEnv(); err == nil {
		t.Fatal("expected an error when no Acunetix URL is configured")
	}

	t.Setenv("ACUNETIX_URL", "https://acunetix.example.com:3443")
	if _, err := newAcunetixClientFromEnv(); err == nil {
		t.Fatal("expected an error when no API key is configured")
	}

	t.Setenv("ACUNETIX_API_KEY", "test-key")
	client, err := newAcunetixClientFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.baseURL != "https://acunetix.example.com:3443/api/v1" {
		t.Fatalf("client.baseURL = %q, want the normalized API root", client.baseURL)
	}
}

func TestClampWebScanProgressKeepsRoomForCompletion(t *testing.T) {
	if got := clampWebScanProgress(0); got != webScanProgressBase {
		t.Fatalf("expected progress floor of %d, got %d", webScanProgressBase, got)
	}
	if got := clampWebScanProgress(100); got != webScanProgressMax {
		t.Fatalf("expected progress ceiling of %d, got %d", webScanProgressMax, got)
	}
	if got := clampWebScanProgress(42); got != 42 {
		t.Fatalf("expected in-band progress to pass through, got %d", got)
	}
}

func TestSeverityValuePrefersVulnerabilitySeverity(t *testing.T) {
	vuln := map[string]any{"severity": float64(3)}
	vulnType := map[string]any{"severity": float64(1)}

	if got := severityValue(vuln, vulnType); got != 3 {
		t.Fatalf("expected severity 3 from the vulnerability, got %d", got)
	}
}

func TestSeverityValueFallsBackToTypeName(t *testing.T) {
	vuln := map[string]any{}
	vulnType := map[string]any{"severity": "critical"}

	if got := severityValue(vuln, vulnType); got != 4 {
		t.Fatalf("expected severity 4 for a critical type, got %d", got)
	}
}

func TestSeverityValueClampsUnknownValues(t *testing.T) {
	if got := severityValue(map[string]any{"severity": float64(99)}, nil); got != 4 {
		t.Fatalf("expected severity to clamp to 4, got %d", got)
	}
	if got := severityValue(map[string]any{}, nil); got != 0 {
		t.Fatalf("expected severity 0 when nothing is reported, got %d", got)
	}
}

func TestExtractCVSSFlattensNestedDescriptor(t *testing.T) {
	score, vector := extractCVSS(map[string]any{
		"cvss3": map[string]any{"score": 9.8, "vector": "CVSS:3.0/AV:N/AC:L"},
	})

	if score == nil {
		t.Fatal("expected a CVSS score from the nested descriptor")
	}
	if vector != "CVSS:3.0/AV:N/AC:L" {
		t.Fatalf("unexpected CVSS vector: %q", vector)
	}
}

func TestExtractCVSSPrefersFlatFields(t *testing.T) {
	score, vector := extractCVSS(map[string]any{
		"cvss_score":  7.5,
		"cvss_vector": "CVSS:3.0/AV:N",
		"cvss3":       map[string]any{"score": 1.0, "vector": "ignored"},
	})

	if score != 7.5 {
		t.Fatalf("expected the flat CVSS score to win, got %v", score)
	}
	if vector != "CVSS:3.0/AV:N" {
		t.Fatalf("expected the flat CVSS vector to win, got %q", vector)
	}
}

func TestExtractCWEHandlesFlatAndListForms(t *testing.T) {
	if got := extractCWE(map[string]any{"cwe": 89}); got != 89 {
		t.Fatalf("expected cwe 89, got %v", got)
	}

	got := extractCWE(map[string]any{"cwe_ids": []any{"79", "89"}})
	if got != "79, 89" {
		t.Fatalf("expected joined cwe ids, got %v", got)
	}

	if got := extractCWE(nil); got != nil {
		t.Fatalf("expected nil for a missing type, got %v", got)
	}
}

func TestStringSliceAcceptsStringAndArray(t *testing.T) {
	if got := stringSlice("https://example.com/ref"); len(got) != 1 || got[0] != "https://example.com/ref" {
		t.Fatalf("expected a single-element slice, got %#v", got)
	}

	got := stringSlice([]any{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected slice: %#v", got)
	}

	if got := stringSlice(nil); got != nil {
		t.Fatalf("expected nil for a missing value, got %#v", got)
	}
}
