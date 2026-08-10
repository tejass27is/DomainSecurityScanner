package models

import "time"

type ScanJob struct {
	ScanID          string         `json:"scan_id"`
	Target          string         `json:"target"`
	Status          string         `json:"status,omitempty"`
	Progress        int            `json:"progress,omitempty"`
	CurrentStage    string         `json:"current_stage,omitempty"`
	Message         string         `json:"message,omitempty"`
	StartedAt       time.Time      `json:"started_at,omitempty"`
	UpdatedAt       time.Time      `json:"updated_at,omitempty"`
	FinishedAt      *time.Time     `json:"finished_at,omitempty"`
	LastError       string         `json:"last_error,omitempty"`
	Attempts        int            `json:"attempts,omitempty"`
	CancelRequested bool           `json:"cancel_requested,omitempty"`
	Checkpoint      map[string]any `json:"checkpoint,omitempty"`
}

type FixData struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type FixScanJob struct {
	ScanID  string  `json:"scan_id"`
	OrgID   string  `json:"org_id"`
	Domain  string  `json:"domain"`
	FixType string  `json:"fix_type"`
	Data    FixData `json:"data"`
}

type FixScanResult struct {
	ScanID string      `json:"scan_id"`
	Domain string      `json:"domain"`
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
}
type ScanNotification struct {
	ScanID         string         `json:"scan_id"`
	Target         string         `json:"target"`
	Event          string         `json:"event"`
	Status         string         `json:"status"`
	Stage          string         `json:"stage,omitempty"`
	Progress       int            `json:"progress,omitempty"`
	Message        string         `json:"message,omitempty"`
	EvidenceCount  int            `json:"evidence_count,omitempty"`
	Evidence       []map[string]any `json:"evidence,omitempty"`
	Checkpoint     map[string]any `json:"checkpoint,omitempty"`
}

type ScanResult struct {
	ScanID      string         `json:"scan_id"`
	Target      string         `json:"target"`
	Status      string         `json:"status"`
	Data        any            `json:"data"`
	Timestamp   time.Time      `json:"timestamp"`
	Evidence    []map[string]any `json:"evidence,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Progress    int            `json:"progress,omitempty"`
	CurrentStage string        `json:"current_stage,omitempty"`
}
