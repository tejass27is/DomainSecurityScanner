package models

type PortFinding struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Service        string `json:"service"`
	Severity       string `json:"severity"`
	Risk           string `json:"risk"`
	Recommendation string `json:"recommendation"`
	Verification   string `json:"verification"`
}
