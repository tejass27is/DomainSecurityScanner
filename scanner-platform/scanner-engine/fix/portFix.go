package fix

import (
	"context"
	"fmt"
	"net"
	"time"

	"scanner-platform/internal/models"
)

type PortScanResult struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	IsOpen bool   `json:"is_open"`
	Status string `json:"status"`
}

func PortFix(
	ctx context.Context,
	job *models.FixScanJob,
) (models.FixScanResult, error) {

	host := job.Data.Host
	port := job.Data.Port

	if port == 0 {
		fmt.Println("INVALID PORT RECEIVED - skipping scan")
		return models.FixScanResult{
			ScanID: job.ScanID,
			Domain: job.Domain,
			Status: "invalid_port",
		}, nil
	}

	if host == "" {
		host = job.Domain
	}

	result := CheckTCPPort(host, port)

	return models.FixScanResult{
		ScanID: job.ScanID,
		Domain: job.Domain,
		Status: result.Status,
		Data:   result,
	}, nil
}

// REAL FIX: TCP CHECK (reliable)
func CheckTCPPort(host string, port int) PortScanResult {

	address := fmt.Sprintf("%s:%d", host, port)

	fmt.Println("TCP CHECK:", address)

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)

	if err != nil {
		return PortScanResult{
			Host:   host,
			Port:   port,
			IsOpen: false,
			Status: "closed",
		}
	}

	conn.Close()

	return PortScanResult{
		Host:   host,
		Port:   port,
		IsOpen: true,
		Status: "open",
	}
}
