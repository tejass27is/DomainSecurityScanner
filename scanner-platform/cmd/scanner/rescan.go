package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

type PortScanResult struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	IsOpen bool   `json:"is_open"`
	Status string `json:"status"`
}

func RescanSinglePort(host string, port int) PortScanResult {

	fmt.Printf("\nScanning %s:%d\n", host, port)

	// Hard timeout so a hung naabu process can never block the worker forever.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		"naabu",
		"-host", host,
		"-p", fmt.Sprintf("%d", port),
		"-json",
	)

	output, err := cmd.CombinedOutput()

	fmt.Println(string(output))

	if err != nil {

		return PortScanResult{
			Host:   host,
			Port:   port,
			IsOpen: false,
			Status: "closed",
		}
	}

	if len(output) > 0 {

		return PortScanResult{
			Host:   host,
			Port:   port,
			IsOpen: true,
			Status: "open",
		}
	}

	return PortScanResult{
		Host:   host,
		Port:   port,
		IsOpen: false,
		Status: "closed",
	}
}
