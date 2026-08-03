package collection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"scanner-platform/scanner-engine/core"
)

type PortFilter struct{}

func NewPortFilter() *PortFilter {
	return &PortFilter{}
}

func (f *PortFilter) Name() string {
	return "Port Collection"
}

func (f *PortFilter) Category() string {
	return "Collection Pipeline"
}

func (f *PortFilter) RunCollectionScanner(
	ctx context.Context,
	subdomains core.Result,
	domain string,
) (core.Result, error) {

	null := core.Result{}
	cmd := exec.CommandContext(
		ctx,
		"naabu",
		"-top-ports", "100",
		"-rate", "3000",
		"-retries", "0",
		"-timeout", "300",
		"-silent",
		"-json",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return null, err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return null, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return null, err
	}

	if err := cmd.Start(); err != nil {
		return null, err
	}

	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			fmt.Println("NAABU ERR:", sc.Text())
		}
	}()

	go func() {
		defer stdin.Close()

		for _, subdomain := range subdomains.Data.([]interface{}) {

			sub := subdomain.(map[string]any)["subdomain"]

			if sub == "" {
				continue
			}

			fmt.Fprintln(stdin, sub)
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	
	subSlice := subdomains.Data.([]interface{})
	index := make(map[string]map[string]any)
	
	for _, item := range subSlice {
		m := item.(map[string]any)
		
		sub := m["subdomain"].(string)
		index[sub] = m
	}
	
	portMap := make(map[string][]core.PortData)
	portSeen := make(map[string]map[string]struct{}) 

	for scanner.Scan() {
		var out core.NaabuOutput

		if err := json.Unmarshal(scanner.Bytes(), &out); err != nil {
			return null, err
		}

		if _, ok := portSeen[out.Host]; !ok {
			portSeen[out.Host] = make(map[string]struct{})
		}

		key := fmt.Sprintf("%d/%s", out.Port, out.Protocol)

		if _, exists := portSeen[out.Host][key]; exists {
			continue 
		}

		portSeen[out.Host][key] = struct{}{}

		portMap[out.Host] = append(portMap[out.Host], core.PortData{
			Port:     out.Port,
			Protocol: out.Protocol,
		})

		if existing, ok := index[out.Host]; ok {
			existing["port_collection"] = portMap[out.Host]
		}
	}

	results := core.Result{
		Scanner:   f.Name(),
		Category:  f.Category(),
		Target:    domain,
		Data:      subdomains.Data,
		Timestamp: time.Now(),
	}

	return results, nil
}
