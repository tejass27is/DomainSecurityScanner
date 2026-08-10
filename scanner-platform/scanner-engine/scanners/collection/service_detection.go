package collection

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"scanner-platform/scanner-engine/analysis"
	"scanner-platform/scanner-engine/core"
)

type ServiceDetectionScanner struct{}

func NewServiceDetectionScanner() *ServiceDetectionScanner {
	return &ServiceDetectionScanner{}
}

func (s *ServiceDetectionScanner) Name() string {
	return "Service Detection Scanner"
}

func (s *ServiceDetectionScanner) Category() string {
	return "Collection"
}

func resolveIP(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func (s *ServiceDetectionScanner) RunCollectionScanner(
	ctx context.Context,
	subdomains core.Result,
	domain string,
) (core.Result, error) {

	type groupKey string
	grouped := make(map[groupKey][]string)

	data, ok := subdomains.Data.([]interface{})
	if !ok {
		return subdomains, fmt.Errorf("invalid data format")
	}

	// =========================================================
	// STEP 1: Normalize + Group Hosts by Port Combination
	// =========================================================

	for _, item := range data {

		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		sub, _ := m["subdomain"].(string)
		if sub == "" {
			continue
		}

		rawPorts, exists := m["port_collection"]
		if !exists || rawPorts == nil {
			continue
		}

		var ports []core.PortData

		// HANDLE MULTIPLE TYPES SAFELY
		switch v := rawPorts.(type) {

		case []core.PortData:
			ports = v

		case []interface{}:

			for _, p := range v {

				pm, ok := p.(map[string]interface{})
				if !ok {
					continue
				}

				portFloat, ok := pm["port"].(float64)
				if !ok {
					continue
				}

				ports = append(ports, core.PortData{
					Port: int(portFloat),
				})
			}

		default:
			continue
		}

		if len(ports) == 0 {
			continue
		}

		// BUILD PORT LIST
		var portList []string

		for _, p := range ports {
			portList = append(portList, fmt.Sprintf("%d", p.Port))
		}

		key := groupKey(strings.Join(portList, ","))

		grouped[key] = append(grouped[key], sub)

		// STORE NORMALIZED PORTS BACK
		m["port_collection"] = ports
	}

	// =========================================================
	// STEP 2: RUN NMAP PER HOST
	// =========================================================

	for key, hosts := range grouped {

		portList := string(key)

		for _, host := range hosts {

			fmt.Println("=================================================")
			fmt.Println("Starting Nmap Scan")
			fmt.Println("Host :", host)
			fmt.Println("Ports:", portList)
			fmt.Println("=================================================")

			// HARD TIMEOUT
			nmapCtx, cancel := context.WithTimeout(ctx, 40*time.Second)

			cmd := exec.CommandContext(
				nmapCtx,
				"nmap",
				"-Pn",
				"-n",
				"-T4",
				"-sV",
				"-p", portList,
				"--host-timeout", "30s",
				"--max-retries", "1",
				"--min-rate", "1000",
				"-oX", "-",
				host,
			)

			out, err := cmd.CombinedOutput()

			cancel()

			if err != nil {

				fmt.Println("Nmap Error on Host:", host)
				fmt.Println("Error:", err)

				if len(out) > 0 {
					fmt.Println(string(out))
				}

				continue
			}

			fmt.Println("Finished Nmap:", host)

			// =====================================================
			// STEP 3: PARSE XML OUTPUT
			// =====================================================

			var result core.NmapRun

			if err := xml.Unmarshal(out, &result); err != nil {

				fmt.Println("XML Parse Error:", err)

				if len(out) > 0 {
					fmt.Println(string(out))
				}

				continue
			}

			// =====================================================
			// STEP 4: MAP RESULTS BACK
			// =====================================================

			for _, h := range result.Hosts {

				var resultHost string

				if len(h.Hostnames) > 0 {

					resultHost = h.Hostnames[0].Name

				} else if len(h.Addresses) > 0 {

					resultHost = h.Addresses[0].Addr

				} else {
					continue
				}

				for _, item := range data {

					m, ok := item.(map[string]any)
					if !ok {
						continue
					}

					sub, _ := m["subdomain"].(string)

					if sub != resultHost {
						continue
					}

					ports, ok := m["port_collection"].([]core.PortData)
					if !ok {
						continue
					}

					// ================================================
					// OPEN PORT ANALYSIS
					// ================================================

					var openPorts []int

					for i := range ports {

						for _, p := range h.Ports {

							if p.PortID == ports[i].Port &&
								p.State.State == "open" {

								ports[i].Service = p.Service.Name
								ports[i].Product = p.Service.Product
								ports[i].Version = p.Service.Version

								openPorts = append(openPorts, ports[i].Port)
							}
						}
					}

					// ================================================
					// SECURITY ANALYSIS
					// ================================================

					for _, port := range openPorts {

						finding := analysis.AnalyzePort(host, port)

						finding.Recommendation =
							analysis.GenerateRecommendation(port)

						finding.Verification =
							analysis.VerifyPort(host, port)

						fmt.Println("================================")
						fmt.Println("Host:", finding.Host)
						fmt.Println("Port:", finding.Port)
						fmt.Println("Service:", finding.Service)
						fmt.Println("Severity:", finding.Severity)
						fmt.Println("Risk:", finding.Risk)
						fmt.Println("Recommendation:", finding.Recommendation)
						fmt.Println("Verification:", finding.Verification)
						fmt.Println("================================")
					}

					m["port_collection"] = ports
				}
			}
		}
	}

	// =========================================================
	// FINAL RESULT
	// =========================================================

	return core.Result{
		Scanner:   s.Name(),
		Category:  s.Category(),
		Target:    domain,
		Data:      data,
		Timestamp: time.Now(),
	}, nil
}
