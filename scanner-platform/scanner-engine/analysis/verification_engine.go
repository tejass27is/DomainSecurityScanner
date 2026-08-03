package analysis

import (
	"fmt"
	"os/exec"
	"strings"
)

func VerifyPort(host string, port int) string {

	cmd := exec.Command(
		"nmap",
		"-Pn",
		"-p",
		fmt.Sprintf("%d", port),
		host,
	)

	output, err := cmd.CombinedOutput()

	if err != nil {
		return "VERIFICATION_FAILED"
	}

	result := string(output)

	if strings.Contains(result, "open") {
		return "OPEN"
	}

	if strings.Contains(result, "filtered") {
		return "FILTERED"
	}

	if strings.Contains(result, "closed") {
		return "CLOSED"
	}

	return "UNKNOWN"
}
