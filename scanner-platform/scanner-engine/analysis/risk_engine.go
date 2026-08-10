package analysis

import "scanner-platform/scanner-engine/models"

func AnalyzePort(host string, port int) models.PortFinding {

	finding := models.PortFinding{
		Host: host,
		Port: port,
	}

	switch port {

	case 21:
		finding.Service = "FTP"
		finding.Severity = "HIGH"
		finding.Risk = "FTP exposed publicly."

	case 22:
		finding.Service = "SSH"
		finding.Severity = "MEDIUM"
		finding.Risk = "SSH exposed publicly."

	case 3306:
		finding.Service = "MySQL"
		finding.Severity = "CRITICAL"
		finding.Risk = "MySQL exposed publicly."

	case 3389:
		finding.Service = "RDP"
		finding.Severity = "CRITICAL"
		finding.Risk = "RDP exposed publicly."

	case 1433:
		finding.Service = "MSSQL"
		finding.Severity = "CRITICAL"
		finding.Risk = "MSSQL exposed publicly."

	case 80:
		finding.Service = "HTTP"
		finding.Severity = "INFO"
		finding.Risk = "Web service running."

	case 443:
		finding.Service = "HTTPS"
		finding.Severity = "INFO"
		finding.Risk = "Secure web service running."

	default:
		finding.Service = "Unknown"
		finding.Severity = "LOW"
		finding.Risk = "Unknown service detected."
	}

	return finding
}
