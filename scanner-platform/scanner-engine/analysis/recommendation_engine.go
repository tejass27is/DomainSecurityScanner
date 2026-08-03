package analysis

func GenerateRecommendation(port int) string {

	switch port {

	case 21:
		return "Disable FTP or replace with SFTP."

	case 22:
		return "Restrict SSH access via firewall."

	case 3306:
		return "Close MySQL port publicly."

	case 3389:
		return "Restrict RDP access using VPN."

	case 1433:
		return "Restrict MSSQL internally."

	case 80:
		return "Redirect HTTP to HTTPS."

	case 443:
		return "Verify TLS certificates."

	default:
		return "Review service manually."
	}
}
