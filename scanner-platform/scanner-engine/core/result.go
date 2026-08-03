package core

import "time"

type ScanResult struct {
	ScanID    string
	Target    string
	Data      any
	Timestamp time.Time
}

type Result struct {
	Scanner   string
	Category  string
	Target    string
	Data      any
	Severity  string
	Timestamp time.Time
}

type HTTPScanData struct {
	IP         string `json:"ip"`
	Subdomain  string `json:"subdomain"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Scheme     string `json:"scheme"`

	Server       string   `json:"server"`
	Technologies []string `json:"technologies"`

	TLS struct {
		Enabled bool   `json:"enabled"`
		Version string `json:"version"`
		Issuer  string `json:"issuer"`
		Expired bool   `json:"expired"`
	} `json:"tls"`

	Headers struct {
		ContentSecurityPolicy bool `json:"content_security_policy"`
		StrictTransport       bool `json:"strict_transport_security"`
		XFrameOptions         bool `json:"x_frame_options"`
		XContentTypeOptions   bool `json:"x_content_type_options"`
	} `json:"headers"`

	Redirects struct {
		FinalURL      string `json:"final_url"`
		RedirectCount int    `json:"redirect_count"`
	} `json:"redirects"`

	Metadata struct {
		Title          string `json:"title"`
		ContentType    string `json:"content_type"`
		ContentLength  int    `json:"content_length"`
		ResponseTimeMs string `json:"response_time_ms"`
	} `json:"metadata"`
}

type SOARecord struct {
	Name    string `json:"name"`
	NS      string `json:"ns"`
	Mailbox string `json:"mailbox"`
	Serial  int64  `json:"serial"`
	Refresh int64  `json:"refresh"`
	Retry   int64  `json:"retry"`
	Expire  int64  `json:"expire"`
	Minttl  int64  `json:"minttl"`
}

type DNSXResult struct {
	Host     string   `json:"host"`
	TTL      int      `json:"ttl"`
	Resolver []string `json:"resolver"`

	A     []string `json:"a"`
	AAAA  []string `json:"aaaa"`
	CNAME []string `json:"cname,omitempty"`
	MX    []string `json:"mx"`
	NS    []string `json:"ns"`
	TXT   []string `json:"txt"`

	SOA []SOARecord `json:"soa"`

	All []string `json:"all"`

	StatusCode string `json:"status_code"`
	Timestamp  string `json:"timestamp"`
}

type NaabuOutput struct {
	Host     string `json:"host"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// type TLSDetails struct {
// 	Enabled    bool      `json:"enabled"`
// 	Version    string    `json:"version,omitempty"`
// 	Cipher     string    `json:"cipher,omitempty"`
// 	ALPN       string    `json:"alpn,omitempty"`
// 	Issuer     string    `json:"issuer,omitempty"`
// 	NotBefore  time.Time `json:"not_before,omitempty"`
// 	NotAfter   time.Time `json:"not_after,omitempty"`
// 	Expired    bool      `json:"expired"`
// 	SelfSigned bool      `json:"self_signed"`
// 	WeakTLS    bool      `json:"weak_tls"`
// }

type PortData struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Service  string   `json:"service,omitempty"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	TLS      *TLSData `json:"tls,omitempty"`
}

type TLSData struct {
	Enabled     bool     `json:"enabled"`
	Version     string   `json:"version"`
	Cipher      string   `json:"cipher"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Expired     bool     `json:"expired"`
	SelfSigned  bool     `json:"self_signed"`
	Wildcard    bool     `json:"wildcard"`
	SAN         []string `json:"san"`
	JARM        string   `json:"jarm"`
	Fingerprint string   `json:"fingerprint"`
}

// core/tlsx_raw.go

type TLSXOutput struct {
	Host        string `json:"host"`
	IP          string `json:"ip"`
	Port        string `json:"port"`
	ProbeStatus bool   `json:"probe_status"`

	TLSVersion string `json:"tls_version"`
	Cipher     string `json:"cipher"`

	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`

	SubjectDN string   `json:"subject_dn"`
	SubjectCN string   `json:"subject_cn"`
	SubjectAN []string `json:"subject_an"`

	IssuerDN string `json:"issuer_dn"`
	IssuerCN string `json:"issuer_cn"`

	WildcardCertificate bool   `json:"wildcard_certificate"`
	JARMHash            string `json:"jarm_hash"`

	FingerprintHash struct {
		SHA256 string `json:"sha256"`
	} `json:"fingerprint_hash"`
}

// type PortData struct {
// 	Port       int         `json:"port"`
// 	Protocol   string      `json:"protocol"`
// 	TLSDetails *TLSDetails `json:"tls_details,omitempty"`
// }
type NmapRun struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Addresses []Address      `xml:"address"`
	Hostnames []Hostname     `xml:"hostnames>hostname"`
	Ports     []NmapPortData `xml:"ports>port"`
}

type Address struct {
	Addr string `xml:"addr,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
}

type NmapPortData struct {
	PortID   int    `xml:"portid,attr"`
	Protocol string `xml:"protocol,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
}