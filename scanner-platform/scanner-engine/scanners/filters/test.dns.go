package filters

import (
	"context"
	"fmt"
	"net"


	"scanner-platform/scanner-engine/core"
)

type DNSFilterTest struct {}

func NEWDNSTEST() *DNSFilterTest {
	return &DNSFilterTest{}
}

func (f *DNSFilterTest) Name() string {
	return "DNSFilterTest"
}

func (f *DNSFilterTest) Category() string {
	return "FilterScanner"
}


func (f *DNSFilterTest) RunFilterScanner(ctx context.Context, subdomains []core.Result, domain string) ([] core.Result, error){

	result := []core.Result{}
		
		fmt.Println("Executing DNS Filter on subdomains")
	
		for _, subdomain := range subdomains {
			ips, err := net.LookupIP(subdomain.Data.(map[string]string)["subdomain"])
			if err != nil || len(ips) == 0 {
				continue
			}
			result = append(result, subdomain)
		}

	fmt.Println("DNS Filtered subdomain count:", len(result))
	
	return result, nil
}