package nameservers

import "net"

// CommonNameservers provides lists of well-known public DNS servers
var CommonNameservers = map[string][]Nameserver{
	"google": {
		{Name: "google-dns1", IP: net.ParseIP("8.8.8.8"), Port: 53, Provider: "Google"},
		{Name: "google-dns2", IP: net.ParseIP("8.8.4.4"), Port: 53, Provider: "Google"},
	},
	"cloudflare": {
		{Name: "cloudflare-dns1", IP: net.ParseIP("1.1.1.1"), Port: 53, Provider: "Cloudflare"},
		{Name: "cloudflare-dns2", IP: net.ParseIP("1.0.0.1"), Port: 53, Provider: "Cloudflare"},
	},
	"quad9": {
		{Name: "quad9-dns1", IP: net.ParseIP("9.9.9.9"), Port: 53, Provider: "Quad9"},
		{Name: "quad9-dns2", IP: net.ParseIP("149.112.112.112"), Port: 53, Provider: "Quad9"},
	},
	"opendns": {
		{Name: "opendns1", IP: net.ParseIP("208.67.222.222"), Port: 53, Provider: "OpenDNS"},
		{Name: "opendns2", IP: net.ParseIP("208.67.220.220"), Port: 53, Provider: "OpenDNS"},
	},
}

type Nameserver struct {
	Name     string `json:"name"`
	IP       net.IP `json:"ip"`
	Port     int    `json:"port"`
	Provider string `json:"provider"`
}

// GetAllNameservers returns all nameservers from all providers
func GetAllNameservers() []Nameserver {
	var all []Nameserver
	for _, servers := range CommonNameservers {
		all = append(all, servers...)
	}
	return all
}

// GetProviderNameservers returns nameservers for a specific provider
func GetProviderNameservers(provider string) []Nameserver {
	if servers, exists := CommonNameservers[provider]; exists {
		return servers
	}
	return nil
}

// GetDefaultNameservers returns a default set of reliable nameservers
func GetDefaultNameservers() []Nameserver {
	return []Nameserver{
		CommonNameservers["google"][0],
		CommonNameservers["cloudflare"][0],
		CommonNameservers["quad9"][0],
	}
}