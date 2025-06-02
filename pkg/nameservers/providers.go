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
	"godaddy": {
		{Name: "godaddy-dns1", IP: net.ParseIP("173.201.71.1"), Port: 53, Provider: "GoDaddy"},
		{Name: "godaddy-dns2", IP: net.ParseIP("173.201.71.12"), Port: 53, Provider: "GoDaddy"},
	},
	"squarespace": {
		{Name: "squarespace-dns1", IP: net.ParseIP("198.185.159.144"), Port: 53, Provider: "Squarespace"},
		{Name: "squarespace-dns2", IP: net.ParseIP("198.185.159.145"), Port: 53, Provider: "Squarespace"},
	},
	"namecheap": {
		{Name: "namecheap-dns1", IP: net.ParseIP("198.54.120.19"), Port: 53, Provider: "Namecheap"},
		{Name: "namecheap-dns2", IP: net.ParseIP("198.54.117.10"), Port: 53, Provider: "Namecheap"},
	},
	"dyn": {
		{Name: "dyn-dns1", IP: net.ParseIP("216.146.35.35"), Port: 53, Provider: "Dyn"},
		{Name: "dyn-dns2", IP: net.ParseIP("216.146.36.36"), Port: 53, Provider: "Dyn"},
	},
	"comodo": {
		{Name: "comodo-dns1", IP: net.ParseIP("8.26.56.26"), Port: 53, Provider: "Comodo"},
		{Name: "comodo-dns2", IP: net.ParseIP("8.20.247.20"), Port: 53, Provider: "Comodo"},
	},
	"verisign": {
		{Name: "verisign-dns1", IP: net.ParseIP("64.6.64.6"), Port: 53, Provider: "Verisign"},
		{Name: "verisign-dns2", IP: net.ParseIP("64.6.65.6"), Port: 53, Provider: "Verisign"},
	},
	"adguard": {
		{Name: "adguard-dns1", IP: net.ParseIP("94.140.14.14"), Port: 53, Provider: "AdGuard"},
		{Name: "adguard-dns2", IP: net.ParseIP("94.140.15.15"), Port: 53, Provider: "AdGuard"},
	},
	"cleanbrowing": {
		{Name: "cleanbrowing-dns1", IP: net.ParseIP("185.228.168.9"), Port: 53, Provider: "CleanBrowsing"},
		{Name: "cleanbrowing-dns2", IP: net.ParseIP("185.228.169.9"), Port: 53, Provider: "CleanBrowsing"},
	},
	"alternate": {
		{Name: "alternate-dns1", IP: net.ParseIP("76.76.19.19"), Port: 53, Provider: "Alternate DNS"},
		{Name: "alternate-dns2", IP: net.ParseIP("76.223.100.101"), Port: 53, Provider: "Alternate DNS"},
	},
	"level3": {
		{Name: "level3-dns1", IP: net.ParseIP("209.244.0.3"), Port: 53, Provider: "Level3"},
		{Name: "level3-dns2", IP: net.ParseIP("209.244.0.4"), Port: 53, Provider: "Level3"},
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
