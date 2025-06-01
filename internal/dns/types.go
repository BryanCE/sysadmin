// =============================================================================
// internal/dns/types.go - Core DNS data structures
// =============================================================================
package dns

import (
	"net"
	"time"
)

// DNSRecordType represents different DNS record types
type DNSRecordType string

const (
	RecordTypeA     DNSRecordType = "A"
	RecordTypeAAAA  DNSRecordType = "AAAA"
	RecordTypeCNAME DNSRecordType = "CNAME"
	RecordTypeMX    DNSRecordType = "MX"
	RecordTypeNS    DNSRecordType = "NS"
	RecordTypeTXT   DNSRecordType = "TXT"
	RecordTypeSOA   DNSRecordType = "SOA"
	RecordTypePTR   DNSRecordType = "PTR"
	RecordTypeSRV   DNSRecordType = "SRV"
)

// DNSRecord represents a single DNS record
type DNSRecord struct {
	Name     string        `json:"name"`
	Type     DNSRecordType `json:"type"`
	Value    string        `json:"value"`
	TTL      uint32        `json:"ttl"`
	Priority int           `json:"priority,omitempty"` // For MX, SRV records
}

// DNSQuery represents a DNS query to be performed
type DNSQuery struct {
	Domain      string          `json:"domain"`
	RecordType  DNSRecordType   `json:"record_type"`
	Nameserver  string          `json:"nameserver"`
	Timeout     time.Duration   `json:"timeout"`
	UseRecursion bool           `json:"use_recursion"`
}

// DNSResult represents the result of a DNS query
type DNSResult struct {
	Query       DNSQuery      `json:"query"`
	Records     []DNSRecord   `json:"records"`
	ResponseTime time.Duration `json:"response_time"`
	Error       error         `json:"error,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
	Nameserver  string        `json:"nameserver"`
}

// PropagationResult represents DNS propagation check results
type PropagationResult struct {
	Domain        string                   `json:"domain"`
	RecordType    DNSRecordType           `json:"record_type"`
	Results       map[string][]DNSRecord  `json:"results"` // nameserver -> records
	Inconsistent  bool                    `json:"inconsistent"`
	TotalServers  int                     `json:"total_servers"`
	SuccessCount  int                     `json:"success_count"`
	Timestamp     time.Time               `json:"timestamp"`
}

// ConsistencyIssue represents a DNS consistency problem
type ConsistencyIssue struct {
	Type        string    `json:"type"`
	Domain      string    `json:"domain"`
	RecordType  DNSRecordType `json:"record_type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"` // "low", "medium", "high"
	Servers     []string  `json:"servers"`
	Expected    string    `json:"expected,omitempty"`
	Actual      string    `json:"actual,omitempty"`
}

// BulkQueryResult represents results from bulk DNS queries
type BulkQueryResult struct {
	TotalQueries    int                    `json:"total_queries"`
	SuccessfulQueries int                  `json:"successful_queries"`
	FailedQueries   int                    `json:"failed_queries"`
	Results         map[string]DNSResult   `json:"results"` // domain -> result
	Duration        time.Duration          `json:"duration"`
	Timestamp       time.Time              `json:"timestamp"`
}

// Nameserver represents a DNS nameserver
type Nameserver struct {
	Name        string `json:"name"`
	IP          net.IP `json:"ip"`
	Port        int    `json:"port"`
	Provider    string `json:"provider"`
	Location    string `json:"location,omitempty"`
	Description string `json:"description,omitempty"`
}

// QueryOptions represents options for DNS queries
type QueryOptions struct {
	Timeout      time.Duration   `json:"timeout"`
	Retries      int            `json:"retries"`
	UseRecursion bool           `json:"use_recursion"`
	CheckDNSSEC  bool           `json:"check_dnssec"`
	IPv4Only     bool           `json:"ipv4_only"`
	IPv6Only     bool           `json:"ipv6_only"`
}

// OutputFormat represents different output formats
type OutputFormat string

const (
	OutputFormatTable OutputFormat = "table"
	OutputFormatJSON  OutputFormat = "json"
	OutputFormatCSV   OutputFormat = "csv"
	OutputFormatXML   OutputFormat = "xml"
)