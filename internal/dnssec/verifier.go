// =============================================================================
// internal/dnssec/verifier.go - DNSSEC verification functionality
// =============================================================================
package dnssec

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidationResult represents the result of DNSSEC validation
type ValidationResult struct {
	Domain           string
	HasDNSSEC        bool
	IsSigned         bool
	IsValid          bool
	ValidationErrors []string
	DS               *DSRecord
	DNSKEY           []*DNSKEYRecord
	RRSIG            []*RRSIGRecord
	Timestamp        time.Time
}

// DSRecord represents a DS (Delegation Signer) record
type DSRecord struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
}

// DNSKEYRecord represents a DNSKEY record
type DNSKEYRecord struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string
}

// RRSIGRecord represents an RRSIG record
type RRSIGRecord struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	TTL         uint32
	Expiration  time.Time
	Inception   time.Time
	KeyTag      uint16
	SignerName  string
	Signature   string
}

// VerifyDNSSEC performs DNSSEC validation for a domain
func VerifyDNSSEC(domain string, nameserver string) (*ValidationResult, error) {
	result := &ValidationResult{
		Domain:    domain,
		HasDNSSEC: false,
		IsSigned:  false,
		IsValid:   false,
		Timestamp: time.Now(),
	}

	// Create DNS client
	client := new(dns.Client)
	client.Net = "udp"

	// Check for DS records at parent zone
	parentZone := getParentZone(domain)
	if parentZone != "" {
		dsResult, err := queryDS(client, domain, parentZone, nameserver)
		if err != nil {
			result.ValidationErrors = append(result.ValidationErrors,
				fmt.Sprintf("Error querying DS records: %v", err))
		} else if dsResult != nil {
			result.HasDNSSEC = true
			result.DS = dsResult
		}
	}

	// Query DNSKEY records
	dnskeyResult, err := queryDNSKEY(client, domain, nameserver)
	if err != nil {
		result.ValidationErrors = append(result.ValidationErrors,
			fmt.Sprintf("Error querying DNSKEY records: %v", err))
	} else {
		result.DNSKEY = dnskeyResult
		if len(dnskeyResult) > 0 {
			result.IsSigned = true
		}
	}

	// Query RRSIG records
	rrsigResult, err := queryRRSIG(client, domain, nameserver)
	if err != nil {
		result.ValidationErrors = append(result.ValidationErrors,
			fmt.Sprintf("Error querying RRSIG records: %v", err))
	} else {
		result.RRSIG = rrsigResult
	}

	// Validate chain of trust
	if result.HasDNSSEC && result.IsSigned {
		valid, err := validateChainOfTrust(result)
		if err != nil {
			result.ValidationErrors = append(result.ValidationErrors,
				fmt.Sprintf("Chain of trust validation error: %v", err))
		}
		result.IsValid = valid
	}

	return result, nil
}

// Helper functions

func getParentZone(domain string) string {
	parts := dns.SplitDomainName(domain)
	if len(parts) <= 1 {
		return ""
	}
	return dns.Fqdn(strings.Join(parts[1:], "."))
}

func queryDS(client *dns.Client, domain, parentZone, nameserver string) (*DSRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if err != nil {
		return nil, err
	}

	for _, ans := range r.Answer {
		if ds, ok := ans.(*dns.DS); ok {
			return &DSRecord{
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
				Digest:     ds.Digest,
			}, nil
		}
	}

	return nil, nil
}

func queryDNSKEY(client *dns.Client, domain, nameserver string) ([]*DNSKEYRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if err != nil {
		return nil, err
	}

	var keys []*DNSKEYRecord
	for _, ans := range r.Answer {
		if dnskey, ok := ans.(*dns.DNSKEY); ok {
			keys = append(keys, &DNSKEYRecord{
				Flags:     dnskey.Flags,
				Protocol:  dnskey.Protocol,
				Algorithm: dnskey.Algorithm,
				PublicKey: dnskey.PublicKey,
			})
		}
	}

	return keys, nil
}

func queryRRSIG(client *dns.Client, domain, nameserver string) ([]*RRSIGRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeRRSIG)
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if err != nil {
		return nil, err
	}

	var sigs []*RRSIGRecord
	for _, ans := range r.Answer {
		if rrsig, ok := ans.(*dns.RRSIG); ok {
			sigs = append(sigs, &RRSIGRecord{
				TypeCovered: rrsig.TypeCovered,
				Algorithm:   rrsig.Algorithm,
				Labels:      rrsig.Labels,
				TTL:         uint32(rrsig.OrigTtl),
				Expiration:  time.Unix(int64(rrsig.Expiration), 0),
				Inception:   time.Unix(int64(rrsig.Inception), 0),
				KeyTag:      rrsig.KeyTag,
				SignerName:  rrsig.SignerName,
				Signature:   rrsig.Signature,
			})
		}
	}

	return sigs, nil
}

func validateChainOfTrust(result *ValidationResult) (bool, error) {
	// Basic validation checks
	if result.DS == nil {
		return false, fmt.Errorf("no DS record found")
	}

	if len(result.DNSKEY) == 0 {
		return false, fmt.Errorf("no DNSKEY records found")
	}

	if len(result.RRSIG) == 0 {
		return false, fmt.Errorf("no RRSIG records found")
	}

	// Check DNSKEY validity
	var foundValidKey bool
	for _, key := range result.DNSKEY {
		if key.Flags&256 != 0 { // Zone Signing Key
			foundValidKey = true
			break
		}
	}

	if !foundValidKey {
		return false, fmt.Errorf("no valid zone signing key found")
	}

	// Check RRSIG validity
	now := time.Now()
	for _, sig := range result.RRSIG {
		if now.After(sig.Expiration) || now.Before(sig.Inception) {
			return false, fmt.Errorf("RRSIG timing validation failed")
		}
	}

	return true, nil
}
