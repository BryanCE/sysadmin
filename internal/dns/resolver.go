// =============================================================================
// internal/dns/resolver.go - DNS resolution implementation
// =============================================================================
package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver handles DNS queries and operations
type Resolver struct {
	client  *dns.Client
	options QueryOptions
}

// NewResolver creates a new DNS resolver with default options
func NewResolver() *Resolver {
	return &Resolver{
		client: &dns.Client{
			Timeout: 5 * time.Second,
		},
		options: QueryOptions{
			Timeout:      5 * time.Second,
			Retries:      3,
			UseRecursion: true,
			CheckDNSSEC:  false,
			IPv4Only:     false,
			IPv6Only:     false,
		},
	}
}

// NewResolverWithOptions creates a resolver with custom options
func NewResolverWithOptions(opts QueryOptions) *Resolver {
	return &Resolver{
		client: &dns.Client{
			Timeout: opts.Timeout,
		},
		options: opts,
	}
}

// Query performs a DNS query for a specific domain and record type
func (r *Resolver) Query(ctx context.Context, domain string, recordType DNSRecordType, nameserver string) (*DNSResult, error) {
	start := time.Now()
	
	result := &DNSResult{
		Query: DNSQuery{
			Domain:       domain,
			RecordType:   recordType,
			Nameserver:   nameserver,
			Timeout:      r.options.Timeout,
			UseRecursion: r.options.UseRecursion,
		},
		Timestamp:  start,
		Nameserver: nameserver,
	}

	// Prepare the DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), r.getRecordTypeCode(recordType))
	msg.RecursionDesired = r.options.UseRecursion

	if r.options.CheckDNSSEC {
		msg.SetEdns0(4096, true)
	}

	// Ensure nameserver has port
	if !strings.Contains(nameserver, ":") {
		nameserver += ":53"
	}

	// Perform the query with retries
	var response *dns.Msg
	var err error
	
	for attempt := 0; attempt < r.options.Retries; attempt++ {
		response, _, err = r.client.ExchangeContext(ctx, msg, nameserver)
		if err == nil {
			break
		}
		if attempt < r.options.Retries-1 {
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
	}

	result.ResponseTime = time.Since(start)

	if err != nil {
		result.Error = fmt.Errorf("DNS query failed: %w", err)
		return result, result.Error
	}

	if response == nil {
		result.Error = fmt.Errorf("received nil response")
		return result, result.Error
	}

	// Parse the response
	result.Records = r.parseResponse(response, recordType)
	return result, nil
}

// QueryMultipleServers queries multiple nameservers for the same domain
func (r *Resolver) QueryMultipleServers(ctx context.Context, domain string, recordType DNSRecordType, nameservers []string) ([]*DNSResult, error) {
	results := make([]*DNSResult, len(nameservers))
	errors := make([]error, len(nameservers))

	// Create a channel to collect results
	type resultWithIndex struct {
		index  int
		result *DNSResult
	}
	
	resultChan := make(chan resultWithIndex, len(nameservers))

	// Launch goroutines for parallel queries
	for i, ns := range nameservers {
		go func(index int, nameserver string) {
			result, err := r.Query(ctx, domain, recordType, nameserver)
			if err != nil {
				errors[index] = err
			}
			resultChan <- resultWithIndex{index: index, result: result}
		}(i, ns)
	}

	// Collect results
	for i := 0; i < len(nameservers); i++ {
		select {
		case res := <-resultChan:
			results[res.index] = res.result
		case <-ctx.Done():
			return results, ctx.Err()
		}
	}

	return results, nil
}

// CheckPropagation checks DNS propagation across multiple nameservers
func (r *Resolver) CheckPropagation(ctx context.Context, domain string, recordType DNSRecordType, nameservers []string) (*PropagationResult, error) {
	results, err := r.QueryMultipleServers(ctx, domain, recordType, nameservers)
	if err != nil {
		return nil, err
	}

	propagation := &PropagationResult{
		Domain:       domain,
		RecordType:   recordType,
		Results:      make(map[string][]DNSRecord),
		TotalServers: len(nameservers),
		Timestamp:    time.Now(),
	}

	// Process results
	var firstValidResult []DNSRecord
	for i, result := range results {
		if result != nil && result.Error == nil && len(result.Records) > 0 {
			propagation.Results[nameservers[i]] = result.Records
			propagation.SuccessCount++

			if firstValidResult == nil {
				firstValidResult = result.Records
			}
		}
	}

	// Check for inconsistencies
	propagation.Inconsistent = r.checkInconsistency(propagation.Results)

	return propagation, nil
}

// parseResponse converts DNS response to our record format
func (r *Resolver) parseResponse(response *dns.Msg, recordType DNSRecordType) []DNSRecord {
	var records []DNSRecord

	for _, answer := range response.Answer {
		record := DNSRecord{
			Name: answer.Header().Name,
			Type: recordType,
			TTL:  answer.Header().Ttl,
		}

		switch rr := answer.(type) {
		case *dns.A:
			record.Value = rr.A.String()
		case *dns.AAAA:
			record.Value = rr.AAAA.String()
		case *dns.CNAME:
			record.Value = rr.Target
		case *dns.MX:
			record.Value = rr.Mx
			record.Priority = int(rr.Preference)
		case *dns.NS:
			record.Value = rr.Ns
		case *dns.TXT:
			record.Value = strings.Join(rr.Txt, " ")
		case *dns.PTR:
			record.Value = rr.Ptr
		case *dns.SOA:
			record.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
				rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
		case *dns.SRV:
			record.Value = rr.Target
			record.Priority = int(rr.Priority)
		default:
			record.Value = answer.String()
		}

		records = append(records, record)
	}

	return records
}

// getRecordTypeCode converts our record type to DNS library type
func (r *Resolver) getRecordTypeCode(recordType DNSRecordType) uint16 {
	switch recordType {
	case RecordTypeA:
		return dns.TypeA
	case RecordTypeAAAA:
		return dns.TypeAAAA
	case RecordTypeCNAME:
		return dns.TypeCNAME
	case RecordTypeMX:
		return dns.TypeMX
	case RecordTypeNS:
		return dns.TypeNS
	case RecordTypeTXT:
		return dns.TypeTXT
	case RecordTypeSOA:
		return dns.TypeSOA
	case RecordTypePTR:
		return dns.TypePTR
	case RecordTypeSRV:
		return dns.TypeSRV
	default:
		return dns.TypeA
	}
}

// checkInconsistency determines if there are inconsistencies in DNS responses
func (r *Resolver) checkInconsistency(results map[string][]DNSRecord) bool {
	if len(results) < 2 {
		return false
	}

	var firstSet map[string]bool
	first := true

	for _, records := range results {
		currentSet := make(map[string]bool)
		for _, record := range records {
			currentSet[record.Value] = true
		}

		if first {
			firstSet = currentSet
			first = false
			continue
		}

		// Compare with first set
		if len(currentSet) != len(firstSet) {
			return true
		}

		for value := range currentSet {
			if !firstSet[value] {
				return true
			}
		}
	}

	return false
}