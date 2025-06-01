// =============================================================================
// internal/dns/checker.go - DNS consistency and validation (FIXED VERSION)
// =============================================================================
package dns

import (
	"context"
	"fmt"
	"strings"
)

// ConsistencyChecker checks for DNS consistency issues
type ConsistencyChecker struct {
	resolver *Resolver
}

// NewConsistencyChecker creates a new consistency checker
func NewConsistencyChecker(resolver *Resolver) *ConsistencyChecker {
	return &ConsistencyChecker{
		resolver: resolver,
	}
}

// CheckConsistency performs comprehensive DNS consistency checks
func (c *ConsistencyChecker) CheckConsistency(ctx context.Context, domain string, nameservers []string) ([]ConsistencyIssue, error) {
	var issues []ConsistencyIssue

	// Check common record types
	recordTypes := []DNSRecordType{RecordTypeA, RecordTypeAAAA, RecordTypeMX, RecordTypeNS, RecordTypeTXT}

	for _, recordType := range recordTypes {
		propagation, err := c.resolver.CheckPropagation(ctx, domain, recordType, nameservers)
		if err != nil {
			continue
		}

		if propagation.Inconsistent {
			issue := ConsistencyIssue{
				Type:        "propagation_inconsistency",
				Domain:      domain,
				RecordType:  recordType,
				Description: fmt.Sprintf("%s records are inconsistent across nameservers", recordType),
				Severity:    c.determineSeverity(recordType),
				Servers:     c.getInconsistentServers(propagation.Results),
			}
			issues = append(issues, issue)
		}

		// Check for other issues
		issues = append(issues, c.checkSpecificIssues(propagation, recordType)...)
	}

	return issues, nil
}

// determineSeverity determines the severity of an issue based on record type
func (c *ConsistencyChecker) determineSeverity(recordType DNSRecordType) string {
	switch recordType {
	case RecordTypeA, RecordTypeAAAA:
		return "high"
	case RecordTypeMX, RecordTypeNS:
		return "medium"
	default:
		return "low"
	}
}

// getInconsistentServers extracts nameservers that have inconsistent results
func (c *ConsistencyChecker) getInconsistentServers(results map[string][]DNSRecord) []string {
	var servers []string
	for server := range results {
		servers = append(servers, server)
	}
	return servers
}

// checkSpecificIssues checks for specific DNS configuration issues
func (c *ConsistencyChecker) checkSpecificIssues(propagation *PropagationResult, recordType DNSRecordType) []ConsistencyIssue {
	var issues []ConsistencyIssue

	switch recordType {
	case RecordTypeMX:
		issues = append(issues, c.checkMXIssues(propagation)...)
	case RecordTypeNS:
		issues = append(issues, c.checkNSIssues(propagation)...)
	case RecordTypeTXT:
		issues = append(issues, c.checkTXTIssues(propagation)...)
	}

	return issues
}

// checkMXIssues checks for MX record specific issues
func (c *ConsistencyChecker) checkMXIssues(propagation *PropagationResult) []ConsistencyIssue {
	var issues []ConsistencyIssue

	for server, records := range propagation.Results {
		for _, record := range records {
			if record.Priority == 0 {
				issues = append(issues, ConsistencyIssue{
					Type:        "mx_priority_zero",
					Domain:      propagation.Domain,
					RecordType:  RecordTypeMX,
					Description: "MX record has priority 0, which may cause mail delivery issues",
					Severity:    "medium",
					Servers:     []string{server},
					Actual:      fmt.Sprintf("Priority: %d", record.Priority),
				})
			}
		}
	}

	return issues
}

// checkNSIssues checks for NS record specific issues
func (c *ConsistencyChecker) checkNSIssues(propagation *PropagationResult) []ConsistencyIssue {
	var issues []ConsistencyIssue

	for server, records := range propagation.Results {
		if len(records) < 2 {
			issues = append(issues, ConsistencyIssue{
				Type:        "insufficient_nameservers",
				Domain:      propagation.Domain,
				RecordType:  RecordTypeNS,
				Description: "Domain has fewer than 2 nameservers, which may cause reliability issues",
				Severity:    "high",
				Servers:     []string{server},
				Actual:      fmt.Sprintf("Count: %d", len(records)),
			})
		}
	}

	return issues
}

// checkTXTIssues checks for TXT record specific issues
func (c *ConsistencyChecker) checkTXTIssues(propagation *PropagationResult) []ConsistencyIssue {
	var issues []ConsistencyIssue

	for server, records := range propagation.Results {
		for _, record := range records {
			if len(record.Value) > 255 {
				issues = append(issues, ConsistencyIssue{
					Type:        "txt_record_too_long",
					Domain:      propagation.Domain,
					RecordType:  RecordTypeTXT,
					Description: "TXT record exceeds recommended length of 255 characters",
					Severity:    "low",
					Servers:     []string{server},
					Actual:      fmt.Sprintf("Length: %d", len(record.Value)),
				})
			}

			// Check for SPF records
			if strings.HasPrefix(record.Value, "v=spf1") {
				issues = append(issues, c.validateSPFRecord(propagation.Domain, record.Value, server)...)
			}

			// Check for DMARC records
			if strings.HasPrefix(record.Value, "v=DMARC1") {
				issues = append(issues, c.validateDMARCRecord(propagation.Domain, record.Value, server)...)
			}

			// Check for DKIM records
			if strings.Contains(record.Name, "_domainkey") {
				issues = append(issues, c.validateDKIMRecord(propagation.Domain, record.Value, server)...)
			}
		}
	}

	return issues
}

// validateSPFRecord validates SPF record syntax
func (c *ConsistencyChecker) validateSPFRecord(domain, spfRecord, server string) []ConsistencyIssue {
	var issues []ConsistencyIssue

	// Check for multiple SPF records (should be avoided)
	if strings.Count(spfRecord, "v=spf1") > 1 {
		issues = append(issues, ConsistencyIssue{
			Type:        "multiple_spf_records",
			Domain:      domain,
			RecordType:  RecordTypeTXT,
			Description: "Multiple SPF records detected, which can cause email delivery issues",
			Severity:    "high",
			Servers:     []string{server},
			Actual:      spfRecord,
		})
	}

	// Check SPF record length
	if len(spfRecord) > 255 {
		issues = append(issues, ConsistencyIssue{
			Type:        "spf_record_too_long",
			Domain:      domain,
			RecordType:  RecordTypeTXT,
			Description: "SPF record is too long and may be truncated",
			Severity:    "medium",
			Servers:     []string{server},
			Actual:      fmt.Sprintf("Length: %d", len(spfRecord)),
		})
	}

	// Check for too many DNS lookups (SPF has a 10 lookup limit)
	lookupCount := strings.Count(spfRecord, "include:") + 
		strings.Count(spfRecord, "a:") + 
		strings.Count(spfRecord, "mx:") + 
		strings.Count(spfRecord, "exists:")

	if lookupCount > 10 {
		issues = append(issues, ConsistencyIssue{
			Type:        "spf_too_many_lookups",
			Domain:      domain,
			RecordType:  RecordTypeTXT,
			Description: "SPF record exceeds the 10 DNS lookup limit",
			Severity:    "high",
			Servers:     []string{server},
			Actual:      fmt.Sprintf("Lookups: %d", lookupCount),
			Expected:    "10 or fewer",
		})
	}

	return issues
}

// validateDMARCRecord validates DMARC record syntax
func (c *ConsistencyChecker) validateDMARCRecord(domain, dmarcRecord, server string) []ConsistencyIssue {
	var issues []ConsistencyIssue

	// Check for missing required policy
	if !strings.Contains(dmarcRecord, "p=") {
		issues = append(issues, ConsistencyIssue{
			Type:        "dmarc_missing_policy",
			Domain:      domain,
			RecordType:  RecordTypeTXT,
			Description: "DMARC record is missing required policy (p=) tag",
			Severity:    "high",
			Servers:     []string{server},
			Actual:      dmarcRecord,
		})
	}

	// Check for weak policy
	if strings.Contains(dmarcRecord, "p=none") {
		issues = append(issues, ConsistencyIssue{
			Type:        "dmarc_weak_policy",
			Domain:      domain,
			RecordType:  RecordTypeTXT,
			Description: "DMARC policy is set to 'none', providing no protection",
			Severity:    "medium",
			Servers:     []string{server},
			Actual:      "p=none",
			Expected:    "p=quarantine or p=reject",
		})
	}

	return issues
}

// validateDKIMRecord validates DKIM record syntax
func (c *ConsistencyChecker) validateDKIMRecord(domain, dkimRecord, server string) []ConsistencyIssue {
	var issues []ConsistencyIssue

	// Check for missing public key
	if !strings.Contains(dkimRecord, "p=") {
		issues = append(issues, ConsistencyIssue{
			Type:        "dkim_missing_public_key",
			Domain:      domain,
			RecordType:  RecordTypeTXT,
			Description: "DKIM record is missing public key (p=) tag",
			Severity:    "high",
			Servers:     []string{server},
			Actual:      dkimRecord,
		})
	}

	// Check for revoked key
	if strings.Contains(dkimRecord, "p=;") || strings.Contains(dkimRecord, "p=\"\";") {
		issues = append(issues, ConsistencyIssue{
			Type:        "dkim_revoked_key",
			Domain:      domain,
			RecordType:  RecordTypeTXT,
			Description: "DKIM key appears to be revoked (empty public key)",
			Severity:    "medium",
			Servers:     []string{server},
			Actual:      "Empty public key",
		})
	}

	return issues
}