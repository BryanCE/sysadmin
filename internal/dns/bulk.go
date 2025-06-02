// =============================================================================
// internal/dns/bulk.go - Bulk DNS operations
// =============================================================================
package dns

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// BulkOperation represents the type of bulk operation
type BulkOperation string

const (
	BulkOperationQuery       BulkOperation = "query"
	BulkOperationPropagation BulkOperation = "propagation"
	BulkOperationConsistency BulkOperation = "consistency"
)

// BulkResult represents the result of a bulk operation on a single domain
type BulkResult struct {
	Domain    string
	Success   bool
	Error     error
	StartTime time.Time
	EndTime   time.Time
	Data      interface{} // Can be QueryResult, PropagationResult, or []ConsistencyIssue
}

// BulkSummary provides a summary of bulk operations
type BulkSummary struct {
	TotalDomains int
	Successful   int
	Failed       int
	Duration     time.Duration
	Results      []BulkResult
}

// BulkProcessor handles bulk DNS operations
type BulkProcessor struct {
	resolver           *Resolver
	consistencyChecker *ConsistencyChecker
	concurrency        int
	progressCallback   func(current, total int, domain string, success bool)
}

// NewBulkProcessor creates a new bulk processor
func NewBulkProcessor(resolver *Resolver, concurrency int) *BulkProcessor {
	return &BulkProcessor{
		resolver:           resolver,
		consistencyChecker: NewConsistencyChecker(resolver),
		concurrency:        concurrency,
	}
}

// SetProgressCallback sets a callback for progress updates
func (bp *BulkProcessor) SetProgressCallback(callback func(current, total int, domain string, success bool)) {
	bp.progressCallback = callback
}

// ReadDomainsFromFile reads domains from a file (one per line)
func ReadDomainsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		domain := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}

		// Basic domain validation
		if !isValidDomain(domain) {
			return nil, fmt.Errorf("invalid domain on line %d: %s", lineNum, domain)
		}

		domains = append(domains, domain)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("no valid domains found in file")
	}

	return domains, nil
}

// ProcessQuery performs bulk DNS queries
func (bp *BulkProcessor) ProcessQuery(ctx context.Context, domains []string, recordType DNSRecordType, nameservers []string) (*BulkSummary, error) {
	startTime := time.Now()
	results := make([]BulkResult, 0, len(domains))

	// Create a channel for domains to process
	domainChan := make(chan string, len(domains))
	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	// Create a channel for results
	resultChan := make(chan BulkResult, len(domains))

	// Create worker pool
	var wg sync.WaitGroup
	for i := 0; i < bp.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				result := bp.processSingleQuery(ctx, domain, recordType, nameservers)
				resultChan <- result
			}
		}()
	}

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results and update progress
	processed := 0
	successful := 0
	for result := range resultChan {
		processed++
		results = append(results, result)

		if result.Success {
			successful++
		}

		if bp.progressCallback != nil {
			bp.progressCallback(processed, len(domains), result.Domain, result.Success)
		}
	}

	return &BulkSummary{
		TotalDomains: len(domains),
		Successful:   successful,
		Failed:       len(domains) - successful,
		Duration:     time.Since(startTime),
		Results:      results,
	}, nil
}

// ProcessPropagation performs bulk DNS propagation checks
func (bp *BulkProcessor) ProcessPropagation(ctx context.Context, domains []string, recordType DNSRecordType, nameservers []string) (*BulkSummary, error) {
	startTime := time.Now()
	results := make([]BulkResult, 0, len(domains))

	// Create a channel for domains to process
	domainChan := make(chan string, len(domains))
	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	// Create a channel for results
	resultChan := make(chan BulkResult, len(domains))

	// Create worker pool
	var wg sync.WaitGroup
	for i := 0; i < bp.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				result := bp.processSinglePropagation(ctx, domain, recordType, nameservers)
				resultChan <- result
			}
		}()
	}

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results and update progress
	processed := 0
	successful := 0
	for result := range resultChan {
		processed++
		results = append(results, result)

		if result.Success {
			successful++
		}

		if bp.progressCallback != nil {
			bp.progressCallback(processed, len(domains), result.Domain, result.Success)
		}
	}

	return &BulkSummary{
		TotalDomains: len(domains),
		Successful:   successful,
		Failed:       len(domains) - successful,
		Duration:     time.Since(startTime),
		Results:      results,
	}, nil
}

// ProcessConsistency performs bulk DNS consistency checks
func (bp *BulkProcessor) ProcessConsistency(ctx context.Context, domains []string, nameservers []string) (*BulkSummary, error) {
	startTime := time.Now()
	results := make([]BulkResult, 0, len(domains))

	// Create a channel for domains to process
	domainChan := make(chan string, len(domains))
	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	// Create a channel for results
	resultChan := make(chan BulkResult, len(domains))

	// Create worker pool
	var wg sync.WaitGroup
	for i := 0; i < bp.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				result := bp.processSingleConsistency(ctx, domain, nameservers)
				resultChan <- result
			}
		}()
	}

	// Close result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results and update progress
	processed := 0
	successful := 0
	for result := range resultChan {
		processed++
		results = append(results, result)

		if result.Success {
			successful++
		}

		if bp.progressCallback != nil {
			bp.progressCallback(processed, len(domains), result.Domain, result.Success)
		}
	}

	return &BulkSummary{
		TotalDomains: len(domains),
		Successful:   successful,
		Failed:       len(domains) - successful,
		Duration:     time.Since(startTime),
		Results:      results,
	}, nil
}

// processSingleQuery processes a single domain query
func (bp *BulkProcessor) processSingleQuery(ctx context.Context, domain string, recordType DNSRecordType, nameservers []string) BulkResult {
	startTime := time.Now()

	// Use first nameserver for query
	ns := nameservers[0]

	result, err := bp.resolver.Query(ctx, domain, recordType, ns)

	return BulkResult{
		Domain:    domain,
		Success:   err == nil,
		Error:     err,
		StartTime: startTime,
		EndTime:   time.Now(),
		Data:      result,
	}
}

// processSinglePropagation processes a single domain propagation check
func (bp *BulkProcessor) processSinglePropagation(ctx context.Context, domain string, recordType DNSRecordType, nameservers []string) BulkResult {
	startTime := time.Now()

	result, err := bp.resolver.CheckPropagation(ctx, domain, recordType, nameservers)

	return BulkResult{
		Domain:    domain,
		Success:   err == nil,
		Error:     err,
		StartTime: startTime,
		EndTime:   time.Now(),
		Data:      result,
	}
}

// processSingleConsistency processes a single domain consistency check
func (bp *BulkProcessor) processSingleConsistency(ctx context.Context, domain string, nameservers []string) BulkResult {
	startTime := time.Now()

	issues, err := bp.consistencyChecker.CheckConsistency(ctx, domain, nameservers)

	// Consider it successful if no error occurred (even if issues were found)
	success := err == nil

	return BulkResult{
		Domain:    domain,
		Success:   success,
		Error:     err,
		StartTime: startTime,
		EndTime:   time.Now(),
		Data:      issues,
	}
}

// isValidDomain performs basic domain validation
func isValidDomain(domain string) bool {
	// Basic validation - can be enhanced
	if domain == "" || len(domain) > 253 {
		return false
	}

	// Check for valid characters
	for _, r := range domain {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-') {
			return false
		}
	}

	// Must contain at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Cannot start or end with dot or hyphen
	if strings.HasPrefix(domain, ".") || strings.HasPrefix(domain, "-") ||
		strings.HasSuffix(domain, ".") || strings.HasSuffix(domain, "-") {
		return false
	}

	return true
}
