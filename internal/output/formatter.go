// =============================================================================
// internal/output/formatter.go - Output formatting for different formats
// =============================================================================
package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/bryanCE/sysadmin/internal/dns"
)

// OutputFormat represents the output format type
type OutputFormat string

const (
	FormatTable OutputFormat = "table"
	FormatJSON  OutputFormat = "json"
	FormatCSV   OutputFormat = "csv"
	FormatXML   OutputFormat = "xml"
)

// Formatter handles output formatting for different formats
type Formatter struct {
	format OutputFormat
}

// NewFormatter creates a new formatter with the specified format
func NewFormatter(format OutputFormat) *Formatter {
	return &Formatter{format: format}
}

// FormatQueryResult formats a single DNS query result
func (f *Formatter) FormatQueryResult(result *dns.DNSResult, writer io.Writer) error {
	switch f.format {
	case FormatJSON:
		return f.formatQueryResultJSON(result, writer)
	case FormatCSV:
		return f.formatQueryResultCSV(result, writer)
	case FormatXML:
		return f.formatQueryResultXML(result, writer)
	default:
		return f.formatQueryResultTable(result, writer)
	}
}

// FormatPropagationResult formats DNS propagation check results
func (f *Formatter) FormatPropagationResult(result *dns.PropagationResult, writer io.Writer) error {
	switch f.format {
	case FormatJSON:
		return json.NewEncoder(writer).Encode(result)
	case FormatCSV:
		return f.formatPropagationResultCSV(result, writer)
	case FormatXML:
		return xml.NewEncoder(writer).Encode(result)
	default:
		return f.formatPropagationResultTable(result, writer)
	}
}

// FormatConsistencyIssues formats DNS consistency issues
func (f *Formatter) FormatConsistencyIssues(issues []dns.ConsistencyIssue, writer io.Writer) error {
	switch f.format {
	case FormatJSON:
		return json.NewEncoder(writer).Encode(issues)
	case FormatCSV:
		return f.formatConsistencyIssuesCSV(issues, writer)
	case FormatXML:
		return xml.NewEncoder(writer).Encode(issues)
	default:
		return f.formatConsistencyIssuesTable(issues, writer)
	}
}

// FormatBulkResult formats bulk query results
func (f *Formatter) FormatBulkResult(result *dns.BulkQueryResult, writer io.Writer) error {
	switch f.format {
	case FormatJSON:
		return json.NewEncoder(writer).Encode(result)
	case FormatCSV:
		return f.formatBulkResultCSV(result, writer)
	case FormatXML:
		return xml.NewEncoder(writer).Encode(result)
	default:
		return f.formatBulkResultTable(result, writer)
	}
}

// Table formatting methods
func (f *Formatter) formatQueryResultTable(result *dns.DNSResult, writer io.Writer) error {
	if result.Error != nil {
		fmt.Fprintf(writer, "❌ Query failed: %v\n", result.Error)
		return nil
	}

	fmt.Fprintf(writer, "🔍 DNS Query Results for %s (%s)\n", result.Query.Domain, result.Query.RecordType)
	fmt.Fprintf(writer, "📡 Nameserver: %s\n", result.Nameserver)
	fmt.Fprintf(writer, "⏱️  Response time: %v\n", result.ResponseTime)
	fmt.Fprintf(writer, "🕐 Queried at: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	if len(result.Records) == 0 {
		fmt.Fprintf(writer, "No records found.\n")
		return nil
	}

	table := NewTable([]string{"Name", "Type", "Value", "TTL", "Priority"})
	
	for _, record := range result.Records {
		priority := ""
		if record.Priority > 0 {
			priority = fmt.Sprintf("%d", record.Priority)
		}
		
		table.AddRow([]string{
			truncateString(record.Name, 40),
			string(record.Type),
			truncateString(record.Value, 50),
			fmt.Sprintf("%d", record.TTL),
			priority,
		})
	}

	return table.Render(writer)
}

func (f *Formatter) formatPropagationResultTable(result *dns.PropagationResult, writer io.Writer) error {
	fmt.Fprintf(writer, "🌐 DNS Propagation Check for %s (%s)\n", result.Domain, result.RecordType)
	fmt.Fprintf(writer, "📊 Checked %d servers, %d responded successfully\n", result.TotalServers, result.SuccessCount)
	
	if result.Inconsistent {
		fmt.Fprintf(writer, "⚠️  Inconsistencies detected!\n")
	} else {
		fmt.Fprintf(writer, "✅ All servers are consistent\n")
	}
	
	fmt.Fprintf(writer, "🕐 Checked at: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	if len(result.Results) == 0 {
		fmt.Fprintf(writer, "No results to display.\n")
		return nil
	}

	table := NewTable([]string{"Nameserver", "Status", "Records", "Values"})

	for nameserver, records := range result.Results {
		status := "✅ OK"
		recordCount := fmt.Sprintf("%d", len(records))
		
		var values []string
		for _, record := range records {
			values = append(values, record.Value)
		}
		valueStr := strings.Join(values, ", ")
		
		table.AddRow([]string{
			nameserver,
			status,
			recordCount,
			truncateString(valueStr, 60),
		})
	}

	return table.Render(writer)
}

func (f *Formatter) formatConsistencyIssuesTable(issues []dns.ConsistencyIssue, writer io.Writer) error {
	if len(issues) == 0 {
		fmt.Fprintf(writer, "✅ No DNS consistency issues found!\n")
		return nil
	}

	fmt.Fprintf(writer, "🔍 DNS Consistency Issues Found: %d\n\n", len(issues))

	table := NewTable([]string{"Severity", "Type", "Domain", "Record", "Description"})

	for _, issue := range issues {
		severity := ""
		switch issue.Severity {
		case "high":
			severity = "🔴 HIGH"
		case "medium":
			severity = "🟡 MEDIUM"
		case "low":
			severity = "🟢 LOW"
		}

		table.AddRow([]string{
			severity,
			issue.Type,
			issue.Domain,
			string(issue.RecordType),
			truncateString(issue.Description, 50),
		})
	}

	return table.Render(writer)
}

func (f *Formatter) formatBulkResultTable(result *dns.BulkQueryResult, writer io.Writer) error {
	fmt.Fprintf(writer, "📋 Bulk DNS Query Results\n")
	fmt.Fprintf(writer, "📊 Total: %d | ✅ Success: %d | ❌ Failed: %d\n", 
		result.TotalQueries, result.SuccessfulQueries, result.FailedQueries)
	fmt.Fprintf(writer, "⏱️  Duration: %v\n", result.Duration)
	fmt.Fprintf(writer, "🕐 Completed at: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	table := NewTable([]string{"Domain", "Status", "Records", "Response Time"})

	for domain, queryResult := range result.Results {
		status := "✅ OK"
		recordCount := fmt.Sprintf("%d", len(queryResult.Records))
		responseTime := queryResult.ResponseTime.String()

		if queryResult.Error != nil {
			status = "❌ ERROR"
			recordCount = "-"
			responseTime = "-"
		}

		table.AddRow([]string{
			domain,
			status,
			recordCount,
			responseTime,
		})
	}

	return table.Render(writer)
}

// JSON formatting methods
func (f *Formatter) formatQueryResultJSON(result *dns.DNSResult, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// CSV formatting methods
func (f *Formatter) formatQueryResultCSV(result *dns.DNSResult, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"Domain", "RecordType", "Nameserver", "Name", "Type", "Value", "TTL", "Priority", "ResponseTime", "Error"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write records
	for _, record := range result.Records {
		row := []string{
			result.Query.Domain,
			string(result.Query.RecordType),
			result.Nameserver,
			record.Name,
			string(record.Type),
			record.Value,
			fmt.Sprintf("%d", record.TTL),
			fmt.Sprintf("%d", record.Priority),
			result.ResponseTime.String(),
			"",
		}
		
		if result.Error != nil {
			row[len(row)-1] = result.Error.Error()
		}
		
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (f *Formatter) formatPropagationResultCSV(result *dns.PropagationResult, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"Domain", "RecordType", "Nameserver", "RecordName", "RecordValue", "TTL", "Inconsistent"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write data
	for nameserver, records := range result.Results {
		for _, record := range records {
			row := []string{
				result.Domain,
				string(result.RecordType),
				nameserver,
				record.Name,
				record.Value,
				fmt.Sprintf("%d", record.TTL),
				fmt.Sprintf("%t", result.Inconsistent),
			}
			if err := csvWriter.Write(row); err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *Formatter) formatConsistencyIssuesCSV(issues []dns.ConsistencyIssue, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"Type", "Domain", "RecordType", "Severity", "Description", "Servers", "Expected", "Actual"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write data
	for _, issue := range issues {
		row := []string{
			issue.Type,
			issue.Domain,
			string(issue.RecordType),
			issue.Severity,
			issue.Description,
			strings.Join(issue.Servers, ";"),
			issue.Expected,
			issue.Actual,
		}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (f *Formatter) formatBulkResultCSV(result *dns.BulkQueryResult, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"Domain", "Status", "RecordCount", "ResponseTime", "Error"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write data
	for domain, queryResult := range result.Results {
		status := "success"
		recordCount := fmt.Sprintf("%d", len(queryResult.Records))
		responseTime := queryResult.ResponseTime.String()
		errorMsg := ""

		if queryResult.Error != nil {
			status = "error"
			recordCount = "0"
			responseTime = "0"
			errorMsg = queryResult.Error.Error()
		}

		row := []string{domain, status, recordCount, responseTime, errorMsg}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// XML formatting methods
func (f *Formatter) formatQueryResultXML(result *dns.DNSResult, writer io.Writer) error {
	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "  ")
	return encoder.Encode(result)
}

// Utility functions
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
