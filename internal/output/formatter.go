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
	"github.com/bryanCE/sysadmin/internal/dnssec"
	"github.com/bryanCE/sysadmin/internal/network"
	"github.com/bryanCE/sysadmin/internal/ssl"
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

// FormatData is a generic method that handles all format types
func (f *Formatter) FormatData(data interface{}, writer io.Writer, tableFormatter func(interface{}, io.Writer) error, csvFormatter func(interface{}, io.Writer) error) error {
	switch f.format {
	case FormatJSON:
		return f.formatJSON(data, writer)
	case FormatCSV:
		if csvFormatter != nil {
			return csvFormatter(data, writer)
		}
		return fmt.Errorf("CSV formatting not implemented for this data type")
	case FormatXML:
		return f.formatXML(data, writer)
	default:
		if tableFormatter != nil {
			return tableFormatter(data, writer)
		}
		return fmt.Errorf("table formatting not implemented for this data type")
	}
}

// Generic JSON formatter
func (f *Formatter) formatJSON(data interface{}, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// Generic XML formatter
func (f *Formatter) formatXML(data interface{}, writer io.Writer) error {
	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "  ")
	return encoder.Encode(data)
}

// CSV writer helper
func (f *Formatter) createCSVWriter(writer io.Writer) *csv.Writer {
	csvWriter := csv.NewWriter(writer)
	return csvWriter
}

// Table helper for creating and rendering tables
func (f *Formatter) createAndRenderTable(headers []string, rows [][]string, writer io.Writer) error {
	table := NewTable(headers)
	for _, row := range rows {
		table.AddRow(row)
	}
	return table.Render(writer)
}

// DNS-specific formatting methods
func (f *Formatter) FormatQueryResult(result *dns.DNSResult, writer io.Writer) error {
	return f.FormatData(result, writer, f.formatQueryResultTable, f.formatQueryResultCSV)
}

func (f *Formatter) FormatPropagationResult(result *dns.PropagationResult, writer io.Writer) error {
	return f.FormatData(result, writer, f.formatPropagationResultTable, f.formatPropagationResultCSV)
}

func (f *Formatter) FormatConsistencyIssues(issues []dns.ConsistencyIssue, writer io.Writer) error {
	return f.FormatData(issues, writer, f.formatConsistencyIssuesTable, f.formatConsistencyIssuesCSV)
}

func (f *Formatter) FormatBulkResult(result *dns.BulkQueryResult, writer io.Writer) error {
	return f.FormatData(result, writer, f.formatBulkResultTable, f.formatBulkResultCSV)
}

func (f *Formatter) FormatBulkSummary(summary *dns.BulkSummary, writer io.Writer) error {
	return f.FormatData(summary, writer, f.formatBulkSummaryTable, f.formatBulkSummaryCSV)
}

// SSL-specific formatting methods
func (f *Formatter) FormatCertInfo(info *ssl.CertInfo, writer io.Writer) error {
	return f.FormatData(info, writer, f.formatCertInfoTable, f.formatCertInfoCSV)
}

// Network-specific formatting methods
func (f *Formatter) FormatScanResult(result *network.ScanResult, writer io.Writer) error {
	return f.FormatData(result, writer, f.formatScanResultTable, f.formatScanResultCSV)
}

func (f *Formatter) FormatHostResult(result *network.HostResult, writer io.Writer) error {
	return f.FormatData(result, writer, f.formatHostResultTable, f.formatHostResultCSV)
}

// DNSSEC-specific formatting methods
func (f *Formatter) FormatDNSSECResult(result *dnssec.ValidationResult, writer io.Writer) error {
	return f.FormatData(result, writer, f.formatDNSSECResultTable, f.formatDNSSECResultCSV)
}

// Table formatting methods
func (f *Formatter) formatQueryResultTable(data interface{}, writer io.Writer) error {
	result := data.(*dns.DNSResult)
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

	var rows [][]string
	for _, record := range result.Records {
		priority := ""
		if record.Priority > 0 {
			priority = fmt.Sprintf("%d", record.Priority)
		}

		rows = append(rows, []string{
			truncateString(record.Name, 40),
			string(record.Type),
			truncateString(record.Value, 50),
			fmt.Sprintf("%d", record.TTL),
			priority,
		})
	}

	return f.createAndRenderTable([]string{"Name", "Type", "Value", "TTL", "Priority"}, rows, writer)
}

func (f *Formatter) formatPropagationResultTable(data interface{}, writer io.Writer) error {
	result := data.(*dns.PropagationResult)
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

	var rows [][]string
	for nameserver, records := range result.Results {
		status := "✅ OK"
		recordCount := fmt.Sprintf("%d", len(records))

		var values []string
		for _, record := range records {
			values = append(values, record.Value)
		}
		valueStr := strings.Join(values, ", ")

		rows = append(rows, []string{
			nameserver,
			status,
			recordCount,
			truncateString(valueStr, 60),
		})
	}

	return f.createAndRenderTable([]string{"Nameserver", "Status", "Records", "Values"}, rows, writer)
}

func (f *Formatter) formatConsistencyIssuesTable(data interface{}, writer io.Writer) error {
	issues := data.([]dns.ConsistencyIssue)
	if len(issues) == 0 {
		fmt.Fprintf(writer, "✅ No DNS consistency issues found!\n")
		return nil
	}

	fmt.Fprintf(writer, "🔍 DNS Consistency Issues Found: %d\n\n", len(issues))

	var rows [][]string
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

		rows = append(rows, []string{
			severity,
			issue.Type,
			issue.Domain,
			string(issue.RecordType),
			truncateString(issue.Description, 50),
		})
	}

	return f.createAndRenderTable([]string{"Severity", "Type", "Domain", "Record", "Description"}, rows, writer)
}

func (f *Formatter) formatBulkResultTable(data interface{}, writer io.Writer) error {
	result := data.(*dns.BulkQueryResult)
	fmt.Fprintf(writer, "📋 Bulk DNS Query Results\n")
	fmt.Fprintf(writer, "📊 Total: %d | ✅ Success: %d | ❌ Failed: %d\n",
		result.TotalQueries, result.SuccessfulQueries, result.FailedQueries)
	fmt.Fprintf(writer, "⏱️  Duration: %v\n", result.Duration)
	fmt.Fprintf(writer, "🕐 Completed at: %s\n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	var rows [][]string
	for domain, queryResult := range result.Results {
		status := "✅ OK"
		recordCount := fmt.Sprintf("%d", len(queryResult.Records))
		responseTime := queryResult.ResponseTime.String()

		if queryResult.Error != nil {
			status = "❌ ERROR"
			recordCount = "-"
			responseTime = "-"
		}

		rows = append(rows, []string{
			domain,
			status,
			recordCount,
			responseTime,
		})
	}

	return f.createAndRenderTable([]string{"Domain", "Status", "Records", "Response Time"}, rows, writer)
}

func (f *Formatter) formatBulkSummaryTable(data interface{}, writer io.Writer) error {
	summary := data.(*dns.BulkSummary)
	fmt.Fprintf(writer, "\n📋 Bulk Operation Summary\n")
	fmt.Fprintf(writer, "📊 Total: %d | ✅ Success: %d | ❌ Failed: %d\n",
		summary.TotalDomains, summary.Successful, summary.Failed)
	fmt.Fprintf(writer, "⏱️  Duration: %v\n\n", summary.Duration)

	if len(summary.Results) == 0 {
		fmt.Fprintf(writer, "No results to display.\n")
		return nil
	}

	var rows [][]string
	for _, result := range summary.Results {
		status := "✅ OK"
		resultStr := "Success"
		if !result.Success {
			status = "❌ ERROR"
			if result.Error != nil {
				resultStr = result.Error.Error()
			} else {
				resultStr = "Failed"
			}
		}

		duration := result.EndTime.Sub(result.StartTime)

		rows = append(rows, []string{
			truncateString(result.Domain, 30),
			status,
			truncateString(resultStr, 40),
			duration.String(),
		})
	}

	return f.createAndRenderTable([]string{"Domain", "Status", "Result", "Duration"}, rows, writer)
}

func (f *Formatter) formatCertInfoTable(data interface{}, writer io.Writer) error {
	info := data.(*ssl.CertInfo)
	fmt.Fprintf(writer, "🔒 SSL Certificate Information for %s\n", info.Domain)
	fmt.Fprintf(writer, "----------------------------------------\n\n")

	rows := [][]string{
		{"Common Name", info.CommonName},
		{"Issuer", truncateString(info.Issuer, 60)},
		{"Valid From", info.NotBefore.Format("2006-01-02 15:04:05")},
		{"Valid Until", info.NotAfter.Format("2006-01-02 15:04:05")},
		{"Expires In", fmt.Sprintf("%d days", info.ExpiresIn)},
		{"Is Valid", fmt.Sprintf("%t", info.IsValid)},
		{"Serial Number", info.SerialNumber},
		{"Signature Algorithm", info.SignatureAlg},
		{"DNS Names", truncateString(strings.Join(info.DNSNames, ", "), 60)},
	}

	return f.createAndRenderTable([]string{"Field", "Value"}, rows, writer)
}

func (f *Formatter) formatScanResultTable(data interface{}, writer io.Writer) error {
	result := data.(*network.ScanResult)
	fmt.Fprintf(writer, "🔍 Network Discovery Results for %s\n", result.Network)
	fmt.Fprintf(writer, "📊 Found %d live hosts out of %d scanned\n", result.Summary.LiveHosts, result.Summary.TotalHosts)
	fmt.Fprintf(writer, "⏱️  Duration: %v\n", result.Duration)
	fmt.Fprintf(writer, "🕐 Completed at: %s\n\n", result.StartTime.Add(result.Duration).Format("2006-01-02 15:04:05"))

	if len(result.Hosts) == 0 {
		fmt.Fprintf(writer, "No live hosts found.\n")
		return nil
	}

	for _, host := range result.Hosts {
		fmt.Fprintf(writer, "🖥️  %s\n", host.IP)
		if len(host.Ports) > 0 {
			for _, port := range host.Ports {
				service := port.Service
				if service == "" {
					service = "Unknown"
				}
				fmt.Fprintf(writer, "   🟢 %-5d %-12s", port.Port, service)
				if port.Banner != "" {
					fmt.Fprintf(writer, " - %s", port.Banner)
				}
				fmt.Fprintf(writer, "\n")
			}
		} else {
			fmt.Fprintf(writer, "   📝 Host alive but no open ports found in scanned range\n")
		}
		fmt.Fprintf(writer, "\n")
	}

	return nil
}

func (f *Formatter) formatHostResultTable(data interface{}, writer io.Writer) error {
	result := data.(*network.HostResult)
	fmt.Fprintf(writer, "🔍 Port Scan Results for %s\n", result.IP)
	fmt.Fprintf(writer, "📊 Found %d open ports\n\n", len(result.Ports))

	if len(result.Ports) == 0 {
		fmt.Fprintf(writer, "No open ports found.\n")
		return nil
	}

	for _, port := range result.Ports {
		service := port.Service
		if service == "" {
			service = "Unknown"
		}
		fmt.Fprintf(writer, "🟢 Port %-5d %-12s", port.Port, service)
		if port.Banner != "" {
			fmt.Fprintf(writer, " - %s", port.Banner)
		}
		fmt.Fprintf(writer, "\n")
	}

	return nil
}

func (f *Formatter) formatDNSSECResultTable(data interface{}, writer io.Writer) error {
	result := data.(*dnssec.ValidationResult)
	fmt.Fprintf(writer, "🔐 DNSSEC Validation Results for %s\n", result.Domain)
	fmt.Fprintf(writer, "----------------------------------------\n\n")

	rows := [][]string{
		{"Has DNSSEC", fmt.Sprintf("%t", result.HasDNSSEC)},
		{"Is Signed", fmt.Sprintf("%t", result.IsSigned)},
		{"Is Valid", fmt.Sprintf("%t", result.IsValid)},
		{"Checked At", result.Timestamp.Format("2006-01-02 15:04:05")},
	}

	if len(result.ValidationErrors) > 0 {
		rows = append(rows, []string{"Validation Errors", strings.Join(result.ValidationErrors, "\n")})
	}

	if err := f.createAndRenderTable([]string{"Property", "Value"}, rows, writer); err != nil {
		return err
	}

	// DS Record details
	if result.DS != nil {
		fmt.Fprintf(writer, "\n🔑 DS Record Details\n")
		fmt.Fprintf(writer, "----------------------------------------\n")

		dsRows := [][]string{
			{"Key Tag", fmt.Sprintf("%d", result.DS.KeyTag)},
			{"Algorithm", fmt.Sprintf("%d", result.DS.Algorithm)},
			{"Digest Type", fmt.Sprintf("%d", result.DS.DigestType)},
			{"Digest", result.DS.Digest},
		}

		if err := f.createAndRenderTable([]string{"Property", "Value"}, dsRows, writer); err != nil {
			return err
		}
	}

	// DNSKEY Records
	if len(result.DNSKEY) > 0 {
		fmt.Fprintf(writer, "\n🔑 DNSKEY Records\n")
		fmt.Fprintf(writer, "----------------------------------------\n")

		var dnskeyRows [][]string
		for _, key := range result.DNSKEY {
			keyType := "Unknown"
			if key.Flags&256 != 0 {
				keyType = "Zone Signing Key (ZSK)"
			} else if key.Flags&257 != 0 {
				keyType = "Key Signing Key (KSK)"
			}

			dnskeyRows = append(dnskeyRows, []string{
				fmt.Sprintf("%d", key.Flags),
				fmt.Sprintf("%d", key.Protocol),
				fmt.Sprintf("%d", key.Algorithm),
				keyType,
			})
		}

		if err := f.createAndRenderTable([]string{"Flags", "Protocol", "Algorithm", "Key Type"}, dnskeyRows, writer); err != nil {
			return err
		}
	}

	// RRSIG Records
	if len(result.RRSIG) > 0 {
		fmt.Fprintf(writer, "\n✍️  RRSIG Records\n")
		fmt.Fprintf(writer, "----------------------------------------\n")

		var rrsigRows [][]string
		for _, sig := range result.RRSIG {
			rrsigRows = append(rrsigRows, []string{
				fmt.Sprintf("%d", sig.TypeCovered),
				fmt.Sprintf("%d", sig.Algorithm),
				fmt.Sprintf("%d", sig.Labels),
				fmt.Sprintf("%d", sig.TTL),
				sig.Expiration.Format("2006-01-02 15:04:05"),
				sig.Inception.Format("2006-01-02 15:04:05"),
			})
		}

		if err := f.createAndRenderTable([]string{"Type Covered", "Algorithm", "Labels", "TTL", "Expiration", "Inception"}, rrsigRows, writer); err != nil {
			return err
		}
	}

	return nil
}

// CSV formatting methods
func (f *Formatter) formatQueryResultCSV(data interface{}, writer io.Writer) error {
	result := data.(*dns.DNSResult)
	csvWriter := f.createCSVWriter(writer)
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

func (f *Formatter) formatPropagationResultCSV(data interface{}, writer io.Writer) error {
	result := data.(*dns.PropagationResult)
	csvWriter := f.createCSVWriter(writer)
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

func (f *Formatter) formatConsistencyIssuesCSV(data interface{}, writer io.Writer) error {
	issues := data.([]dns.ConsistencyIssue)
	csvWriter := f.createCSVWriter(writer)
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

func (f *Formatter) formatBulkResultCSV(data interface{}, writer io.Writer) error {
	result := data.(*dns.BulkQueryResult)
	csvWriter := f.createCSVWriter(writer)
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

func (f *Formatter) formatBulkSummaryCSV(data interface{}, writer io.Writer) error {
	summary := data.(*dns.BulkSummary)
	csvWriter := f.createCSVWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"Domain", "Status", "Success", "Error", "StartTime", "EndTime", "Duration"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write data
	for _, result := range summary.Results {
		status := "success"
		errorMsg := ""
		if !result.Success {
			status = "error"
			if result.Error != nil {
				errorMsg = result.Error.Error()
			}
		}

		duration := result.EndTime.Sub(result.StartTime)

		row := []string{
			result.Domain,
			status,
			fmt.Sprintf("%t", result.Success),
			errorMsg,
			result.StartTime.Format("2006-01-02 15:04:05"),
			result.EndTime.Format("2006-01-02 15:04:05"),
			duration.String(),
		}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (f *Formatter) formatCertInfoCSV(data interface{}, writer io.Writer) error {
	info := data.(*ssl.CertInfo)
	csvWriter := f.createCSVWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{
		"Domain",
		"CommonName",
		"Issuer",
		"ValidFrom",
		"ValidUntil",
		"ExpiresIn",
		"IsValid",
		"SerialNumber",
		"SignatureAlgorithm",
		"DNSNames",
	}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write data
	row := []string{
		info.Domain,
		info.CommonName,
		info.Issuer,
		info.NotBefore.Format("2006-01-02 15:04:05"),
		info.NotAfter.Format("2006-01-02 15:04:05"),
		fmt.Sprintf("%d", info.ExpiresIn),
		fmt.Sprintf("%t", info.IsValid),
		info.SerialNumber,
		info.SignatureAlg,
		strings.Join(info.DNSNames, ";"),
	}
	return csvWriter.Write(row)
}

func (f *Formatter) formatScanResultCSV(data interface{}, writer io.Writer) error {
	result := data.(*network.ScanResult)
	csvWriter := f.createCSVWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"Network", "IP", "Alive", "Port", "Open", "Service", "Banner", "Duration", "TotalHosts", "LiveHosts"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write data
	for _, host := range result.Hosts {
		if len(host.Ports) > 0 {
			for _, port := range host.Ports {
				row := []string{
					result.Network,
					host.IP,
					fmt.Sprintf("%t", host.Alive),
					fmt.Sprintf("%d", port.Port),
					fmt.Sprintf("%t", port.Open),
					port.Service,
					port.Banner,
					result.Duration.String(),
					fmt.Sprintf("%d", result.Summary.TotalHosts),
					fmt.Sprintf("%d", result.Summary.LiveHosts),
				}
				if err := csvWriter.Write(row); err != nil {
					return err
				}
			}
		} else {
			// Host alive but no open ports
			row := []string{
				result.Network,
				host.IP,
				fmt.Sprintf("%t", host.Alive),
				"-",
				"false",
				"-",
				"-",
				result.Duration.String(),
				fmt.Sprintf("%d", result.Summary.TotalHosts),
				fmt.Sprintf("%d", result.Summary.LiveHosts),
			}
			if err := csvWriter.Write(row); err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *Formatter) formatHostResultCSV(data interface{}, writer io.Writer) error {
	result := data.(*network.HostResult)
	csvWriter := f.createCSVWriter(writer)
	defer csvWriter.Flush()

	// Write header
	header := []string{"IP", "Alive", "Port", "Open", "Service", "Banner"}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	// Write data
	for _, port := range result.Ports {
		row := []string{
			result.IP,
			fmt.Sprintf("%t", result.Alive),
			fmt.Sprintf("%d", port.Port),
			fmt.Sprintf("%t", port.Open),
			port.Service,
			port.Banner,
		}
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (f *Formatter) formatDNSSECResultCSV(data interface{}, writer io.Writer) error {
	result := data.(*dnssec.ValidationResult)
	csvWriter := f.createCSVWriter(writer)
	defer csvWriter.Flush()

	// Write basic info
	header := []string{
		"Domain",
		"HasDNSSEC",
		"IsSigned",
		"IsValid",
		"ValidationErrors",
		"CheckedAt",
	}
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	row := []string{
		result.Domain,
		fmt.Sprintf("%t", result.HasDNSSEC),
		fmt.Sprintf("%t", result.IsSigned),
		fmt.Sprintf("%t", result.IsValid),
		strings.Join(result.ValidationErrors, "; "),
		result.Timestamp.Format("2006-01-02 15:04:05"),
	}
	if err := csvWriter.Write(row); err != nil {
		return err
	}

	// Write DS record
	if result.DS != nil {
		if err := csvWriter.Write([]string{"", "DS Record Details"}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"KeyTag", "Algorithm", "DigestType", "Digest"}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{
			fmt.Sprintf("%d", result.DS.KeyTag),
			fmt.Sprintf("%d", result.DS.Algorithm),
			fmt.Sprintf("%d", result.DS.DigestType),
			result.DS.Digest,
		}); err != nil {
			return err
		}
	}

	// Write DNSKEY records
	if len(result.DNSKEY) > 0 {
		if err := csvWriter.Write([]string{"", "DNSKEY Records"}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{"Flags", "Protocol", "Algorithm", "PublicKey"}); err != nil {
			return err
		}
		for _, key := range result.DNSKEY {
			if err := csvWriter.Write([]string{
				fmt.Sprintf("%d", key.Flags),
				fmt.Sprintf("%d", key.Protocol),
				fmt.Sprintf("%d", key.Algorithm),
				key.PublicKey,
			}); err != nil {
				return err
			}
		}
	}

	// Write RRSIG records
	if len(result.RRSIG) > 0 {
		if err := csvWriter.Write([]string{"", "RRSIG Records"}); err != nil {
			return err
		}
		if err := csvWriter.Write([]string{
			"TypeCovered",
			"Algorithm",
			"Labels",
			"TTL",
			"Expiration",
			"Inception",
			"KeyTag",
			"SignerName",
		}); err != nil {
			return err
		}
		for _, sig := range result.RRSIG {
			if err := csvWriter.Write([]string{
				fmt.Sprintf("%d", sig.TypeCovered),
				fmt.Sprintf("%d", sig.Algorithm),
				fmt.Sprintf("%d", sig.Labels),
				fmt.Sprintf("%d", sig.TTL),
				sig.Expiration.Format("2006-01-02 15:04:05"),
				sig.Inception.Format("2006-01-02 15:04:05"),
				fmt.Sprintf("%d", sig.KeyTag),
				sig.SignerName,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

// Utility functions
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
