// =============================================================================
// internal/output/ssl_formatter.go - SSL certificate output formatting
// =============================================================================
package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/bryanCE/sysadmin/internal/ssl"
)

// FormatCertInfo formats SSL certificate information
func (f *Formatter) FormatCertInfo(info *ssl.CertInfo, writer io.Writer) error {
	switch f.format {
	case FormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(info)
	case FormatCSV:
		return f.formatCertInfoCSV(info, writer)
	case FormatXML:
		encoder := xml.NewEncoder(writer)
		encoder.Indent("", "  ")
		return encoder.Encode(info)
	default:
		return f.formatCertInfoTable(info, writer)
	}
}

// formatCertInfoTable formats certificate information in a table format
func (f *Formatter) formatCertInfoTable(info *ssl.CertInfo, writer io.Writer) error {
	fmt.Fprintf(writer, "🔒 SSL Certificate Information for %s\n", info.Domain)
	fmt.Fprintf(writer, "----------------------------------------\n\n")

	table := NewTable([]string{"Field", "Value"})

	table.AddRow([]string{"Common Name", info.CommonName})
	table.AddRow([]string{"Issuer", truncateString(info.Issuer, 60)})
	table.AddRow([]string{"Valid From", info.NotBefore.Format("2006-01-02 15:04:05")})
	table.AddRow([]string{"Valid Until", info.NotAfter.Format("2006-01-02 15:04:05")})
	table.AddRow([]string{"Expires In", fmt.Sprintf("%d days", info.ExpiresIn)})
	table.AddRow([]string{"Is Valid", fmt.Sprintf("%t", info.IsValid)})
	table.AddRow([]string{"Serial Number", info.SerialNumber})
	table.AddRow([]string{"Signature Algorithm", info.SignatureAlg})
	table.AddRow([]string{"DNS Names", truncateString(strings.Join(info.DNSNames, ", "), 60)})

	return table.Render(writer)
}

// formatCertInfoCSV formats certificate information in CSV format
func (f *Formatter) formatCertInfoCSV(info *ssl.CertInfo, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
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
