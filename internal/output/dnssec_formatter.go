// =============================================================================
// internal/output/dnssec_formatter.go - DNSSEC validation output formatting
// =============================================================================
package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bryanCE/sysadmin/internal/dnssec"
)

// FormatDNSSECResult formats DNSSEC validation results
func (f *Formatter) FormatDNSSECResult(result *dnssec.ValidationResult, writer io.Writer) error {
	switch f.format {
	case FormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	case FormatCSV:
		return f.formatDNSSECResultCSV(result, writer)
	case FormatXML:
		encoder := xml.NewEncoder(writer)
		encoder.Indent("", "  ")
		return encoder.Encode(result)
	default:
		return f.formatDNSSECResultTable(result, writer)
	}
}

// formatDNSSECResultTable formats DNSSEC validation results in a table format
func (f *Formatter) formatDNSSECResultTable(result *dnssec.ValidationResult, writer io.Writer) error {
	fmt.Fprintf(writer, "🔐 DNSSEC Validation Results for %s\n", result.Domain)
	fmt.Fprintf(writer, "----------------------------------------\n\n")

	table := NewTable([]string{"Property", "Value"})

	// Basic DNSSEC status
	table.AddRow([]string{"Has DNSSEC", fmt.Sprintf("%t", result.HasDNSSEC)})
	table.AddRow([]string{"Is Signed", fmt.Sprintf("%t", result.IsSigned)})
	table.AddRow([]string{"Is Valid", fmt.Sprintf("%t", result.IsValid)})
	table.AddRow([]string{"Checked At", result.Timestamp.Format(time.RFC3339)})

	if len(result.ValidationErrors) > 0 {
		table.AddRow([]string{"Validation Errors", strings.Join(result.ValidationErrors, "\n")})
	}

	if err := table.Render(writer); err != nil {
		return err
	}

	// DS Record details
	if result.DS != nil {
		fmt.Fprintf(writer, "\n🔑 DS Record Details\n")
		fmt.Fprintf(writer, "----------------------------------------\n")

		dsTable := NewTable([]string{"Property", "Value"})
		dsTable.AddRow([]string{"Key Tag", fmt.Sprintf("%d", result.DS.KeyTag)})
		dsTable.AddRow([]string{"Algorithm", fmt.Sprintf("%d", result.DS.Algorithm)})
		dsTable.AddRow([]string{"Digest Type", fmt.Sprintf("%d", result.DS.DigestType)})
		dsTable.AddRow([]string{"Digest", result.DS.Digest})

		if err := dsTable.Render(writer); err != nil {
			return err
		}
	}

	// DNSKEY Records
	if len(result.DNSKEY) > 0 {
		fmt.Fprintf(writer, "\n🔑 DNSKEY Records\n")
		fmt.Fprintf(writer, "----------------------------------------\n")

		dnskeyTable := NewTable([]string{"Flags", "Protocol", "Algorithm", "Key Type"})
		for _, key := range result.DNSKEY {
			keyType := "Unknown"
			if key.Flags&256 != 0 {
				keyType = "Zone Signing Key (ZSK)"
			} else if key.Flags&257 != 0 {
				keyType = "Key Signing Key (KSK)"
			}

			dnskeyTable.AddRow([]string{
				fmt.Sprintf("%d", key.Flags),
				fmt.Sprintf("%d", key.Protocol),
				fmt.Sprintf("%d", key.Algorithm),
				keyType,
			})
		}

		if err := dnskeyTable.Render(writer); err != nil {
			return err
		}
	}

	// RRSIG Records
	if len(result.RRSIG) > 0 {
		fmt.Fprintf(writer, "\n✍️  RRSIG Records\n")
		fmt.Fprintf(writer, "----------------------------------------\n")

		rrsigTable := NewTable([]string{"Type Covered", "Algorithm", "Labels", "TTL", "Expiration", "Inception"})
		for _, sig := range result.RRSIG {
			rrsigTable.AddRow([]string{
				fmt.Sprintf("%d", sig.TypeCovered),
				fmt.Sprintf("%d", sig.Algorithm),
				fmt.Sprintf("%d", sig.Labels),
				fmt.Sprintf("%d", sig.TTL),
				sig.Expiration.Format(time.RFC3339),
				sig.Inception.Format(time.RFC3339),
			})
		}

		if err := rrsigTable.Render(writer); err != nil {
			return err
		}
	}

	return nil
}

// formatDNSSECResultCSV formats DNSSEC validation results in CSV format
func (f *Formatter) formatDNSSECResultCSV(result *dnssec.ValidationResult, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
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
		result.Timestamp.Format(time.RFC3339),
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
				sig.Expiration.Format(time.RFC3339),
				sig.Inception.Format(time.RFC3339),
				fmt.Sprintf("%d", sig.KeyTag),
				sig.SignerName,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}
