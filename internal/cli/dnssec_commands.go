// =============================================================================
// internal/cli/dnssec_commands.go - DNSSEC-related CLI commands
// =============================================================================
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/bryanCE/sysadmin/internal/dnssec"
	"github.com/bryanCE/sysadmin/internal/output"
	"github.com/spf13/cobra"
)

// NewDNSSECVerifyCommand creates the dnssec-verify subcommand
func NewDNSSECVerifyCommand() *cobra.Command {
	var (
		nameserverFlag string
		formatFlag     string
	)

	cmd := &cobra.Command{
		Use:   "dnssec-verify [domain]",
		Short: "Verify DNSSEC configuration",
		Long: `Perform comprehensive DNSSEC validation for a domain.
Checks DS records, DNSKEY records, and validates the chain of trust.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]

			// Use default nameserver if not specified
			if nameserverFlag == "" {
				nameserverFlag = "8.8.8.8" // Google's public DNS
			}

			// Verify DNSSEC
			result, err := dnssec.VerifyDNSSEC(domain, nameserverFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return err
			}

			// Format and display results
			var format output.OutputFormat
			switch strings.ToLower(formatFlag) {
			case "json":
				format = output.FormatJSON
			case "csv":
				format = output.FormatCSV
			case "xml":
				format = output.FormatXML
			default:
				format = output.FormatTable
			}

			formatter := output.NewFormatter(format)
			return formatter.FormatDNSSECResult(result, os.Stdout)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&nameserverFlag, "nameserver", "n", "", "Nameserver to query (IP address)")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")

	return cmd
}
