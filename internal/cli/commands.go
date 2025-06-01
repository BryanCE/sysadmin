// =============================================================================
// internal/cli/commands.go - CLI command definitions
// =============================================================================
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bryanCE/sysadmin/internal/dns"
	"github.com/bryanCE/sysadmin/internal/output"
	"github.com/bryanCE/sysadmin/pkg/nameservers"
	"github.com/spf13/cobra"
)

// NewQueryCommand creates the query subcommand
func NewQueryCommand() *cobra.Command {
	var (
		nameserverFlag string
		formatFlag     string
	)

	cmd := &cobra.Command{
		Use:   "query [domain] [record-type]",
		Short: "Query DNS records for a domain",
		Long: `Perform DNS queries for a specific domain and record type.
Supports all common record types (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV).`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			recordType := dns.RecordTypeA // Default to A record

			if len(args) > 1 {
				recordType = dns.DNSRecordType(strings.ToUpper(args[1]))
			}

			// Get nameserver
			var ns string
			if nameserverFlag != "" {
				ns = nameserverFlag
			} else {
				defaultNS := nameservers.GetDefaultNameservers()[0]
				ns = defaultNS.IP.String()
			}

			// Create resolver
			resolver := dns.NewResolver()

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Perform query
			result, err := resolver.Query(ctx, domain, recordType, ns)
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
			return formatter.FormatQueryResult(result, os.Stdout)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&nameserverFlag, "nameserver", "n", "", "Nameserver to query (IP address)")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")

	return cmd
}

// NewPropagationCommand creates the propagation subcommand
func NewPropagationCommand() *cobra.Command {
	var (
		providerFlag string
		formatFlag   string
	)

	cmd := &cobra.Command{
		Use:   "propagation [domain] [record-type]",
		Short: "Check DNS propagation across servers",
		Long: `Check DNS propagation status for a domain across multiple nameservers.
Useful for verifying that DNS changes have propagated correctly.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			recordType := dns.RecordTypeA // Default to A record

			if len(args) > 1 {
				recordType = dns.DNSRecordType(strings.ToUpper(args[1]))
			}

			// Get nameservers
			var ns []string
			if providerFlag != "" {
				providers := strings.Split(providerFlag, ",")
				for _, provider := range providers {
					provider = strings.TrimSpace(provider)
					servers := nameservers.GetProviderNameservers(provider)
					if servers != nil {
						for _, server := range servers {
							ns = append(ns, server.IP.String())
						}
					}
				}
			}

			if len(ns) == 0 {
				// Use default nameservers
				defaultServers := nameservers.GetDefaultNameservers()
				for _, server := range defaultServers {
					ns = append(ns, server.IP.String())
				}
			}

			// Create resolver
			resolver := dns.NewResolver()

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Check propagation
			result, err := resolver.CheckPropagation(ctx, domain, recordType, ns)
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
			return formatter.FormatPropagationResult(result, os.Stdout)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&providerFlag, "providers", "p", "", "DNS providers to check (comma-separated: google,cloudflare,quad9,opendns)")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")

	return cmd
}

// NewConsistencyCommand creates the consistency subcommand
func NewConsistencyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "consistency [domain]",
		Short: "Check DNS consistency issues",
		Long: `Perform comprehensive DNS consistency checks for a domain.
Identifies misconfigurations, inconsistencies, and potential problems.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Consistency command executed")
			return nil
		},
	}
	return cmd
}

// NewBulkCommand creates the bulk subcommand
func NewBulkCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bulk [file]",
		Short: "Perform bulk DNS operations",
		Long: `Execute DNS operations on multiple domains from a file.
The file should contain one domain per line.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Bulk command executed")
			return nil
		},
	}
	return cmd
}
