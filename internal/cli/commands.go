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
				if strings.TrimSpace(strings.ToLower(providerFlag)) == "all" {
					// Use all available nameservers
					allServers := nameservers.GetAllNameservers()
					for _, server := range allServers {
						ns = append(ns, server.IP.String())
					}
				} else {
					providers := strings.Split(providerFlag, ",")
					for _, provider := range providers {
						provider = strings.TrimSpace(provider)
						servers := nameservers.GetProviderNameservers(provider)
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
	cmd.Flags().StringVarP(&providerFlag, "providers", "p", "", "DNS providers to check (comma-separated: google,cloudflare,quad9,opendns) or 'all' for all providers")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")

	return cmd
}

// NewConsistencyCommand creates the consistency subcommand
func NewConsistencyCommand() *cobra.Command {
	var (
		providerFlag string
		formatFlag   string
	)

	cmd := &cobra.Command{
		Use:   "consistency [domain]",
		Short: "Check DNS consistency issues",
		Long: `Perform comprehensive DNS consistency checks for a domain.
Identifies misconfigurations, inconsistencies, and potential problems.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]

			// Get nameservers
			var ns []string
			if providerFlag != "" {
				if strings.TrimSpace(strings.ToLower(providerFlag)) == "all" {
					// Use all available nameservers
					allServers := nameservers.GetAllNameservers()
					for _, server := range allServers {
						ns = append(ns, server.IP.String())
					}
				} else {
					providers := strings.Split(providerFlag, ",")
					for _, provider := range providers {
						provider = strings.TrimSpace(provider)
						servers := nameservers.GetProviderNameservers(provider)
						for _, server := range servers {
							ns = append(ns, server.IP.String())
						}
					}
				}
			}

			if len(ns) == 0 {
				// Use all nameservers for comprehensive check
				allServers := nameservers.GetAllNameservers()
				for _, server := range allServers {
					ns = append(ns, server.IP.String())
				}
			}

			// Create resolver and checker
			resolver := dns.NewResolver()
			checker := dns.NewConsistencyChecker(resolver)

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			// Check consistency
			issues, err := checker.CheckConsistency(ctx, domain, ns)
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
			return formatter.FormatConsistencyIssues(issues, os.Stdout)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&providerFlag, "providers", "p", "", "DNS providers to check (comma-separated: google,cloudflare,quad9,opendns) or 'all' for all providers")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")

	return cmd
}

// NewBulkCommand creates the bulk subcommand
func NewBulkCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bulk",
		Short: "Perform bulk DNS operations",
		Long: `Execute DNS operations on multiple domains from a file.
The file should contain one domain per line.`,
	}

	// Add subcommands
	cmd.AddCommand(NewBulkQueryCommand())
	cmd.AddCommand(NewBulkPropagationCommand())
	cmd.AddCommand(NewBulkConsistencyCommand())

	return cmd
}

// NewBulkQueryCommand creates the bulk query subcommand
func NewBulkQueryCommand() *cobra.Command {
	var (
		nameserverFlag  string
		formatFlag      string
		concurrencyFlag int
	)

	cmd := &cobra.Command{
		Use:   "query [file] [record-type]",
		Short: "Perform bulk DNS queries",
		Long: `Query DNS records for multiple domains from a file.
The file should contain one domain per line.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filename := args[0]
			recordType := dns.RecordTypeA // Default to A record

			if len(args) > 1 {
				recordType = dns.DNSRecordType(strings.ToUpper(args[1]))
			}

			// Read domains from file
			domains, err := dns.ReadDomainsFromFile(filename)
			if err != nil {
				return fmt.Errorf("failed to read domains: %w", err)
			}

			// Get nameserver
			var ns []string
			if nameserverFlag != "" {
				ns = []string{nameserverFlag}
			} else {
				defaultNS := nameservers.GetDefaultNameservers()[0]
				ns = []string{defaultNS.IP.String()}
			}

			// Create resolver and bulk processor
			resolver := dns.NewResolver()
			processor := dns.NewBulkProcessor(resolver, concurrencyFlag)

			// Set progress callback
			processor.SetProgressCallback(func(current, total int, domain string, success bool) {
				status := "✓"
				if !success {
					status = "✗"
				}
				fmt.Printf("\r[%d/%d] %s %s", current, total, domain, status)
				if current == total {
					fmt.Println() // New line after completion
				}
			})

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			fmt.Printf("Processing %d domains...\n", len(domains))

			// Process bulk query
			summary, err := processor.ProcessQuery(ctx, domains, recordType, ns)
			if err != nil {
				return fmt.Errorf("bulk query failed: %w", err)
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
			return formatter.FormatBulkSummary(summary, os.Stdout)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&nameserverFlag, "nameserver", "n", "", "Nameserver to query (IP address)")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")
	cmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 5, "Number of concurrent queries")

	return cmd
}

// NewBulkPropagationCommand creates the bulk propagation subcommand
func NewBulkPropagationCommand() *cobra.Command {
	var (
		providerFlag    string
		formatFlag      string
		concurrencyFlag int
	)

	cmd := &cobra.Command{
		Use:   "propagation [file] [record-type]",
		Short: "Check DNS propagation for multiple domains",
		Long: `Check DNS propagation status for multiple domains from a file.
The file should contain one domain per line.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filename := args[0]
			recordType := dns.RecordTypeA // Default to A record

			if len(args) > 1 {
				recordType = dns.DNSRecordType(strings.ToUpper(args[1]))
			}

			// Read domains from file
			domains, err := dns.ReadDomainsFromFile(filename)
			if err != nil {
				return fmt.Errorf("failed to read domains: %w", err)
			}

			// Get nameservers
			var ns []string
			if providerFlag != "" {
				if strings.TrimSpace(strings.ToLower(providerFlag)) == "all" {
					// Use all available nameservers
					allServers := nameservers.GetAllNameservers()
					for _, server := range allServers {
						ns = append(ns, server.IP.String())
					}
				} else {
					providers := strings.Split(providerFlag, ",")
					for _, provider := range providers {
						provider = strings.TrimSpace(provider)
						servers := nameservers.GetProviderNameservers(provider)
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

			// Create resolver and bulk processor
			resolver := dns.NewResolver()
			processor := dns.NewBulkProcessor(resolver, concurrencyFlag)

			// Set progress callback
			processor.SetProgressCallback(func(current, total int, domain string, success bool) {
				status := "✓"
				if !success {
					status = "✗"
				}
				fmt.Printf("\r[%d/%d] %s %s", current, total, domain, status)
				if current == total {
					fmt.Println() // New line after completion
				}
			})

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			fmt.Printf("Processing %d domains...\n", len(domains))

			// Process bulk propagation
			summary, err := processor.ProcessPropagation(ctx, domains, recordType, ns)
			if err != nil {
				return fmt.Errorf("bulk propagation check failed: %w", err)
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
			return formatter.FormatBulkSummary(summary, os.Stdout)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&providerFlag, "providers", "p", "", "DNS providers to check (comma-separated: google,cloudflare,quad9,opendns) or 'all' for all providers")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")
	cmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 3, "Number of concurrent checks")

	return cmd
}

// NewBulkConsistencyCommand creates the bulk consistency subcommand
func NewBulkConsistencyCommand() *cobra.Command {
	var (
		providerFlag    string
		formatFlag      string
		concurrencyFlag int
	)

	cmd := &cobra.Command{
		Use:   "consistency [file]",
		Short: "Check DNS consistency for multiple domains",
		Long: `Check DNS consistency for multiple domains from a file.
The file should contain one domain per line.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filename := args[0]

			// Read domains from file
			domains, err := dns.ReadDomainsFromFile(filename)
			if err != nil {
				return fmt.Errorf("failed to read domains: %w", err)
			}

			// Get nameservers
			var ns []string
			if providerFlag != "" {
				if strings.TrimSpace(strings.ToLower(providerFlag)) == "all" {
					// Use all available nameservers
					allServers := nameservers.GetAllNameservers()
					for _, server := range allServers {
						ns = append(ns, server.IP.String())
					}
				} else {
					providers := strings.Split(providerFlag, ",")
					for _, provider := range providers {
						provider = strings.TrimSpace(provider)
						servers := nameservers.GetProviderNameservers(provider)
						for _, server := range servers {
							ns = append(ns, server.IP.String())
						}
					}
				}
			}

			if len(ns) == 0 {
				// Use all nameservers for comprehensive check
				allServers := nameservers.GetAllNameservers()
				for _, server := range allServers {
					ns = append(ns, server.IP.String())
				}
			}

			// Create resolver and bulk processor
			resolver := dns.NewResolver()
			processor := dns.NewBulkProcessor(resolver, concurrencyFlag)

			// Set progress callback
			processor.SetProgressCallback(func(current, total int, domain string, success bool) {
				status := "✓"
				if !success {
					status = "✗"
				}
				fmt.Printf("\r[%d/%d] %s %s", current, total, domain, status)
				if current == total {
					fmt.Println() // New line after completion
				}
			})

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			fmt.Printf("Processing %d domains...\n", len(domains))

			// Process bulk consistency
			summary, err := processor.ProcessConsistency(ctx, domains, ns)
			if err != nil {
				return fmt.Errorf("bulk consistency check failed: %w", err)
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
			return formatter.FormatBulkSummary(summary, os.Stdout)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&providerFlag, "providers", "p", "", "DNS providers to check (comma-separated: google,cloudflare,quad9,opendns) or 'all' for all providers")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")
	cmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 2, "Number of concurrent checks")

	return cmd
}
