package main

import (
	"fmt"
	"os"

	"github.com/bryanCE/sysadmin/internal/cli"

	"github.com/spf13/cobra"
)

var version = "dev" // Will be set by ldflags during build

func main() {
	rootCmd := &cobra.Command{
		Use:   "dns-tool",
		Short: "DNS & SSL Swiss Army Knife - Advanced DNS and SSL analysis tool",
		Long: `A comprehensive tool for network administrators and security professionals.
Features include DNS querying, propagation checking, DNS inconsistency detection,
and SSL certificate validation and analysis.`,
		Version: version,
	}

	// Add DNS subcommands
	rootCmd.AddCommand(cli.NewQueryCommand())
	rootCmd.AddCommand(cli.NewPropagationCommand())
	rootCmd.AddCommand(cli.NewConsistencyCommand())
	rootCmd.AddCommand(cli.NewBulkCommand())

	// Add SSL subcommands
	rootCmd.AddCommand(cli.NewSSLCheckCommand())

	// Add DNSSEC subcommands
	rootCmd.AddCommand(cli.NewDNSSECVerifyCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
