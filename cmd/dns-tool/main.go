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
		Short: "DNS Swiss Army Knife - Advanced DNS querying and analysis tool",
		Long: `A comprehensive DNS tool for network administrators and security professionals.
Features include multi-nameserver queries, propagation checking, and DNS inconsistency detection.`,
		Version: version,
	}

	// Add subcommands
	rootCmd.AddCommand(cli.NewQueryCommand())
	rootCmd.AddCommand(cli.NewPropagationCommand())
	rootCmd.AddCommand(cli.NewConsistencyCommand())
	rootCmd.AddCommand(cli.NewBulkCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}