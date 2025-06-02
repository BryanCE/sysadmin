// =============================================================================
// internal/cli/ssl_commands.go - SSL-related CLI commands
// =============================================================================
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/bryanCE/sysadmin/internal/output"
	"github.com/bryanCE/sysadmin/internal/ssl"
	"github.com/spf13/cobra"
)

// NewSSLCheckCommand creates the ssl-check subcommand
func NewSSLCheckCommand() *cobra.Command {
	var (
		portFlag   string
		formatFlag string
	)

	cmd := &cobra.Command{
		Use:   "ssl-check [domain]",
		Short: "Check SSL certificate for a domain",
		Long: `Validate SSL/TLS certificate for a given domain.
Checks certificate validity, expiration, issuer information, and more.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]

			// Check certificate
			info, err := ssl.CheckCertificate(domain, portFlag)
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
			return formatter.FormatCertInfo(info, os.Stdout)
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&portFlag, "port", "p", "443", "Port to connect to (default: 443)")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")

	return cmd
}
