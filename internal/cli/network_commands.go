// =============================================================================
// internal/cli/network_commands.go - Network scanning CLI commands
// =============================================================================
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bryanCE/sysadmin/internal/network"
	"github.com/bryanCE/sysadmin/internal/output"
	"github.com/spf13/cobra"
)

// NewNetworkCommand creates the network subcommand
func NewNetworkCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Network discovery and port scanning tools",
		Long: `Network scanning and discovery tools for system administrators.
Includes ping sweeps, port scanning, and network discovery functionality.`,
	}

	// Add subcommands
	cmd.AddCommand(NewPingSweepCommand())
	cmd.AddCommand(NewPortScanCommand())
	cmd.AddCommand(NewDiscoveryCommand())
	cmd.AddCommand(NewWorkerPoolDiscoveryCommand())
	cmd.AddCommand(NewMonitorCommand())

	return cmd
}

// NewPingSweepCommand creates the ping sweep subcommand
func NewPingSweepCommand() *cobra.Command {
	var (
		formatFlag      string
		timeoutFlag     string
		concurrencyFlag int
	)

	cmd := &cobra.Command{
		Use:   "ping [network]",
		Short: "Perform ping sweep to discover live hosts",
		Long: `Discover live hosts on a network using TCP ping sweep.
Uses multiple common ports for faster and more reliable host discovery.

Examples:
  systool network ping 192.168.1.0/24
  systool network ping 10.0.0.0/24 --timeout 5s`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			networkCIDR := args[0]

			// Parse timeout - using optimized default
			timeout := 1 * time.Second
			if timeoutFlag != "" {
				var err error
				timeout, err = time.ParseDuration(timeoutFlag)
				if err != nil {
					return fmt.Errorf("invalid timeout format: %w", err)
				}
			}

			// Create scanner with optimized settings
			scanner := network.NewScanner()
			scanner.SetTimeout(timeout)
			if concurrencyFlag > 0 {
				scanner.SetConcurrency(concurrencyFlag, 5000)
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			fmt.Printf("🔍 Ping sweep on network: %s\n", networkCIDR)

			// Perform ping sweep
			result, err := scanner.PingSweep(ctx, networkCIDR)
			if err != nil {
				return fmt.Errorf("ping sweep failed: %w", err)
			}

			// Display results
			fmt.Printf("\n✅ Batch scan completed in %v\n", result.Duration)

			for _, host := range result.Hosts {
				fmt.Printf("🟢 %-15s (%.2fms)\n", host.IP, float64(host.Latency.Nanoseconds())/1000000)
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")
	cmd.Flags().StringVarP(&timeoutFlag, "timeout", "t", "1s", "Connection timeout (e.g., 1s, 500ms)")
	cmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 500, "Number of concurrent hosts to scan")

	return cmd
}

// NewPortScanCommand creates the port scan subcommand
func NewPortScanCommand() *cobra.Command {
	var (
		formatFlag      string
		timeoutFlag     string
		concurrencyFlag int
	)

	cmd := &cobra.Command{
		Use:   "portscan [host] [ports]",
		Short: "Scan ports on a specific host",
		Long: `Scan specific ports on a target host to identify open services.
Supports port ranges and comma-separated lists.

Examples:
  systool network portscan 192.168.1.1 22,80,443
  systool network portscan example.com 1-1000
  systool network portscan 10.0.0.1 80,443,8080,8443`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]
			portRange := args[1]

			// Parse ports
			ports, err := network.ParsePortRange(portRange)
			if err != nil {
				return fmt.Errorf("invalid port range: %w", err)
			}

			// Parse timeout - using optimized default
			timeout := 1 * time.Second
			if timeoutFlag != "" {
				timeout, err = time.ParseDuration(timeoutFlag)
				if err != nil {
					return fmt.Errorf("invalid timeout format: %w", err)
				}
			}

			// Create scanner with optimized settings
			scanner := network.NewScanner()
			scanner.SetTimeout(timeout)
			if concurrencyFlag > 0 {
				scanner.SetConcurrency(500, concurrencyFlag)
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			// Perform port scan
			result, err := scanner.ScanPorts(ctx, host, ports)
			if err != nil {
				return fmt.Errorf("port scan failed: %w", err)
			}

			// Display results
			fmt.Printf("\n📊 Found %d open ports:\n\n", len(result.Ports))

			for _, port := range result.Ports {
				service := port.Service
				if service == "" {
					service = "Unknown"
				}
				fmt.Printf("🟢 Port %-5d %-12s", port.Port, service)
				if port.Banner != "" {
					fmt.Printf(" - %s", port.Banner)
				}
				fmt.Println()
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")
	cmd.Flags().StringVarP(&timeoutFlag, "timeout", "t", "1s", "Connection timeout (e.g., 1s, 500ms)")
	cmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 5000, "Number of concurrent ports to scan")

	return cmd
}

// NewDiscoveryCommand creates the network discovery subcommand
func NewDiscoveryCommand() *cobra.Command {
	var (
		formatFlag      string
		timeoutFlag     string
		concurrencyFlag int
	)

	cmd := &cobra.Command{
		Use:   "discovery [network] [ports]",
		Short: "Perform network discovery with port scanning",
		Long: `Discover live hosts on a network and scan specified ports.
Combines host discovery with port scanning for comprehensive network mapping.

Examples:
  systool network discovery 192.168.1.0/24 22,80,443
  systool network discovery 10.0.0.0/24 1-1000
  systool network discovery 172.16.0.0/24 80,443,8080,3389,22`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			networkCIDR := args[0]
			portRange := args[1]

			// Parse ports
			ports, err := network.ParsePortRange(portRange)
			if err != nil {
				return fmt.Errorf("invalid port range: %w", err)
			}

			// Parse timeout - using optimized default
			timeout := 1 * time.Second
			if timeoutFlag != "" {
				timeout, err = time.ParseDuration(timeoutFlag)
				if err != nil {
					return fmt.Errorf("invalid timeout format: %w", err)
				}
			}

			// Create scanner with optimized settings
			scanner := network.NewScanner()
			scanner.SetTimeout(timeout)
			if concurrencyFlag > 0 {
				scanner.SetConcurrency(concurrencyFlag, 5000)
			}

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			// Perform network discovery
			result, err := scanner.NetworkDiscovery(ctx, networkCIDR, ports)
			if err != nil {
				return fmt.Errorf("network discovery failed: %w", err)
			}

			// Display results
			// Format and display results using the formatter
			formatter := output.NewFormatter(output.OutputFormat(formatFlag))
			return formatter.FormatScanResult(result, os.Stdout)
			fmt.Printf("📊 Found %d live hosts out of %d scanned:\n\n", result.Summary.LiveHosts, result.Summary.TotalHosts)

			for _, host := range result.Hosts {
				fmt.Printf("��️  %s\n", host.IP)
				if len(host.Ports) > 0 {
					for _, port := range host.Ports {
						service := port.Service
						if service == "" {
							service = "Unknown"
						}
						fmt.Printf("   🟢 %-5d %-12s", port.Port, service)
						if port.Banner != "" {
							fmt.Printf(" - %s", port.Banner)
						}
						fmt.Println()
					}
				} else {
					fmt.Printf("   📝 Host alive but no open ports found in scanned range\n")
				}
				fmt.Println()
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")
	cmd.Flags().StringVarP(&timeoutFlag, "timeout", "t", "1s", "Connection timeout (e.g., 1s, 500ms)")
	cmd.Flags().IntVarP(&concurrencyFlag, "concurrency", "c", 500, "Number of concurrent hosts to scan")

	return cmd
}

// NewWorkerPoolDiscoveryCommand creates the worker pool discovery subcommand for maximum performance
func NewWorkerPoolDiscoveryCommand() *cobra.Command {
	var (
		formatFlag  string
		timeoutFlag string
	)

	cmd := &cobra.Command{
		Use:   "discovery-fast [network] [ports]",
		Short: "Perform high-speed network discovery using worker pools",
		Long: `Discover live hosts on a network and scan specified ports using worker pools.
This is the fastest scanning method available, optimized for maximum performance.

Examples:
  systool network discovery-fast 192.168.1.0/24 22,80,443
  systool network discovery-fast 10.0.0.0/24 1-1000
  systool network discovery-fast 172.16.0.0/24 80,443,8080,3389,22`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			networkCIDR := args[0]
			portRange := args[1]

			// Parse ports
			ports, err := network.ParsePortRange(portRange)
			if err != nil {
				return fmt.Errorf("invalid port range: %w", err)
			}

			// Parse timeout - using optimized default
			timeout := 1 * time.Second
			if timeoutFlag != "" {
				timeout, err = time.ParseDuration(timeoutFlag)
				if err != nil {
					return fmt.Errorf("invalid timeout format: %w", err)
				}
			}

			// Create scanner with optimized settings
			scanner := network.NewScanner()
			scanner.SetTimeout(timeout)

			// Create context with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			// Perform worker pool network discovery
			result, err := scanner.NetworkDiscoveryWorkerPool(ctx, networkCIDR, ports)
			if err != nil {
				return fmt.Errorf("network discovery failed: %w", err)
			}

			// Display results
			fmt.Printf("\n✅ Discovery completed in %v\n", result.Duration)
			fmt.Printf("📊 Found %d live hosts out of %d scanned:\n\n", result.Summary.LiveHosts, result.Summary.TotalHosts)

			for _, host := range result.Hosts {
				fmt.Printf("🖥️  %s\n", host.IP)
				if len(host.Ports) > 0 {
					for _, port := range host.Ports {
						service := port.Service
						if service == "" {
							service = "Unknown"
						}
						fmt.Printf("   🟢 %-5d %-12s", port.Port, service)
						if port.Banner != "" {
							fmt.Printf(" - %s", port.Banner)
						}
						fmt.Println()
					}
				} else {
					fmt.Printf("   📝 Host alive but no open ports found in scanned range\n")
				}
				fmt.Println()
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")
	cmd.Flags().StringVarP(&timeoutFlag, "timeout", "t", "1s", "Connection timeout (e.g., 1s, 500ms)")

	return cmd
}

// NewMonitorCommand creates the port monitoring subcommand
func NewMonitorCommand() *cobra.Command {
	var (
		formatFlag   string
		intervalFlag string
	)

	cmd := &cobra.Command{
		Use:   "monitor [hosts] [ports]",
		Short: "Monitor specific ports on hosts continuously",
		Long: `Continuously monitor specific ports on target hosts.
Useful for monitoring service availability and detecting changes.

Examples:
  systool network monitor 192.168.1.1,192.168.1.2 80,443
  systool network monitor example.com,google.com 80,443,22
  systool network monitor 10.0.0.1 3389,22,80 --interval 60s`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostList := args[0]
			portRange := args[1]

			// Parse hosts
			hosts := strings.Split(hostList, ",")
			for i, host := range hosts {
				hosts[i] = strings.TrimSpace(host)
			}

			// Parse ports
			ports, err := network.ParsePortRange(portRange)
			if err != nil {
				return fmt.Errorf("invalid port range: %w", err)
			}

			// Parse interval
			interval := 30 * time.Second
			if intervalFlag != "" {
				interval, err = time.ParseDuration(intervalFlag)
				if err != nil {
					return fmt.Errorf("invalid interval format: %w", err)
				}
			}

			// Create scanner with optimized settings
			scanner := network.NewScanner()

			fmt.Printf("👀 Monitoring %d hosts on %d ports (Ctrl+C to stop)\n", len(hosts), len(ports))
			fmt.Printf("⏰ Checking every %v...\n\n", interval)

			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			// Initial check
			checkHosts(scanner, hosts, ports, formatFlag)

			for range ticker.C {
				fmt.Printf("\n⏰ %s - Checking status...\n", time.Now().Format("15:04:05"))
				checkHosts(scanner, hosts, ports, formatFlag)
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json, csv, xml)")
	cmd.Flags().StringVarP(&intervalFlag, "interval", "i", "30s", "Check interval (e.g., 30s, 1m)")

	return cmd
}

// checkHosts performs a check on all hosts and ports
func checkHosts(scanner *network.Scanner, hosts []string, ports []int, formatFlag string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, host := range hosts {
		fmt.Printf("🔍 %s: ", host)

		result, err := scanner.ScanPorts(ctx, host, ports)
		if err != nil {
			fmt.Printf("🔴 ERROR - %v\n", err)
			continue
		}

		if len(result.Ports) > 0 {
			var openPorts []int
			for _, port := range result.Ports {
				if port.Open {
					openPorts = append(openPorts, port.Port)
				}
			}
			fmt.Printf("🟢 UP - Ports: %v\n", openPorts)
		} else {
			fmt.Printf("🔴 DOWN or filtered\n")
		}
	}
}
