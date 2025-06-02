// =============================================================================
// internal/network/scanner.go - Network scanning functionality
// =============================================================================
package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PortResult represents the result of scanning a single port
type PortResult struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

// HostResult represents the result of scanning a single host
type HostResult struct {
	IP      string        `json:"ip"`
	Alive   bool          `json:"alive"`
	Ports   []PortResult  `json:"ports"`
	Latency time.Duration `json:"latency"`
}

// ScanResult represents the complete scan results
type ScanResult struct {
	Network   string        `json:"network"`
	Hosts     []HostResult  `json:"hosts"`
	StartTime time.Time     `json:"start_time"`
	Duration  time.Duration `json:"duration"`
	Summary   ScanSummary   `json:"summary"`
}

// ScanSummary provides summary statistics
type ScanSummary struct {
	TotalHosts   int `json:"total_hosts"`
	LiveHosts    int `json:"live_hosts"`
	TotalPorts   int `json:"total_ports"`
	OpenPorts    int `json:"open_ports"`
	HostsScanned int `json:"hosts_scanned"`
	PortsScanned int `json:"ports_scanned"`
}

// Scanner provides network scanning capabilities
type Scanner struct {
	timeout            time.Duration
	maxHostConcurrency int
	maxPortConcurrency int
	batchSize          int
}

// NewScanner creates a new scanner with optimized default settings
func NewScanner() *Scanner {
	return &Scanner{
		timeout:            1 * time.Second, // Reduced from 3 seconds for speed
		maxHostConcurrency: 500,             // Increased for better performance
		maxPortConcurrency: 5000,            // Significantly increased for port scanning
		batchSize:          254,             // Process one subnet at a time
	}
}

// SetTimeout sets the connection timeout for scans
func (s *Scanner) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

// SetConcurrency sets the concurrency limits
func (s *Scanner) SetConcurrency(hostConcurrency, portConcurrency int) {
	s.maxHostConcurrency = hostConcurrency
	s.maxPortConcurrency = portConcurrency
}

// SetBatchSize sets the batch size for processing
func (s *Scanner) SetBatchSize(size int) {
	s.batchSize = size
}

// Common services for port identification
var commonServices = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	135:  "RPC",
	139:  "NetBIOS",
	143:  "IMAP",
	443:  "HTTPS",
	445:  "SMB",
	993:  "IMAPS",
	995:  "POP3S",
	1433: "MSSQL",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	6379: "Redis",
	8080: "HTTP-Alt",
	9200: "Elasticsearch",
}

// PingSweep performs a ping sweep on the given network with batch processing and progress feedback
func (s *Scanner) PingSweep(ctx context.Context, network string) (*ScanResult, error) {
	start := time.Now()
	fmt.Printf("🔍 Batch scanning network: %s\n", network)

	ips, err := s.generateIPs(network)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IPs: %w", err)
	}

	var allHosts []HostResult
	var resultsMutex sync.Mutex

	// Process IPs in batches with progress feedback
	for i := 0; i < len(ips); i += s.batchSize {
		end := i + s.batchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[i:end]
		batchStart := time.Now()

		var wg sync.WaitGroup
		results := make(chan HostResult, len(batch))
		sem := make(chan struct{}, s.maxHostConcurrency)

		for _, ip := range batch {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				pingStart := time.Now()
				alive := s.pingHostFast(ctx, ip)
				latency := time.Since(pingStart)

				if alive {
					results <- HostResult{
						IP:      ip,
						Alive:   alive,
						Latency: latency,
					}
				}
			}(ip)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		var batchHosts []HostResult
		for result := range results {
			batchHosts = append(batchHosts, result)
		}

		resultsMutex.Lock()
		allHosts = append(allHosts, batchHosts...)
		resultsMutex.Unlock()

		batchElapsed := time.Since(batchStart)
		fmt.Printf("📈 Batch %d/%d: %d hosts found in %v\n",
			(i/s.batchSize)+1, (len(ips)+s.batchSize-1)/s.batchSize,
			len(batchHosts), batchElapsed)
		os.Stdout.Sync() // Force flush output
	}

	duration := time.Since(start)

	// Sort results by IP
	sort.Slice(allHosts, func(i, j int) bool {
		return s.compareIPs(allHosts[i].IP, allHosts[j].IP)
	})

	summary := ScanSummary{
		TotalHosts:   len(ips),
		LiveHosts:    len(allHosts),
		HostsScanned: len(ips),
	}

	return &ScanResult{
		Network:   network,
		Hosts:     allHosts,
		StartTime: start,
		Duration:  duration,
		Summary:   summary,
	}, nil
}

// ScanPorts scans specific ports on a target host with optimized batching and real-time progress
func (s *Scanner) ScanPorts(ctx context.Context, target string, ports []int) (*HostResult, error) {
	fmt.Printf("🔍 Scanning %s for %d ports...\n", target, len(ports))

	const portBatchSize = 1000
	var allResults []PortResult
	var resultsMutex sync.Mutex

	start := time.Now()

	// Process ports in batches for better performance
	for i := 0; i < len(ports); i += portBatchSize {
		end := i + portBatchSize
		if end > len(ports) {
			end = len(ports)
		}

		batch := ports[i:end]
		batchStart := time.Now()

		var wg sync.WaitGroup
		results := make(chan PortResult, len(batch))
		sem := make(chan struct{}, s.maxPortConcurrency)

		for _, port := range batch {
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				result := s.scanPortFast(target, port)
				if result.Open {
					results <- result
				}
			}(port)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect batch results
		var batchResults []PortResult
		for result := range results {
			batchResults = append(batchResults, result)
		}

		resultsMutex.Lock()
		allResults = append(allResults, batchResults...)
		resultsMutex.Unlock()

		batchElapsed := time.Since(batchStart)
		fmt.Printf("📈 Batch %d/%d: %d open ports found in %v\n",
			(i/portBatchSize)+1, (len(ports)+portBatchSize-1)/portBatchSize,
			len(batchResults), batchElapsed)
		os.Stdout.Sync() // Force flush output
	}

	elapsed := time.Since(start)
	fmt.Printf("✅ Scan completed in %v\n", elapsed)

	// Sort ports
	sort.Slice(allResults, func(i, j int) bool {
		return allResults[i].Port < allResults[j].Port
	})

	return &HostResult{
		IP:    target,
		Alive: len(allResults) > 0,
		Ports: allResults,
	}, nil
}

// NetworkDiscovery performs network discovery with port scanning using optimized batching
func (s *Scanner) NetworkDiscovery(ctx context.Context, network string, ports []int) (*ScanResult, error) {
	start := time.Now()
	fmt.Printf("🔍 Network discovery on %s\n", network)

	ips, err := s.generateIPs(network)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IPs: %w", err)
	}

	var allHosts []HostResult
	var resultsMutex sync.Mutex

	// Process IPs in batches to manage memory and provide progress feedback
	for i := 0; i < len(ips); i += s.batchSize {
		end := i + s.batchSize
		if end > len(ips) {
			end = len(ips)
		}

		batch := ips[i:end]
		batchStart := time.Now()

		var wg sync.WaitGroup
		results := make(chan HostResult, len(batch))
		sem := make(chan struct{}, s.maxHostConcurrency)

		for _, ip := range batch {
			wg.Add(1)
			go func(ip string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Use the faster ping method first
				if !s.pingHostFast(ctx, ip) {
					return
				}

				// Scan ports concurrently for this host
				var portWg sync.WaitGroup
				portResults := make(chan PortResult, len(ports))
				portSem := make(chan struct{}, s.maxPortConcurrency)

				for _, port := range ports {
					portWg.Add(1)
					go func(port int) {
						defer portWg.Done()
						portSem <- struct{}{}
						defer func() { <-portSem }()

						result := s.scanPortFast(ip, port)
						if result.Open {
							portResults <- result
						}
					}(port)
				}

				go func() {
					portWg.Wait()
					close(portResults)
				}()

				var openPorts []PortResult
				for result := range portResults {
					openPorts = append(openPorts, result)
				}

				if len(openPorts) > 0 || len(ports) == 0 {
					results <- HostResult{
						IP:    ip,
						Alive: true,
						Ports: openPorts,
					}
				}
			}(ip)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		// Collect batch results
		var batchHosts []HostResult
		for result := range results {
			batchHosts = append(batchHosts, result)
		}

		resultsMutex.Lock()
		allHosts = append(allHosts, batchHosts...)
		resultsMutex.Unlock()

		batchElapsed := time.Since(batchStart)
		fmt.Printf("📈 Batch %d/%d: %d hosts found in %v\n",
			(i/s.batchSize)+1, (len(ips)+s.batchSize-1)/s.batchSize,
			len(batchHosts), batchElapsed)
		os.Stdout.Sync() // Force flush output
	}

	duration := time.Since(start)

	// Sort results by IP
	sort.Slice(allHosts, func(i, j int) bool {
		return s.compareIPs(allHosts[i].IP, allHosts[j].IP)
	})

	// Calculate summary
	totalPorts := 0
	openPorts := 0
	for _, host := range allHosts {
		totalPorts += len(ports)
		openPorts += len(host.Ports)
	}

	summary := ScanSummary{
		TotalHosts:   len(ips),
		LiveHosts:    len(allHosts),
		TotalPorts:   len(ports),
		OpenPorts:    openPorts,
		HostsScanned: len(ips),
		PortsScanned: totalPorts,
	}

	return &ScanResult{
		Network:   network,
		Hosts:     allHosts,
		StartTime: start,
		Duration:  duration,
		Summary:   summary,
	}, nil
}

// NetworkDiscoveryWorkerPool performs network discovery using worker pools for maximum performance
func (s *Scanner) NetworkDiscoveryWorkerPool(ctx context.Context, network string, ports []int) (*ScanResult, error) {
	start := time.Now()
	fmt.Printf("🔍 Network discovery on %s (Worker Pool)\n", network)

	ips, err := s.generateIPs(network)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IPs: %w", err)
	}

	const numWorkers = 50
	const bufferSize = 100

	// Create channels
	jobs := make(chan string, bufferSize)
	results := make(chan HostResult, bufferSize)

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if !s.pingHostFast(ctx, ip) {
					continue
				}

				var portResults []PortResult
				var portWg sync.WaitGroup
				portChan := make(chan PortResult, len(ports))

				for _, port := range ports {
					portWg.Add(1)
					go func(port int) {
						defer portWg.Done()
						result := s.scanPortFast(ip, port)
						if result.Open {
							portChan <- result
						}
					}(port)
				}

				go func() {
					portWg.Wait()
					close(portChan)
				}()

				for result := range portChan {
					portResults = append(portResults, result)
				}

				if len(portResults) > 0 {
					results <- HostResult{
						IP:    ip,
						Alive: true,
						Ports: portResults,
					}
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for _, ip := range ips {
			jobs <- ip
		}
		close(jobs)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	var hosts []HostResult
	for result := range results {
		hosts = append(hosts, result)
	}

	duration := time.Since(start)

	sort.Slice(hosts, func(i, j int) bool {
		return s.compareIPs(hosts[i].IP, hosts[j].IP)
	})

	// Calculate summary
	totalPorts := 0
	openPorts := 0
	for _, host := range hosts {
		totalPorts += len(ports)
		openPorts += len(host.Ports)
	}

	summary := ScanSummary{
		TotalHosts:   len(ips),
		LiveHosts:    len(hosts),
		TotalPorts:   len(ports),
		OpenPorts:    openPorts,
		HostsScanned: len(ips),
		PortsScanned: totalPorts,
	}

	return &ScanResult{
		Network:   network,
		Hosts:     hosts,
		StartTime: start,
		Duration:  duration,
		Summary:   summary,
	}, nil
}

// pingHostFast performs a fast ping using TCP connect instead of ICMP
func (s *Scanner) pingHostFast(ctx context.Context, ip string) bool {
	// Try multiple common ports quickly
	ports := []int{80, 443, 22, 21, 23, 25, 53, 135, 139, 445}

	pingCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	// Use a channel to return as soon as any port responds
	success := make(chan bool, len(ports))

	for _, port := range ports {
		go func(p int) {
			address := fmt.Sprintf("%s:%d", ip, p)
			conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				select {
				case success <- true:
				default:
				}
			}
		}(port)
	}

	select {
	case <-success:
		return true
	case <-pingCtx.Done():
		return false
	}
}

// scanPort scans a single port on a host (legacy method for compatibility)
func (s *Scanner) scanPort(host string, port int) PortResult {
	target := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", target, s.timeout)
	if err != nil {
		return PortResult{Port: port, Open: false}
	}
	defer conn.Close()

	service := commonServices[port]
	banner := s.grabBanner(conn, port)

	return PortResult{
		Port:    port,
		Open:    true,
		Service: service,
		Banner:  banner,
	}
}

// scanPortFast scans a single port with optimized timeout
func (s *Scanner) scanPortFast(host string, port int) PortResult {
	timeout := 1 * time.Second // Reduced from 3 seconds
	target := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return PortResult{Port: port, Open: false}
	}
	defer conn.Close()

	service := commonServices[port]
	banner := s.grabBannerFast(conn, port)

	return PortResult{
		Port:    port,
		Open:    true,
		Service: service,
		Banner:  banner,
	}
}

// grabBanner attempts to grab a service banner (legacy method)
func (s *Scanner) grabBanner(conn net.Conn, port int) string {
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	// Send appropriate probe based on port
	switch port {
	case 22:
		// SSH typically sends banner immediately
	case 80, 8080:
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n"))
	case 25:
		// SMTP sends banner immediately
	case 21:
		// FTP sends banner immediately
	case 443:
		// HTTPS - don't try to grab banner as it requires TLS handshake
		return ""
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := string(buffer[:n])
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")
	banner = strings.TrimSpace(banner)

	if len(banner) > 40 {
		banner = banner[:40] + "..."
	}

	return banner
}

// grabBannerFast grabs banners with shorter timeout for speed
func (s *Scanner) grabBannerFast(conn net.Conn, port int) string {
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) // Reduced timeout

	// Send appropriate probe based on port
	switch port {
	case 22:
		// SSH typically sends banner immediately
	case 80, 8080:
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n"))
	case 25:
		// SMTP sends banner immediately
	case 21:
		// FTP sends banner immediately
	case 443:
		// HTTPS - don't try to grab banner as it requires TLS handshake
		return ""
	}

	buffer := make([]byte, 512) // Smaller buffer
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := string(buffer[:n])
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")
	banner = strings.TrimSpace(banner)

	if len(banner) > 40 { // Shorter banner limit
		banner = banner[:40] + "..."
	}

	return banner
}

// generateIPs generates a list of IPs from a network CIDR
func (s *Scanner) generateIPs(network string) ([]string, error) {
	var ips []string

	// Simple implementation for /24 networks
	if strings.HasSuffix(network, "/24") {
		base := strings.TrimSuffix(network, "/24")
		baseIP := strings.Split(base, ".")
		if len(baseIP) == 4 {
			for i := 1; i < 255; i++ {
				ip := fmt.Sprintf("%s.%s.%s.%d", baseIP[0], baseIP[1], baseIP[2], i)
				ips = append(ips, ip)
			}
		}
	} else {
		// Try to parse as CIDR
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			return nil, fmt.Errorf("invalid network format: %s", network)
		}

		// Generate IPs for the network
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); s.incrementIP(ip) {
			ips = append(ips, ip.String())
		}
	}

	return ips, nil
}

// incrementIP increments an IP address
func (s *Scanner) incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// compareIPs compares two IP addresses for sorting
func (s *Scanner) compareIPs(ip1, ip2 string) bool {
	parts1 := strings.Split(ip1, ".")
	parts2 := strings.Split(ip2, ".")

	for i := 0; i < 4; i++ {
		var n1, n2 int
		fmt.Sscanf(parts1[i], "%d", &n1)
		fmt.Sscanf(parts2[i], "%d", &n2)
		if n1 != n2 {
			return n1 < n2
		}
	}
	return false
}

// ParsePortRange parses a port range string into a slice of ports
func ParsePortRange(portRange string) ([]int, error) {
	var ports []int

	if strings.Contains(portRange, "-") {
		// Range format: 1-1000
		parts := strings.Split(portRange, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port range format")
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: ports must be between 1-65535 and start <= end")
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		}
	} else {
		// Comma-separated format: 80,443,22
		for _, portStr := range strings.Split(portRange, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", portStr)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d (must be 1-65535)", port)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}
