# SysTool - DNS, SSL & Network Swiss Army Knife

A comprehensive command-line tool for network administrators and security professionals. SysTool provides advanced DNS analysis, SSL certificate validation, and DNSSEC verification capabilities.

## Features

- **DNS Operations**
  - Query DNS records for any domain
  - Check DNS propagation across multiple nameservers
  - Detect DNS consistency issues and misconfigurations
  - Bulk operations for processing multiple domains
  
- **SSL Certificate Analysis**
  - Validate SSL/TLS certificates
  - Check certificate expiration dates
  - Analyze certificate chains and issuer information
  
- **DNSSEC Validation**
  - Verify DNSSEC configuration
  - Validate DS records and DNSKEY records
  - Check chain of trust

- **Network Operations**
  - TCP ping sweep for host discovery
  - Port scanning with service detection
  - Network discovery combining host and port scanning
  - Continuous port monitoring for service availability
  - Support for CIDR notation and port ranges
  - Banner grabbing and service identification

- **Multiple Output Formats**
  - Table (default, human-readable)
  - JSON (machine-readable)
  - CSV (spreadsheet-friendly)
  - XML (structured data)


## Usage

### DNS Commands

#### Query DNS Records

Query specific DNS records for a domain:

```bash
# Basic A record query
systool query example.com

# Query specific record type
systool query example.com MX

# Use specific nameserver
systool query example.com A --nameserver 8.8.8.8

# Output as JSON
systool query example.com A --format json
```

**Supported Record Types:** A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV

#### Check DNS Propagation

Verify DNS propagation across multiple nameservers:

```bash
# Check propagation using default nameservers
systool propagation example.com

# Check specific record type
systool propagation example.com MX

# Use specific DNS providers
systool propagation example.com A --providers google,cloudflare,quad9

# Output as CSV
systool propagation example.com A --format csv
```

**Supported Providers:** google, cloudflare, quad9, opendns

#### DNS Consistency Check

Perform comprehensive DNS consistency analysis:

```bash
# Check for DNS inconsistencies
systool consistency example.com

# Use specific providers
systool consistency example.com --providers google,cloudflare

# Output as JSON for automation
systool consistency example.com --format json
```

#### Bulk DNS Operations

Process multiple domains from a file:

```bash
# Create a domains file
echo -e "example.com\ngoogle.com\ngithub.com" > domains.txt

# Bulk query
systool bulk query domains.txt A

# Bulk propagation check
systool bulk propagation domains.txt A --concurrency 10

# Bulk consistency check
systool bulk consistency domains.txt --concurrency 5
```

### SSL Commands

#### SSL Certificate Check

Validate SSL certificates:

```bash
# Check SSL certificate
systool ssl-check example.com

# Use custom port
systool ssl-check example.com --port 8443

# Output as JSON
systool ssl-check example.com --format json
```

### DNSSEC Commands

#### DNSSEC Verification

Verify DNSSEC configuration:

```bash
# Verify DNSSEC
systool dnssec example.com

# Use specific nameserver
systool dnssec example.com --nameserver 8.8.8.8

# Output as JSON
systool dnssec example.com --format json
```

### Network Commands

#### Ping Sweep

Discover live hosts on a network using TCP ping sweep:

```bash
# Basic ping sweep on /24 network
systool network ping 192.168.1.0/24

# Custom timeout and concurrency
systool network ping 10.0.0.0/24 --timeout 5s --concurrency 50

# Output as JSON
systool network ping 172.16.0.0/24 --format json
```

#### Port Scanning

Scan specific ports on target hosts:

```bash
# Scan common ports
systool network portscan 192.168.1.1 22,80,443

# Scan port range
systool network portscan example.com 1-1000

# Scan with custom timeout
systool network portscan 10.0.0.1 80,443,8080,8443 --timeout 5s

# High concurrency scan
systool network portscan target.com 1-65535 --concurrency 100
```

#### Network Discovery

Combine host discovery with port scanning for comprehensive network mapping:

```bash
# Discover hosts and scan common ports
systool network discovery 192.168.1.0/24 22,80,443

# Full port range discovery
systool network discovery 10.0.0.0/24 1-1000

# Custom services discovery
systool network discovery 172.16.0.0/24 80,443,8080,3389,22 --concurrency 50

# Output as JSON for automation
systool network discovery 192.168.0.0/24 22,80,443 --format json
```

#### Port Monitoring

Continuously monitor specific ports on target hosts:

```bash
# Monitor web services
systool network monitor 192.168.1.1,192.168.1.2 80,443

# Monitor multiple hosts and services
systool network monitor example.com,google.com 80,443,22

# Custom monitoring interval
systool network monitor 10.0.0.1 3389,22,80 --interval 60s

# Monitor with different check frequency
systool network monitor server1.local,server2.local 22,80,443,3306 --interval 5m
```

**Supported Port Formats:**
- Single ports: `80,443,22`
- Port ranges: `1-1000`, `8000-9000`
- Mixed: `22,80,443,8000-8100`

**Common Services Detected:**
- FTP (21), SSH (22), Telnet (23), SMTP (25)
- DNS (53), HTTP (80), POP3 (110), IMAP (143)
- HTTPS (443), SMB (445), MSSQL (1433), MySQL (3306)
- RDP (3389), PostgreSQL (5432), VNC (5900), Redis (6379)
- HTTP-Alt (8080), Elasticsearch (9200)

## Output Formats

### Table Format (Default)

Human-readable table output with emojis and formatting:

```
🔍 DNS Query Results for example.com (A)
📡 Nameserver: 8.8.8.8
⏱️  Response time: 45ms
🕐 Queried at: 2024-01-15 10:30:45

┌─────────────┬──────┬─────────────────┬─────┬──────────┐
│ Name        │ Type │ Value           │ TTL │ Priority │
├─────────────┼──────┼─────────────────┼─────┼──────────┤
│ example.com │ A    │ 93.184.216.34   │ 300 │          │
└─────────────┴──────┴─────────────────┴─────┴──────────┘
```

### JSON Format

Machine-readable JSON output:

```json
{
  "query": {
    "domain": "example.com",
    "record_type": "A",
    "nameserver": "8.8.8.8"
  },
  "records": [
    {
      "name": "example.com",
      "type": "A",
      "value": "93.184.216.34",
      "ttl": 300
    }
  ],
  "response_time": "45ms",
  "timestamp": "2024-01-15T10:30:45Z"
}
```

### CSV Format

Spreadsheet-friendly CSV output:

```csv
Domain,RecordType,Nameserver,Name,Type,Value,TTL,Priority,ResponseTime,Error
example.com,A,8.8.8.8,example.com,A,93.184.216.34,300,,45ms,
```

### XML Format

Structured XML output:

```xml
<DNSResult>
  <Query>
    <Domain>example.com</Domain>
    <RecordType>A</RecordType>
    <Nameserver>8.8.8.8</Nameserver>
  </Query>
  <Records>
    <Record>
      <Name>example.com</Name>
      <Type>A</Type>
      <Value>93.184.216.34</Value>
      <TTL>300</TTL>
    </Record>
  </Records>
  <ResponseTime>45ms</ResponseTime>
  <Timestamp>2024-01-15T10:30:45Z</Timestamp>
</DNSResult>
```

## Examples

### Common Use Cases

#### 1. Troubleshoot DNS Issues

```bash
# Check if DNS has propagated after making changes
systool propagation mysite.com A

# Look for DNS inconsistencies
systool consistency mysite.com

# Verify DNSSEC is working
systool dnssec mysite.com
```

#### 2. SSL Certificate Monitoring

```bash
# Check certificate expiration
systool ssl-check mysite.com

# Monitor multiple sites
echo -e "site1.com\nsite2.com\nsite3.com" > sites.txt
for site in $(cat sites.txt); do
  echo "Checking $site..."
  systool ssl-check $site --format json | jq '.expires_in'
done
```

#### 3. DNS Migration Verification

```bash
# Before migration - document current state
systool query mysite.com A --format json > before.json

# After migration - verify changes
systool query mysite.com A --format json > after.json

# Check propagation across all major providers
systool propagation mysite.com A --providers google,cloudflare,quad9,opendns
```

#### 4. Bulk Domain Analysis

```bash
# Analyze multiple domains
systool bulk query domains.txt A --format csv > results.csv

# Check SSL certificates for multiple domains
for domain in $(cat domains.txt); do
  systool ssl-check $domain --format json >> ssl_results.json
done
```

#### 5. Network Discovery and Scanning

```bash
# Discover live hosts on your local network
systool network ping 192.168.1.0/24

# Scan common ports on a specific host
systool network portscan 192.168.1.1 22,80,443,3389

# Full network discovery with port scanning
systool network discovery 10.0.0.0/24 22,80,443,8080

# Monitor critical services continuously
systool network monitor server1.local,server2.local 22,80,443 --interval 5m
```

#### 6. Security Assessment

```bash
# Quick security scan of a target
systool network portscan target.example.com 21,22,23,25,53,80,110,143,443,993,995

# Comprehensive network mapping
systool network discovery 172.16.0.0/24 1-1000 --concurrency 50 --format json > network_map.json

# Monitor for unauthorized services
systool network monitor 192.168.1.0/24 1337,4444,5555 --interval 1m
```

### Advanced Usage

#### Custom Nameserver Lists

```bash
# Query specific nameservers
systool query example.com A --nameserver 1.1.1.1
systool query example.com A --nameserver 208.67.222.222
```

#### Automation and Scripting

```bash
#!/bin/bash
# DNS health check script

DOMAIN="$1"
if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

echo "=== DNS Health Check for $DOMAIN ==="

# Check basic DNS resolution
echo "1. Basic DNS Query:"
systool query "$DOMAIN" A

# Check propagation
echo -e "\n2. Propagation Check:"
systool propagation "$DOMAIN" A

# Check for consistency issues
echo -e "\n3. Consistency Check:"
systool consistency "$DOMAIN"

# Check SSL certificate
echo -e "\n4. SSL Certificate:"
systool ssl-check "$DOMAIN"

# Check DNSSEC
echo -e "\n5. DNSSEC Verification:"
systool dnssec "$DOMAIN"
```

## Configuration

### Environment Variables

- `SYSTOOL_DEFAULT_NAMESERVER`: Default nameserver to use (default: 8.8.8.8)
- `SYSTOOL_DEFAULT_TIMEOUT`: Default timeout for queries (default: 10s)
- `SYSTOOL_DEFAULT_FORMAT`: Default output format (default: table)

### Command-Line Flags

Global flags available for most commands:

- `--format, -f`: Output format (table, json, csv, xml)
- `--nameserver, -n`: Nameserver to query
- `--help, -h`: Show help information
- `--version`: Show version information

## Error Handling

SysTool provides detailed error messages and appropriate exit codes:

- `0`: Success
- `1`: General error
- `2`: Invalid arguments
- `3`: Network/DNS error
- `4`: SSL/TLS error
- `5`: DNSSEC validation error

## Performance

### Concurrency

Bulk operations support configurable concurrency:

```bash
# Low concurrency for rate-limited APIs
systool bulk query domains.txt A --concurrency 2

# Higher concurrency for better performance
systool bulk query domains.txt A --concurrency 10
```

### Timeouts

Default timeouts are optimized for reliability:

- Single queries: 10 seconds
- Propagation checks: 30 seconds
- Consistency checks: 60 seconds
- Bulk operations: 5-15 minutes (depending on operation)

## Troubleshooting

### Common Issues

#### DNS Resolution Failures

```bash
# Try different nameservers
systool query example.com A --nameserver 1.1.1.1
systool query example.com A --nameserver 8.8.8.8
```

#### SSL Certificate Issues

```bash
# Check specific port
systool ssl-check example.com --port 8443

# Verify certificate chain
systool ssl-check example.com --format json | jq '.issuer'
```

#### DNSSEC Validation Failures

```bash
# Check if DNSSEC is enabled
systool dnssec example.com --format json | jq '.has_dnssec'

# Use different nameserver
systool dnssec example.com --nameserver 1.1.1.1
```
