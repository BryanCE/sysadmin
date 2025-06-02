# SysTool - DNS & SSL Swiss Army Knife

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

- **Multiple Output Formats**
  - Table (default, human-readable)
  - JSON (machine-readable)
  - CSV (spreadsheet-friendly)
  - XML (structured data)

## Installation

### Prerequisites

- Go 1.24.0 or later

### Building from Source

```bash
# Clone the repository
git clone https://github.com/bryanCE/sysadmin.git
cd sysadmin

# Install dependencies
make deps

# Build for current platform
make build

# Build for all platforms
make build-all

# Install to GOPATH/bin
make install
```

### Development Setup

```bash
# Install development dependencies
make dev-deps

# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Run linter
make lint

# Run all quality checks
make check
```

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