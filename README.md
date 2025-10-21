# BountyTxt

[![Go Report Card](https://goreportcard.com/badge/github.com/bountytxt/bountytxt)](https://goreportcard.com/report/github.com/bountytxt/bountytxt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

BountyTxt CLI is a comprehensive tool for discovering, validating, and analyzing RFC 9116 security.txt files to find vulnerability disclosure contacts for domains.

The tool prioritizes legal and safe defaults, including HTTPS-only requests, honoring robots.txt, and avoiding unsolicited messages.

## Features

- **Security.txt Discovery**: Find security.txt files at standard locations (/.well-known/security.txt, /security.txt)
- **Comprehensive Validation**: RFC 9116 compliance checking with detailed scoring and grading
- **Contact Extraction**: Extract and validate contact information (emails, URLs, phone numbers)
- **Bug Bounty Analysis**: Analyze bug bounty programs from security.txt and external sources
- **Subdomain Hunting**: Discover security.txt files across subdomains
- **Bulk Processing**: Process multiple domains from files or stdin
- **CI/CD Integration**: Proper exit codes and structured logging for automated pipelines
- **Multiple Output Formats**: Table, JSON, YAML, CSV, XML, SARIF
- **Export Capabilities**: Export validation results and security.txt data

## Installation

### Pre-built Binaries

Download the latest release from the [releases page](https://github.com/bountytxt/bountytxt/releases).

### From Source

```bash
git clone https://github.com/bountytxt/bountytxt.git
cd bountytxt
go build -o bountytxt ./cmd/securitytxt
```

### Go Install

```bash
go install github.com/bountytxt/bountytxt/cmd/securitytxt@latest
```

## Quick Start

```bash
# Find security.txt for a domain
bountytxt find example.com

# Validate security.txt compliance
bountytxt verify example.com

# Extract contact information
bountytxt contacts example.com

# Hunt for security.txt across subdomains
bountytxt hunt example.com

# Analyze bug bounty programs
bountytxt bounty example.com
```

## Commands

### Core Commands

- `find` - Discover security.txt files for a domain
- `verify` - Validate security.txt files with RFC 9116 compliance checking
- `contacts` - Extract and analyze contact information
- `bounty` - Analyze bug bounty programs from security.txt and external sources

### Advanced Commands

- `hunt` - Hunt for security.txt files with subdomain enumeration
- `bulk` - Process multiple domains from file or stdin
- `export` - Export security.txt data in various formats (JSON, YAML, CSV, XML, SARIF)
- `programs` - Search and list bug bounty programs
- `ci` - CI/CD integration with proper exit codes and structured logging

## Usage Examples

### Basic Discovery
```bash
bountytxt find github.com
```

### Validation with Scoring
```bash
bountytxt verify example.com --output json
```

### Contact Analysis
```bash
bountytxt contacts example.com --validate-contacts --show-confidence
```

### Subdomain Hunting
```bash
bountytxt hunt example.com --subdomains www,api,dev --include-wildcards
```

### Bulk Processing
```bash
# From file
bountytxt bulk domains.txt --output jsonl

# From stdin
cat domains.txt | bountytxt bulk -
```

### CI/CD Integration
```bash
bountytxt ci example.com --min-score 80 --fail-on error,warning --github-actions
```

### Export Data
```bash
bountytxt export example.com --format sarif --output results.sarif
bountytxt export example.com --format json --include-validation --output security-data.json
```

## Configuration

Create a configuration file at `~/.bountytxt.yaml`:

```yaml
output:
  format: table
  verbose: false
  quiet: false

timeout: 30s
max-redirects: 5
verify-tls: true
honor-robots: true
public-mode: true
user-agent: "bountytxt/1.0.0"
workers: 10
rate-limit: 5.0
rate-burst: 10
```

## Output Formats

BountyTxt supports multiple output formats:

- **Table** (default): Human-readable tabular output
- **JSON**: Structured data for APIs and tools
- **JSONL**: JSON Lines format for streaming
- **YAML**: Human-readable configuration format
- **CSV**: Spreadsheet and database import
- **XML**: Enterprise system integration
- **SARIF**: Static Analysis Results Interchange Format

## Validation Scoring

BountyTxt provides comprehensive validation with scoring:

- **Score**: 0-100 points based on compliance and best practices
- **Grade**: A, B, C, D, F based on score ranges
- **Issues**: Detailed validation issues with severity levels (error, warning, info)
- **Suggestions**: Remediation recommendations for each issue

## Safety & Ethics

BountyTxt is designed with security research ethics in mind:

- **HTTPS-Only**: Enforces HTTPS for all requests by default
- **Robots.txt Respect**: Honors robots.txt directives
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming servers
- **Public Mode**: Restricts certain features for public safety
- **No Unsolicited Contact**: Never sends unsolicited messages

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) CLI framework
- Uses [Viper](https://github.com/spf13/viper) for configuration
- Follows RFC 9116 security.txt specification
- Inspired by the security research community's need for better tooling

## Disclaimer

This tool is intended for security research and vulnerability disclosure purposes only. Users are responsible for complying with applicable laws and regulations. The maintainers are not responsible for misuse of this tool.