# Nimbis

**Nimble Security at Scale** - A comprehensive security scanning CLI tool for code, containers, and infrastructure.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)](https://go.dev/)

## Features

- **Interactive Console** - Metasploit-style interface with guided prompts (no CLI knowledge required)
- **Multi-Scanner Orchestration** - Integrates 7+ open-source security scanners
- **Container Security** - Scan Docker images and Dockerfiles for vulnerabilities
- **AI-Powered Explanations** - Get plain-language security analysis from Claude, GPT, or Ollama
- **Fast Parallel Scanning** - Run multiple scanners simultaneously
- **Multiple Output Formats** - JSON, SARIF, HTML, and table
- **Smart Filtering** - Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
- **Dual-Mode Operation** - Interactive console or CLI automation

## Scan Coverage

| Type | Description | Scanners |
|------|-------------|----------|
| IaC | Infrastructure as Code misconfigurations | Trivy, Checkov |
| Secrets | Hardcoded credentials and API keys | TruffleHog, Trivy |
| SAST | Static application security testing | OpenGrep |
| SCA | Vulnerable dependencies | Trivy, Grype |
| Container | Container images and Dockerfiles | Trivy |
| SBOM | Software Bill of Materials | Syft |

## Installation

### From Source
```bash
git clone https://github.com/ChrisHolman/Nimbis-cli.git
cd Nimbis-cli
go build -o nimbis .
```

### Download Binary
```bash
# Linux (x64)
curl -L https://github.com/ChrisHolman/Nimbis-cli/releases/latest/download/nimbis-linux-amd64 -o nimbis
chmod +x nimbis

# macOS (Intel)
curl -L https://github.com/ChrisHolman/Nimbis-cli/releases/latest/download/nimbis-darwin-amd64 -o nimbis
chmod +x nimbis

# macOS (Apple Silicon)
curl -L https://github.com/ChrisHolman/Nimbis-cli/releases/latest/download/nimbis-darwin-arm64 -o nimbis
chmod +x nimbis
```

## Quick Start

### Interactive Mode (Easiest)

Run without arguments for the guided console interface:

```bash
./nimbis
```

Available commands:
- `scan` - Start a security scan with guided prompts
- `help` - Show available commands
- `exit` - Quit

Example workflow:
```
nimbis> scan
Enter target: nginx:latest
Select scan type: 6 (Container)
Select severity: 3 (HIGH)
Proceed? y
```

### CLI Mode (Automation)

Use flags for automated scanning in CI/CD:

```bash
# Scan everything
./nimbis --all

# Scan specific types
./nimbis --container --target nginx:latest --severity HIGH
./nimbis --sca --iac --target /path/to/project

# Generate reports
./nimbis --all --format html --output report.html
./nimbis --secrets --format json --output results.json
```

## Usage Examples

### Container Scanning
```bash
# Scan a Docker image
./nimbis --container --target nginx:latest

# Scan a Dockerfile
./nimbis --container --target Dockerfile

# Scan with severity filter
./nimbis --container --target myapp:v1.0 --severity CRITICAL
```

### Code Scanning
```bash
# Scan for secrets and IaC issues
./nimbis --secrets --iac --target /path/to/project

# Full scan with high severity only
./nimbis --all --severity HIGH

# Generate HTML report
./nimbis --sca --sast --format html --output security-report.html
```

### Severity Filtering
```bash
# Show only HIGH and CRITICAL
./nimbis --severity HIGH

# Fail build on CRITICAL issues
./nimbis --all --fail-on CRITICAL
```

## AI-Powered Explanations

Get intelligent security analysis using AI:

### Setup
```bash
# Option 1: Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-your-key"

# Option 2: OpenAI GPT
export OPENAI_API_KEY="sk-your-key"

# Option 3: Local Ollama (free)
ollama pull llama2
```

### Usage
```bash
# Scan and explain findings
./nimbis explain

# Explain high severity issues
./nimbis --severity HIGH explain --max 20
```

## Scanner Installation

Nimbis requires external scanners. Install automatically or manually:

### Automatic
```bash
./nimbis --auto-install
```

### Manual
```bash
# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Checkov
pip3 install checkov

# OpenGrep
npm install -g @opengrep/cli
```

## CI/CD Integration

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Nimbis
        run: |
          curl -L https://github.com/ChrisHolman/Nimbis-cli/releases/latest/download/nimbis-linux-amd64 -o nimbis
          chmod +x nimbis

      - name: Run Scan
        run: ./nimbis --all --severity HIGH --format json --output results.json

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: results.json
```

### GitLab CI
```yaml
security_scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl
    - curl -L https://github.com/ChrisHolman/Nimbis-cli/releases/latest/download/nimbis-linux-amd64 -o nimbis
    - chmod +x nimbis
  script:
    - ./nimbis --all --severity HIGH --format json --output results.json
  artifacts:
    paths:
      - results.json
    expire_in: 1 week
```

## Configuration

### Environment Variables
```bash
# AI Provider
export ANTHROPIC_API_KEY="sk-ant-..."
export ANTHROPIC_MODEL="claude-sonnet-4-20250514"

export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4"

export OLLAMA_URL="http://localhost:11434"
export OLLAMA_MODEL="llama2"

# Scanner Paths (if not in PATH)
export TRIVY_PATH="/usr/local/bin/trivy"
export GRYPE_PATH="/usr/local/bin/grype"
```

## Development

```bash
# Clone repository
git clone https://github.com/ChrisHolman/Nimbis-cli.git
cd Nimbis-cli

# Install dependencies
go mod download

# Build
go build -o nimbis .

# Run tests
go test ./...

# Run locally
./nimbis --all --verbose
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

Built with these open-source tools:
- [Trivy](https://github.com/aquasecurity/trivy) - Container & dependency scanner
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanner
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner
- [Syft](https://github.com/anchore/syft) - SBOM generator
- [Checkov](https://github.com/bridgecrewio/checkov) - IaC scanner
- [OpenGrep](https://github.com/semgrep/semgrep) - SAST tool

## Support

- Bug Reports: [GitHub Issues](https://github.com/ChrisHolman/Nimbis-cli/issues)
- Documentation: [GitHub Wiki](https://github.com/ChrisHolman/Nimbis-cli/wiki)
