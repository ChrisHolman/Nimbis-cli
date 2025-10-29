# 🛡️ Nimbis

**Nimble Security at Scale** - A comprehensive, AI-powered security scanning CLI tool for code, containers, and infrastructure.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)
[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)](https://go.dev/)

## 🌟 Features

- **🔍 Multi-Scanner Orchestration** - Integrates 7+ open-source security scanners
- **🤖 AI-Powered Explanations** - Get plain-language security analysis from Claude, GPT, or local Ollama
- **⚡ Fast Parallel Scanning** - Run multiple scanners simultaneously for speed
- **📊 Multiple Output Formats** - JSON, SARIF, HTML, and table formats
- **🎯 Smart Filtering** - Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
- **🔧 Auto-Install** - Automatically download and install missing scanners
- **🚀 Cross-Platform** - Works on Linux, macOS, and Windows

## 🎭 What Nimbis Scans

| Scan Type | Description | Scanners Used |
|-----------|-------------|---------------|
| **IaC** | Infrastructure as Code misconfigurations | Trivy, Checkov |
| **Secrets** | Hardcoded credentials and API keys | TruffleHog, Trivy |
| **SAST** | Static application security testing | OpenGrep |
| **SCA** | Vulnerable dependencies | Trivy, Grype |
| **SBOM** | Software Bill of Materials generation | Syft |

## 🚀 Quick Start

### Installation

#### From Source
```bash
git clone https://github.com/yourusername/nimbis.git
cd nimbis
go build -o nimbis .
```

#### Download Binary
```bash
# Linux
curl -L https://github.com/yourusername/nimbis/releases/latest/download/nimbis-linux-amd64 -o nimbis
chmod +x nimbis

# macOS
curl -L https://github.com/yourusername/nimbis/releases/latest/download/nimbis-darwin-amd64 -o nimbis
chmod +x nimbis

# Windows
# Download from releases page
```

### Basic Usage

```bash
# Scan current directory with all scanners
./nimbis

# Scan specific directory for HIGH+ severity issues
./nimbis --severity HIGH --target /path/to/project

# Generate HTML report
./nimbis --all --format html --output report.html

# Run with verbose output
./nimbis --all --verbose
```

## 🤖 AI-Powered Explanations

Get intelligent, actionable security analysis using AI:

### Setup AI Provider

Choose one option:

```bash
# Option 1: Anthropic Claude (Recommended)
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Option 2: OpenAI GPT
export OPENAI_API_KEY="sk-your-key-here"

# Option 3: Local Ollama (Free, no API key needed)
ollama pull llama2
```

### Use Explain Command

```bash
# Scan and explain all findings
./nimbis explain

# Scan for HIGH+ severity and explain top 20
./nimbis --severity HIGH explain --max 20

# Scan for CRITICAL issues and explain all
./nimbis --severity CRITICAL explain --max 100
```

### Example Output

```
🤖 Nimbis AI Explanation

🔧 Configuring AI provider...
  ✓ Using Anthropic Claude (claude-sonnet-4-20250514)

📊 Explaining all 24 findings

💭 Analyzing findings with AI...

╔══════════════════════════════════════════════════════════╗
║        🤖 AI SECURITY ANALYSIS                           ║
╚══════════════════════════════════════════════════════════╝

📊 SUMMARY
─────────────────────────────────────────────────────────
Your system has critical vulnerabilities requiring immediate
attention. The primary issues are an outdated Go runtime with 23
known CVEs and containers running as root user...

💡 KEY RECOMMENDATIONS
─────────────────────────────────────────────────────────
1. Upgrade Go to version 1.21.12 or later immediately

2. Add non-root user to your Dockerfile

3. Implement health checks in containers
```

## 📖 Usage Guide

### Scan Types

```bash
# Scan everything (default)
./nimbis --all

# Specific scan types
./nimbis --iac           # Infrastructure as Code only
./nimbis --secrets       # Secrets only
./nimbis --sast          # Static analysis only
./nimbis --sca           # Dependency vulnerabilities only
./nimbis --sbom          # Generate SBOM only

# Combine scan types
./nimbis --iac --secrets --sca
```

### Severity Filtering

```bash
# Show only HIGH and CRITICAL issues
./nimbis --severity HIGH

# Show only CRITICAL issues
./nimbis --severity CRITICAL

# Fail build on HIGH or above
./nimbis --severity LOW --fail-on HIGH
```

### Output Formats

```bash
# JSON (default)
./nimbis --format json --output results.json

# SARIF (for GitHub Code Scanning)
./nimbis --format sarif --output results.sarif

# HTML Report
./nimbis --format html --output report.html

# Table (human-readable)
./nimbis --format table
```

### Advanced Options

```bash
# Quiet mode (minimal output, saves to file)
./nimbis --quiet

# Run scanners sequentially (easier debugging)
./nimbis --parallel=false --verbose

# Auto-install missing scanners
./nimbis --auto-install

# Target specific directory
./nimbis --target /path/to/scan
```

## 🔧 Scanner Installation

Nimbis requires external scanners to be installed. You can install them manually or use `--auto-install`:

### Automatic Installation

```bash
./nimbis --auto-install
```

### Manual Installation

#### Linux/macOS

```bash
# Trivy (IaC, Secrets, SCA)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin

# TruffleHog (Secrets)
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin

# Grype (SCA)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Syft (SBOM)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Checkov (IaC)
pip3 install checkov

# OpenGrep (SAST)
npm install -g @opengrep/cli
```

#### Windows

Download binaries from the respective project release pages and add to PATH.

## 🔄 CI/CD Integration

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
          curl -L https://github.com/yourusername/nimbis/releases/latest/download/nimbis-linux-amd64 -o nimbis
          chmod +x nimbis
      
      - name: Run Security Scan
        run: ./nimbis --fail-on HIGH --format json --output results.json
      
      - name: AI Explanation
        if: failure()
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: ./nimbis explain --max 20
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: |
            results.json
            nimbis-results-explanation.txt
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache curl
    - curl -L https://github.com/yourusername/nimbis/releases/latest/download/nimbis-linux-amd64 -o nimbis
    - chmod +x nimbis
  script:
    - ./nimbis --fail-on HIGH --format json --output results.json
  artifacts:
    paths:
      - results.json
    expire_in: 1 week
```

## 📊 Example Workflows

### Pre-Commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running security scan..."
./nimbis --severity HIGH --quiet

if [ $? -ne 0 ]; then
    echo "❌ Security issues found! Run './nimbis explain' for details."
    exit 1
fi

echo "✅ Security scan passed!"
```

### Weekly Security Audit

```bash
#!/bin/bash
# weekly-audit.sh

# Run comprehensive scan
./nimbis --all --format html --output "security-report-$(date +%Y%m%d).html"

# Generate AI explanation
export ANTHROPIC_API_KEY="your-key"
./nimbis explain --max 50 > "explanation-$(date +%Y%m%d).txt"

# Email results (example)
mail -s "Weekly Security Report" team@company.com < "explanation-$(date +%Y%m%d).txt"
```

## 🎯 Best Practices

1. **Start Broad, Then Focus**
   - Initial scan: `./nimbis --severity LOW`
   - Production: `./nimbis --severity HIGH --fail-on CRITICAL`

2. **Use AI Explanations for Learning**
   - `./nimbis explain` helps understand and prioritize fixes

3. **Integrate Early**
   - Add to CI/CD from day one
   - Run on every pull request

4. **Regular Updates**
   - Keep Nimbis and scanners up to date
   - Review new vulnerabilities weekly

5. **Archive Results**
   - Save scan results for compliance and trend analysis

## 🛠️ Configuration

### Environment Variables

```bash
# AI Provider Configuration
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

## 📈 Output Examples

### Console Output

```
███    ██ ██ ███    ███ ██████  ██ ███████ 
████   ██ ██ ████  ████ ██   ██ ██ ██      
██ ██  ██ ██ ██ ████ ██ ██████  ██ ███████ 
██  ██ ██ ██ ██  ██  ██ ██   ██ ██      ██ 
██   ████ ██ ██      ██ ██████  ██ ███████ 

                v0.1.0
    IaC • Secrets • SAST • SCA • SBOM

╔════════════════════════════════════════════════════════╗
║  SCAN SUMMARY                                          ║
╠════════════════════════════════════════════════════════╣
║  Total Findings:           24                          ║
║  Scan Duration:            29.4s                       ║
║  Scanners Used:            7                           ║
╚════════════════════════════════════════════════════════╝

Severity Breakdown:
  CRITICAL 7
  HIGH 17

Findings by Type:
  • SCA: 23
  • IaC: 1
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/nimbis.git
cd nimbis

# Install dependencies
go mod download

# Build
go build -o nimbis .

# Run tests
go test ./...

# Run locally
./nimbis --all --verbose
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## 🙏 Acknowledgments

Nimbis builds upon these excellent open-source tools:

- [Trivy](https://github.com/aquasecurity/trivy) - Container & dependency scanner
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanner
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner
- [Syft](https://github.com/anchore/syft) - SBOM generator
- [Checkov](https://github.com/bridgecrewio/checkov) - IaC scanner
- [OpenGrep](https://github.com/semgrep/semgrep) - SAST tool

## 🐛 Issues & Support

- **Bug Reports**: [GitHub Issues](https://github.com/yourusername/nimbis/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/yourusername/nimbis/discussions)
- **Security Issues**: Please email security@yourdomain.com

## 🗺️ Roadmap

- [ ] Container image scanning
- [ ] Interactive explanation mode (Q&A with AI)
- [ ] Custom rule definitions
- [ ] VS Code extension
- [ ] Dashboard web UI
- [ ] Trend analysis across scans
- [ ] Integration with issue trackers (Jira, GitHub Issues)
- [ ] Multi-language explanations
- [ ] Baseline and differential scanning

## ⭐ Star History

If you find Nimbis useful, please consider giving it a star!

---

**Made with ❤️ for the security community**

*Nimbis - Nimble Security at Scale*
