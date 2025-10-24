# Nimbis Examples

This document provides practical examples for using Nimbis in various scenarios.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Scanning Different Project Types](#scanning-different-project-types)
- [CI/CD Integration](#cicd-integration)
- [Advanced Filtering](#advanced-filtering)
- [Output Formats](#output-formats)

## Basic Usage

### Quick Scan

Scan the current directory with all available scanners:

```bash
nimbis
```

### Scan Specific Directory

```bash
nimbis -t /path/to/project
```

### Verbose Output

Get detailed information about what's happening:

```bash
nimbis -v
```

## Scanning Different Project Types

### Node.js/JavaScript Project

```bash
# Full security scan
nimbis -t ./my-node-app --all

# Just dependencies and secrets
nimbis -t ./my-node-app --sca --secrets

# Focus on critical issues
nimbis -t ./my-node-app --severity CRITICAL
```

### Python Project

```bash
# Scan for vulnerabilities and secrets
nimbis -t ./my-python-app --sca --secrets --sast

# Generate SBOM
nimbis -t ./my-python-app --sbom -f json -o sbom.json
```

### Go Project

```bash
# Full scan with HTML report
nimbis -t ./my-go-app --all -f html -o report.html
```

### Infrastructure as Code

#### Terraform

```bash
# Scan Terraform configurations
nimbis -t ./terraform --iac

# Detailed IaC scan with specific severity
nimbis -t ./terraform --iac --severity MEDIUM -v
```

#### Kubernetes Manifests

```bash
# Scan K8s YAML files
nimbis -t ./k8s --iac

# Generate report for K8s configs
nimbis -t ./k8s --iac -f html -o k8s-security-report.html
```

#### Docker

```bash
# Scan Dockerfile and container configs
nimbis -t ./docker --iac --container
```

### Monorepo

```bash
# Scan entire monorepo
nimbis -t ./monorepo --all --parallel

# Scan specific package in monorepo
nimbis -t ./monorepo/packages/api --all
```

## CI/CD Integration

### GitHub Actions - Pull Request Check

```yaml
name: Security Check

on: pull_request

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Security Scan
        run: |
          # Install nimbis
          curl -L https://github.com/yourusername/nimbis/releases/latest/download/nimbis-linux-amd64 -o nimbis
          chmod +x nimbis
          
          # Run scan and fail on HIGH or CRITICAL
          ./nimbis --fail-on HIGH -f json -o results.json
      
      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-results
          path: results.json
```

### GitHub Actions - Code Scanning with SARIF

```yaml
name: Code Scanning

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Run SecureScan
        run: |
          curl -L https://github.com/yourusername/nimbis/releases/latest/download/nimbis-linux-amd64 -o nimbis
          chmod +x nimbis
          ./nimbis -f sarif -o results.sarif || true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
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
    - ./nimbis --fail-on HIGH -f json -o gl-security-report.json
  artifacts:
    reports:
      security: gl-security-report.json
    paths:
      - gl-security-report.json
    expire_in: 1 week
  allow_failure: false
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    curl -L https://github.com/yourusername/securescan/releases/latest/download/securescan-linux-amd64 -o securescan
                    chmod +x securescan
                    ./securescan --fail-on HIGH -f json -o security-report.json
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'security-report.json', fingerprint: true
            publishHTML([
                reportDir: '.',
                reportFiles: 'security-report.json',
                reportName: 'Security Scan Report'
            ])
        }
    }
}
```

### CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install Nimbis
          command: |
            curl -L https://github.com/yourusername/nimbis/releases/latest/download/nimbis-linux-amd64 -o nimbis
            chmod +x nimbis
      - run:
          name: Run Security Scan
          command: ./nimbis --fail-on HIGH -f json -o results.json
      - store_artifacts:
          path: results.json

workflows:
  security:
    jobs:
      - security-scan
```

## Advanced Filtering

### By Severity

```bash
# Only show CRITICAL issues
nimbis --severity CRITICAL

# Show MEDIUM and above
nimbis --severity MEDIUM

# Fail build on HIGH or above
nimbis --fail-on HIGH
```

### By Scan Type

```bash
# Only secrets
nimbis --secrets

# Only IaC misconfigurations
nimbis --iac

# Combine multiple types
nimbis --secrets --sast --sca
```

### Sequential vs Parallel

```bash
# Run scanners in parallel (default, faster)
nimbis --parallel=true

# Run scanners sequentially (easier to debug)
nimbis --parallel=false -v
```

## Output Formats

### JSON (Default)

```bash
# Output to stdout
nimbis -f json

# Save to file
nimbis -f json -o results.json

# Pretty print with jq
nimbis -f json | jq '.'
```

### SARIF (GitHub Code Scanning)

```bash
# Generate SARIF report
nimbis -f sarif -o results.sarif

# Upload to GitHub
gh api /repos/OWNER/REPO/code-scanning/sarifs \
  -F commit_sha=$(git rev-parse HEAD) \
  -F ref=refs/heads/main \
  -F sarif=@results.sarif
```

### HTML Report

```bash
# Generate beautiful HTML report
nimbis -f html -o report.html

# Open in browser (macOS)
nimbis -f html -o report.html && open report.html

# Open in browser (Linux)
nimbis -f html -o report.html && xdg-open report.html
```

### Table Format

```bash
# Human-readable table
nimbis -f table

# Save table to file
nimbis -f table -o results.txt
```

## Real-World Scenarios

### Pre-Commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash

echo "Running security scan..."
nimbis --fail-on HIGH --severity MEDIUM -f table

if [ $? -ne 0 ]; then
    echo "❌ Security scan failed! Fix issues before committing."
    exit 1
fi

echo "✅ Security scan passed!"
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

### Docker Container Scanning

```bash
# Build and scan Docker image
docker build -t myapp:latest .
docker save myapp:latest -o myapp.tar
nimbis --container -t myapp.tar
```

### Scheduled Security Audits

Create a cron job (`crontab -e`):

```bash
# Run weekly security scan every Monday at 2 AM
0 2 * * 1 cd /path/to/project && /usr/local/bin/nimbis --all -f html -o /var/reports/security-$(date +\%Y\%m\%d).html
```

### Multi-Project Scan

```bash
#!/bin/bash

PROJECTS=(
    "/path/to/project1"
    "/path/to/project2"
    "/path/to/project3"
)

for project in "${PROJECTS[@]}"; do
    echo "Scanning $project..."
    nimbis -t "$project" -f json -o "$(basename $project)-results.json"
done

echo "All scans complete!"
```

### Generate Security Dashboard

```bash
# Scan all projects and generate reports
nimbis -t ./frontend --all -f html -o reports/frontend.html
nimbis -t ./backend --all -f html -o reports/backend.html
nimbis -t ./infrastructure --iac -f html -o reports/infra.html

# Create index.html that links to all reports
cat > reports/index.html << EOF
<html>
<head><title>Security Dashboard</title></head>
<body>
  <h1>Security Reports</h1>
  <ul>
    <li><a href="frontend.html">Frontend</a></li>
    <li><a href="backend.html">Backend</a></li>
    <li><a href="infra.html">Infrastructure</a></li>
  </ul>
</body>
</html>
EOF
```

## Troubleshooting Examples

### Debug Scanner Execution

```bash
# See which scanners are available
nimbis -v --all

# Run with maximum verbosity
nimbis -v -t . 2>&1 | tee debug.log
```

### Handle Large Repositories

```bash
# Exclude large directories
nimbis -t . --all | grep -v "node_modules\|vendor\|.git"

# Scan specific subdirectories
nimbis -t ./src --all
nimbis -t ./config --iac
```

### Compare Results

```bash
# Baseline scan
nimbis -f json -o baseline.json

# After fixes
nimbis -f json -o current.json

# Compare (requires jq)
diff <(jq -S . baseline.json) <(jq -S . current.json)
```

## Tips and Best Practices

1. **Start with low severity**: Begin with `--severity LOW` to see all issues, then tighten as you fix them
2. **Use specific scan types**: Only run scans relevant to your project to save time
3. **Integrate early**: Add to CI/CD from day one
4. **Review regularly**: Schedule periodic full scans
5. **Generate SBOMs**: Use `--sbom` for compliance and tracking
6. **Store results**: Archive scan results for trend analysis
7. **Fail fast**: Use `--fail-on` appropriately for your security requirements

## Getting Help

```bash
# Show help
nimbis --help

# Show version
nimbis --version

# Check available scanners
nimbis --check-tools
```
