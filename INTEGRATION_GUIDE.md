# 🤖 Nimbis AI Explain Feature - Integration Guide

## 📋 Overview

This adds AI-powered explanation capabilities to Nimbis, allowing you to get plain-language security analysis using Anthropic Claude, OpenAI GPT, or local Ollama models.

## 🚀 Quick Setup

### 1. Add the New Files

Add these two new files to your Nimbis project directory:

```
nimbis/
├── explain.go           # AI provider logic and explanation engine
├── cmd_explain.go       # CLI command handler
├── main.go              # (existing)
├── scanners.go          # (existing)
└── ...                  # (other existing files)
```

### 2. Configure Your AI Provider

Choose one of these options:

#### Option A: Anthropic Claude (Recommended)
```bash
export ANTHROPIC_API_KEY="sk-ant-xxxxx"
export ANTHROPIC_MODEL="claude-sonnet-4-20250514"  # Optional, has good default
```

#### Option B: OpenAI GPT
```bash
export OPENAI_API_KEY="sk-xxxxx"
export OPENAI_MODEL="gpt-4"  # Optional
```

#### Option C: Local Ollama (Free, No API Key)
```bash
# Install Ollama: https://ollama.ai
ollama pull llama2
export OLLAMA_MODEL="llama2"
export OLLAMA_URL="http://localhost:11434"  # Optional
```

### 3. Rebuild Nimbis

```bash
cd ~/nimbis
go mod tidy
go build -o nimbis .
```

## 🎯 Usage Examples

### Basic Explanation
```bash
# Explain all CRITICAL and HIGH findings
./nimbis explain

# Explain all findings down to MEDIUM severity
./nimbis explain --min-severity MEDIUM

# Explain top 5 findings only
./nimbis explain --max 5
```

### Advanced Usage
```bash
# Force a specific AI provider
./nimbis explain --provider anthropic

# Scan and explain in one command
./nimbis scan --target . && ./nimbis explain

# Get explanations for a different project
./nimbis scan --target /path/to/project
./nimbis explain
```

## 📊 What You Get

### 1. AI Summary
Plain-language overview of your security posture:
```
📊 SUMMARY
─────────────────────────────────────────────────────────
Your codebase has several critical vulnerabilities primarily 
stemming from an outdated Go standard library (v1.19.8). 
The most urgent issues include...
```

### 2. Prioritized Recommendations
Actionable steps ranked by importance:
```
💡 KEY RECOMMENDATIONS
─────────────────────────────────────────────────────────
1. Upgrade Go to version 1.21.12 or later immediately
2. Add a non-root user to your Dockerfile
3. Implement health checks in your container
```

### 3. Detailed Finding Analysis
Each finding with context and fixes:
```
📋 DETAILED FINDINGS
─────────────────────────────────────────────────────────

1. 🔴 CRITICAL - CVE-2023-24531
   CVE: CVE-2023-24531
   📦 Package: stdlib (v1.19.8)
   📍 Location: /nimbis
   💡 Fix: Upgrade to 1.21.0-0
```

### 4. Saved Report
Full explanation saved to: `nimbis-results-explanation.txt`

## 🔧 Command Options

```bash
./nimbis explain --help

Flags:
      --max int              Maximum findings to explain (default 10)
      --min-severity string  Minimum severity (LOW|MEDIUM|HIGH|CRITICAL) (default "HIGH")
      --provider string      Force AI provider (anthropic|openai|ollama)
      --interactive          Interactive Q&A mode (coming soon)

Global Flags:
  -t, --target string    Target to scan (default ".")
  -v, --verbose          Verbose output
```

## 🎨 Example Output

When you run `./nimbis explain`, you'll see:

```
🤖 Nimbis AI Explanation

🔧 Configuring AI provider...
  ✓ Using Anthropic Claude (claude-sonnet-4-20250514)

📊 Explaining 7 findings

💭 Analyzing findings with AI...

╔══════════════════════════════════════════════════════════╗
║        🤖 AI SECURITY ANALYSIS                           ║
╚══════════════════════════════════════════════════════════╝

📊 SUMMARY
─────────────────────────────────────────────────────────
Your application has 7 critical security vulnerabilities...

💡 KEY RECOMMENDATIONS
─────────────────────────────────────────────────────────
1. Upgrade your Go version immediately to 1.21.12
2. Address the Dockerfile security misconfigurations
3. Implement proper health monitoring
...

💾 Full explanation saved to: nimbis-results-explanation.txt
```

## 🐛 Troubleshooting

### "No AI provider configured"
```bash
# Set up your API key
export ANTHROPIC_API_KEY="your-key-here"

# Or use free local Ollama
ollama pull llama2
```

### "No existing scan results found"
The explain command will automatically run a scan first if needed.

### Rate Limits
- **Anthropic/OpenAI**: Free tier has limits, explain batches findings
- **Ollama**: No limits, runs locally, but slower

### API Key Not Working
```bash
# Verify your key is set
echo $ANTHROPIC_API_KEY

# Test the API
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json"
```

## 📚 Integration with CI/CD

### GitHub Actions
```yaml
name: Security Scan with AI Explanation

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Nimbis
        run: |
          wget https://github.com/youruser/nimbis/releases/latest/download/nimbis-linux-amd64
          chmod +x nimbis-linux-amd64
      
      - name: Scan and Explain
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          ./nimbis-linux-amd64 scan
          ./nimbis-linux-amd64 explain --max 20
      
      - name: Upload Explanation
        uses: actions/upload-artifact@v3
        with:
          name: security-explanation
          path: nimbis-results-explanation.txt
```

## 🎯 Best Practices

1. **Start with Critical**: Focus on `--min-severity HIGH` first
2. **Batch Processing**: Use `--max` to avoid hitting API limits
3. **Save Results**: Explanation files are great for documentation
4. **Review Regularly**: Run weekly scans with explanations
5. **Team Sharing**: Share explanation files in PRs for context

## 🚦 Next Steps

After integrating explain:

1. Run your first AI explanation
2. Review the recommendations
3. Fix critical issues first
4. Set up automated scanning in CI/CD
5. Share results with your team

## 💡 Feature Roadmap

Coming soon:
- Interactive Q&A mode (`--interactive`)
- Custom explanation templates
- Multi-language explanations
- Trend analysis across scans
- Integration with issue trackers

## 🤝 Need Help?

- Check the main Nimbis documentation
- Report issues on GitHub
- Join our community discussions

Happy secure coding! 🛡️
