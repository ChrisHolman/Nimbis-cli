# Quick Setup Steps for Nimbis AI Explain

## 1. Replace Files:

```bash
cd ~/nimbis

# Back up your existing files first
cp command_explain.go command_explain.go.backup
cp main.go main.go.backup
cp explain.go explain.go.backup 2>/dev/null || true

# Replace command_explain.go with the new version from the artifact
# Replace explain.go with the new version from the artifact
```

## 2. Edit main.go

Open `main.go` and make these changes:

### Delete the old explain command registration (around line 73-80):
```go
// DELETE THIS ENTIRE BLOCK:
explainCmd := &cobra.Command{
	Use:   "explain",
	Short: "Get AI-powered explanations for security findings",
	Long: `Use AI to explain security findings in plain language with actionable fix suggestions.
Supports OpenAI, Anthropic Claude, and local Ollama models.`,
	RunE: runExplain,
}
rootCmd.AddCommand(explainCmd)
```

### Delete the old runExplain function (around line 91-145):
```go
// DELETE THIS ENTIRE FUNCTION:
func runExplain(cmd *cobra.Command, args []string) error {
	// ... all the code in here ...
}
```

### Add the new registration:
Find the `main()` function and add this line BEFORE `rootCmd.Execute()`:

```go
func main() {
	rootCmd := &cobra.Command{
		// ...
	}

	// ... all your existing flags ...

	// ADD THIS LINE HERE:
	rootCmd.AddCommand(explainCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

## 3. Set Up Your API Key

Choose one:

```bash
# Option A: Anthropic Claude (recommended)
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Option B: OpenAI
export OPENAI_API_KEY="sk-your-key-here"

# Option C: Local Ollama (free but slower)
# Install from https://ollama.ai then:
ollama pull llama2
```

## 4. Build

```bash
cd ~/nimbis
go build -o nimbis .
```

## 5. Test

```bash
# Test with your current findings
./nimbis explain

# Or run a fresh scan first
./nimbis --all
./nimbis explain

# Explain with more findings
./nimbis explain --max 20 --min-severity MEDIUM
```

## Expected Output

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
Your codebase has 7 critical vulnerabilities stemming from an 
outdated Go standard library (v1.19.8)...

💡 KEY RECOMMENDATIONS
─────────────────────────────────────────────────────────
1. Upgrade Go to version 1.21.12 immediately
2. Add a non-root user to your Dockerfile
3. Implement health checks in your container

📋 DETAILED FINDINGS
─────────────────────────────────────────────────────────

1. 🔴 CRITICAL - CVE-2023-24531
   CVE: CVE-2023-24531
   📦 Package: stdlib (v1.19.8)
   📍 Location: /nimbis
   💡 Fix: Upgrade to 1.21.0-0
...

💾 Full explanation saved to: nimbis-results-explanation.txt
```

## Troubleshooting

### "undefined: explainCmd"
- Make sure you added `rootCmd.AddCommand(explainCmd)` in main.go
- The explainCmd is defined in command_explain.go

### "runExplain redeclared"
- You didn't delete the old runExplain function from main.go
- Search for `func runExplain` and delete the entire function

### "results.Findings undefined"
- This error shouldn't occur with the new code
- If it does, make sure you're using the NEW command_explain.go file

### "No AI provider configured"
```bash
# Set your API key:
export ANTHROPIC_API_KEY="your-key"

# Or check if it's set:
echo $ANTHROPIC_API_KEY
```

### API calls failing
```bash
# Test your API key:
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-20250514","max_tokens":10,"messages":[{"role":"user","content":"Hi"}]}'
```

## File Structure After Setup

```
~/nimbis/
├── main.go              (modified - removed old explain code)
├── command_explain.go   (replaced - new AI version)
├── explain.go           (new - AI provider logic)
├── types.go            (unchanged)
├── scanner.go          (unchanged)
├── trivy.go            (unchanged)
├── other_scanners.go   (unchanged)
├── formatter.go        (unchanged)
├── banner.go           (unchanged)
└── installer.go        (unchanged)
```

## Quick Command Reference

```bash
# Basic explain
./nimbis explain

# Explain more findings
./nimbis explain --max 20

# Explain all severity levels
./nimbis explain --min-severity LOW

# Scan specific directory then explain
./nimbis -t /path/to/project --all
./nimbis explain

# Force specific AI provider
./nimbis explain --provider anthropic
```

## Success! 🎉

Once built successfully, you now have AI-powered security explanations in Nimbis!
