package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// AIProvider interface for different LLM providers
type AIProvider interface {
	Explain(finding Finding, codeContext string) (string, error)
	GetName() string
	IsConfigured() bool
}

// OpenAIProvider implements OpenAI/ChatGPT
type OpenAIProvider struct {
	apiKey string
	model  string
}

// AnthropicProvider implements Claude
type AnthropicProvider struct {
	apiKey string
	model  string
}

// OllamaProvider implements local Ollama
type OllamaProvider struct {
	endpoint string
	model    string
}

// NewAIProvider creates an AI provider based on configuration
func NewAIProvider() AIProvider {
	// Try providers in order of preference
	
	// 1. Check for OpenAI
	if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
		model := os.Getenv("OPENAI_MODEL")
		if model == "" {
			model = "gpt-4o-mini" // Cheaper, faster default
		}
		return &OpenAIProvider{apiKey: apiKey, model: model}
	}
	
	// 2. Check for Anthropic Claude
	if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
		model := os.Getenv("ANTHROPIC_MODEL")
		if model == "" {
			model = "claude-3-5-sonnet-20241022"
		}
		return &AnthropicProvider{apiKey: apiKey, model: model}
	}
	
	// 3. Check for local Ollama
	endpoint := os.Getenv("OLLAMA_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:11434" // Default Ollama endpoint
	}
	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "llama3.2" // Default model
	}
	
	return &OllamaProvider{endpoint: endpoint, model: model}
}

// OpenAI Implementation
func (p *OpenAIProvider) GetName() string {
	return "OpenAI " + p.model
}

func (p *OpenAIProvider) IsConfigured() bool {
	return p.apiKey != ""
}

func (p *OpenAIProvider) Explain(finding Finding, codeContext string) (string, error) {
	prompt := buildExplanationPrompt(finding, codeContext)
	
	requestBody := map[string]interface{}{
		"model": p.model,
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a security expert helping developers understand and fix vulnerabilities. Be concise, practical, and provide actionable advice.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.7,
		"max_tokens":  1000,
	}
	
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OpenAI API error: %s", string(body))
	}
	
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI")
	}
	
	return result.Choices[0].Message.Content, nil
}

// Anthropic Implementation
func (p *AnthropicProvider) GetName() string {
	return "Anthropic " + p.model
}

func (p *AnthropicProvider) IsConfigured() bool {
	return p.apiKey != ""
}

func (p *AnthropicProvider) Explain(finding Finding, codeContext string) (string, error) {
	prompt := buildExplanationPrompt(finding, codeContext)
	
	requestBody := map[string]interface{}{
		"model": p.model,
		"max_tokens": 1024,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}
	
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Anthropic API error: %s", string(body))
	}
	
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	if len(result.Content) == 0 {
		return "", fmt.Errorf("no response from Anthropic")
	}
	
	return result.Content[0].Text, nil
}

// Ollama Implementation
func (p *OllamaProvider) GetName() string {
	return "Ollama " + p.model
}

func (p *OllamaProvider) IsConfigured() bool {
	// Check if Ollama is running
	resp, err := http.Get(p.endpoint + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (p *OllamaProvider) Explain(finding Finding, codeContext string) (string, error) {
	prompt := buildExplanationPrompt(finding, codeContext)
	
	requestBody := map[string]interface{}{
		"model":  p.model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.7,
		},
	}
	
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequest("POST", p.endpoint+"/api/generate", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Ollama not running. Start with: ollama serve")
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Ollama API error: %s", string(body))
	}
	
	var result struct {
		Response string `json:"response"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	return result.Response, nil
}

// buildExplanationPrompt creates the prompt for AI explanation
func buildExplanationPrompt(finding Finding, codeContext string) string {
	var prompt strings.Builder
	
	prompt.WriteString("Explain this security finding:\n\n")
	
	// Finding details
	if finding.CVE != "" {
		prompt.WriteString(fmt.Sprintf("CVE: %s\n", finding.CVE))
	}
	prompt.WriteString(fmt.Sprintf("Title: %s\n", finding.Title))
	prompt.WriteString(fmt.Sprintf("Severity: %s\n", finding.Severity))
	prompt.WriteString(fmt.Sprintf("Type: %s\n", finding.Type))
	
	if finding.File != "" {
		prompt.WriteString(fmt.Sprintf("Location: %s", finding.File))
		if finding.Line > 0 {
			prompt.WriteString(fmt.Sprintf(":%d", finding.Line))
		}
		prompt.WriteString("\n")
	}
	
	if finding.Description != "" {
		prompt.WriteString(fmt.Sprintf("Description: %s\n", finding.Description))
	}
	
	// Package info for SCA
	if finding.Type == ScanTypeSCA {
		if pkg, ok := finding.Extra["package"]; ok {
			prompt.WriteString(fmt.Sprintf("\nAffected Package: %s\n", pkg))
			if ver, ok := finding.Extra["installed_version"]; ok {
				prompt.WriteString(fmt.Sprintf("Current Version: %s\n", ver))
			}
			if fix, ok := finding.Extra["fixed_version"]; ok && fix != "" {
				prompt.WriteString(fmt.Sprintf("Fixed Version: %s\n", fix))
			}
		}
	}
	
	// Code context if available
	if codeContext != "" {
		prompt.WriteString("\nCode Context:\n```\n")
		prompt.WriteString(codeContext)
		prompt.WriteString("\n```\n")
	}
	
	prompt.WriteString("\nProvide:\n")
	prompt.WriteString("1. Simple explanation (2-3 sentences)\n")
	prompt.WriteString("2. Why this is dangerous\n")
	prompt.WriteString("3. How to fix it (be specific and practical)\n")
	prompt.WriteString("4. Prevention tips\n")
	prompt.WriteString("\nBe concise and actionable. Use clear language.")
	
	return prompt.String()
}

// GetCodeContext retrieves code context around a finding
func GetCodeContext(file string, line int, contextLines int) string {
	if file == "" || line <= 0 {
		return ""
	}
	
	data, err := os.ReadFile(file)
	if err != nil {
		return ""
	}
	
	lines := strings.Split(string(data), "\n")
	if line > len(lines) {
		return ""
	}
	
	start := line - contextLines - 1
	if start < 0 {
		start = 0
	}
	
	end := line + contextLines
	if end > len(lines) {
		end = len(lines)
	}
	
	var context strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == line-1 {
			prefix = "> " // Mark the actual line
		}
		context.WriteString(fmt.Sprintf("%s%4d | %s\n", prefix, i+1, lines[i]))
	}
	
	return context.String()
}

// ExplainFinding provides AI-powered explanation for a finding
func ExplainFinding(finding Finding) error {
	provider := NewAIProvider()
	
	if !provider.IsConfigured() {
		return showAISetupInstructions()
	}
	
	PrintInfo(fmt.Sprintf("Getting AI explanation from %s...", provider.GetName()))
	
	// Get code context if available
	codeContext := GetCodeContext(finding.File, finding.Line, 3)
	
	explanation, err := provider.Explain(finding, codeContext)
	if err != nil {
		return fmt.Errorf("AI explanation failed: %w", err)
	}
	
	// Display the explanation nicely
	displayExplanation(finding, explanation)
	
	return nil
}

// displayExplanation shows the AI explanation in a nice format
func displayExplanation(finding Finding, explanation string) {
	fmt.Println()
	PrintSectionHeader(fmt.Sprintf("AI EXPLANATION - %s", finding.Title))
	fmt.Println()
	
	// Show finding summary
	fmt.Printf("%s%s%s\n", Bold, finding.Title, Reset)
	if finding.CVE != "" {
		fmt.Printf("%sCVE:%s %s\n", Dim, Reset, finding.CVE)
	}
	fmt.Printf("%sSeverity:%s %s\n", Dim, Reset, ColorSeverity(finding.Severity))
	if finding.File != "" {
		location := finding.File
		if finding.Line > 0 {
			location += fmt.Sprintf(":%d", finding.Line)
		}
		fmt.Printf("%sLocation:%s %s\n", Dim, Reset, location)
	}
	
	fmt.Println()
	fmt.Println(strings.Repeat("─", 70))
	fmt.Println()
	
	// Display AI explanation with light formatting
	lines := strings.Split(explanation, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "**") {
			fmt.Printf("%s%s%s\n", Bold, strings.Trim(line, "# *"), Reset)
		} else if strings.TrimSpace(line) != "" {
			fmt.Println(line)
		} else {
			fmt.Println()
		}
	}
	
	PrintSectionFooter()
}

// showAISetupInstructions shows how to configure AI
func showAISetupInstructions() error {
	fmt.Println()
	PrintWarning("AI features require configuration")
	fmt.Println()
	fmt.Println("Choose one of the following options:")
	fmt.Println()
	
	fmt.Printf("%s%s1. OpenAI (ChatGPT) - Recommended%s\n", Bold, BrightCyan, Reset)
	fmt.Println("   export OPENAI_API_KEY='sk-...'")
	fmt.Println("   export OPENAI_MODEL='gpt-4o-mini'  # Optional, default: gpt-4o-mini")
	fmt.Println("   Get API key: https://platform.openai.com/api-keys")
	fmt.Println()
	
	fmt.Printf("%s%s2. Anthropic Claude%s\n", Bold, BrightCyan, Reset)
	fmt.Println("   export ANTHROPIC_API_KEY='sk-ant-...'")
	fmt.Println("   export ANTHROPIC_MODEL='claude-3-5-sonnet-20241022'  # Optional")
	fmt.Println("   Get API key: https://console.anthropic.com/")
	fmt.Println()
	
	fmt.Printf("%s%s3. Ollama (Local, Free, Private)%s\n", Bold, BrightCyan, Reset)
	fmt.Println("   # Install Ollama")
	fmt.Println("   curl -fsSL https://ollama.com/install.sh | sh")
	fmt.Println("   ")
	fmt.Println("   # Pull a model")
	fmt.Println("   ollama pull llama3.2")
	fmt.Println("   ")
	fmt.Println("   # Start Ollama (runs on http://localhost:11434)")
	fmt.Println("   ollama serve")
	fmt.Println("   ")
	fmt.Println("   # Optional: Configure")
	fmt.Println("   export OLLAMA_ENDPOINT='http://localhost:11434'  # Optional")
	fmt.Println("   export OLLAMA_MODEL='llama3.2'  # Optional, default: llama3.2")
	fmt.Println()
	
	fmt.Println("After configuring, try:")
	fmt.Printf("  %snimbis explain%s\n", BrightCyan, Reset)
	fmt.Println()
	
	return fmt.Errorf("AI not configured")
}
