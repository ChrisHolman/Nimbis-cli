package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AIProvider represents different AI service providers
type AIProvider string

const (
	ProviderAnthropic AIProvider = "anthropic"
	ProviderOpenAI    AIProvider = "openai"
	ProviderOllama    AIProvider = "ollama"
)

// AIConfig holds configuration for AI providers
type AIConfig struct {
	Provider AIProvider
	APIKey   string
	Model    string
	BaseURL  string
}

// ExplanationRequest represents a request to explain findings
type ExplanationRequest struct {
	Findings []Finding
	Severity string
	MaxCount int
}

// ExplanationResponse represents the AI's explanation
type ExplanationResponse struct {
	Summary      string
	Explanations []FindingExplanation
	Recommendations []string
}

// FindingExplanation represents an explained finding
type FindingExplanation struct {
	Finding     Finding
	Explanation string
	FixSteps    []string
	Priority    string
}

// AnthropicRequest for Claude API
type AnthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	Messages  []Message `json:"messages"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AnthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

// OpenAIRequest for GPT API
type OpenAIRequest struct {
	Model    string          `json:"model"`
	Messages []Message       `json:"messages"`
	MaxTokens int            `json:"max_tokens,omitempty"`
}

type OpenAIResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

// OllamaRequest for local Ollama
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

// GetAIConfig detects and configures the AI provider
func GetAIConfig() (*AIConfig, error) {
	// Check for Anthropic
	if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
		return &AIConfig{
			Provider: ProviderAnthropic,
			APIKey:   apiKey,
			Model:    getEnvOrDefault("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
			BaseURL:  "https://api.anthropic.com/v1/messages",
		}, nil
	}

	// Check for OpenAI
	if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
		return &AIConfig{
			Provider: ProviderOpenAI,
			APIKey:   apiKey,
			Model:    getEnvOrDefault("OPENAI_MODEL", "gpt-4"),
			BaseURL:  "https://api.openai.com/v1/chat/completions",
		}, nil
	}

	// Check for Ollama
	ollamaURL := getEnvOrDefault("OLLAMA_URL", "http://localhost:11434")
	if isOllamaAvailable(ollamaURL) {
		return &AIConfig{
			Provider: ProviderOllama,
			Model:    getEnvOrDefault("OLLAMA_MODEL", "llama2"),
			BaseURL:  ollamaURL + "/api/generate",
		}, nil
	}

	return nil, fmt.Errorf("no AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or run Ollama locally")
}

func getEnvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}

func isOllamaAvailable(baseURL string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(baseURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200 || resp.StatusCode == 404
}

// ExplainFindings uses AI to explain security findings
func ExplainFindings(config *AIConfig, request ExplanationRequest) (*ExplanationResponse, error) {
	prompt := buildExplanationPrompt(request)

	var explanation string
	var err error

	switch config.Provider {
	case ProviderAnthropic:
		explanation, err = callAnthropic(config, prompt)
	case ProviderOpenAI:
		explanation, err = callOpenAI(config, prompt)
	case ProviderOllama:
		explanation, err = callOllama(config, prompt)
	default:
		return nil, fmt.Errorf("unsupported AI provider: %s", config.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("AI request failed: %w", err)
	}

	return parseExplanation(explanation, request.Findings), nil
}

func buildExplanationPrompt(request ExplanationRequest) string {
	var sb strings.Builder
	
	sb.WriteString("You are a security expert. Analyze these security findings and provide:\n")
	sb.WriteString("1. A brief summary of the overall security posture\n")
	sb.WriteString("2. For each finding: a plain-language explanation and concrete fix steps\n")
	sb.WriteString("3. Prioritized recommendations\n\n")
	
	sb.WriteString("Security Findings:\n\n")
	
	for i, finding := range request.Findings {
		if i >= request.MaxCount {
			break
		}
		sb.WriteString(fmt.Sprintf("## Finding %d: %s\n", i+1, finding.Title))
		sb.WriteString(fmt.Sprintf("Severity: %s\n", finding.Severity))
		sb.WriteString(fmt.Sprintf("Type: %s\n", finding.Type))
		
		if finding.CVE != "" {
			sb.WriteString(fmt.Sprintf("CVE: %s\n", finding.CVE))
		}
		if finding.Package != "" {
			sb.WriteString(fmt.Sprintf("Package: %s\n", finding.Package))
		}
		if finding.Version != "" {
			sb.WriteString(fmt.Sprintf("Version: %s\n", finding.Version))
		}
		if finding.Location != "" {
			sb.WriteString(fmt.Sprintf("Location: %s\n", finding.Location))
		}
		if finding.Description != "" {
			sb.WriteString(fmt.Sprintf("Description: %s\n", finding.Description))
		}
		if finding.Remediation != "" {
			sb.WriteString(fmt.Sprintf("Suggested Fix: %s\n", finding.Remediation))
		}
		sb.WriteString("\n")
	}
	
	sb.WriteString("\nProvide your analysis in this format:\n")
	sb.WriteString("SUMMARY: [brief overall assessment]\n\n")
	sb.WriteString("FINDINGS:\n")
	sb.WriteString("[For each finding, number them and provide explanation and fix steps]\n\n")
	sb.WriteString("RECOMMENDATIONS:\n")
	sb.WriteString("[Prioritized list of actions to take]\n")
	
	return sb.String()
}

func callAnthropic(config *AIConfig, prompt string) (string, error) {
	reqBody := AnthropicRequest{
		Model:     config.Model,
		MaxTokens: 4096,
		Messages: []Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", config.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var anthropicResp AnthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&anthropicResp); err != nil {
		return "", err
	}

	if len(anthropicResp.Content) == 0 {
		return "", fmt.Errorf("no content in response")
	}

	return anthropicResp.Content[0].Text, nil
}

func callOpenAI(config *AIConfig, prompt string) (string, error) {
	reqBody := OpenAIRequest{
		Model: config.Model,
		Messages: []Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens: 4096,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", config.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.APIKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var openaiResp OpenAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&openaiResp); err != nil {
		return "", err
	}

	if len(openaiResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return openaiResp.Choices[0].Message.Content, nil
}

func callOllama(config *AIConfig, prompt string) (string, error) {
	reqBody := OllamaRequest{
		Model:  config.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", config.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return ollamaResp.Response, nil
}

func parseExplanation(aiResponse string, findings []Finding) *ExplanationResponse {
	response := &ExplanationResponse{
		Explanations:    make([]FindingExplanation, 0),
		Recommendations: make([]string, 0),
	}

	// Simple parsing - split by sections
	sections := strings.Split(aiResponse, "\n\n")
	
	for _, section := range sections {
		section = strings.TrimSpace(section)
		
		if strings.HasPrefix(section, "SUMMARY:") {
			response.Summary = strings.TrimPrefix(section, "SUMMARY:")
			response.Summary = strings.TrimSpace(response.Summary)
		} else if strings.Contains(section, "RECOMMENDATIONS:") {
			// Extract recommendations
			lines := strings.Split(section, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && line != "RECOMMENDATIONS:" && !strings.HasPrefix(line, "RECOMMENDATIONS:") {
					// Remove bullet points and numbers
					line = strings.TrimPrefix(line, "-")
					line = strings.TrimPrefix(line, "*")
					line = strings.TrimSpace(line)
					if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
						// Remove leading numbers
						parts := strings.SplitN(line, ".", 2)
						if len(parts) == 2 {
							line = strings.TrimSpace(parts[1])
						}
					}
					if line != "" {
						response.Recommendations = append(response.Recommendations, line)
					}
				}
			}
		}
	}

	// If we couldn't parse properly, use the whole response as summary
	if response.Summary == "" {
		response.Summary = aiResponse
	}

	return response
}

// FormatExplanation formats the explanation for terminal output
func FormatExplanation(response *ExplanationResponse) string {
	var sb strings.Builder
	
	sb.WriteString("\n╔══════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║        🤖 AI SECURITY ANALYSIS                           ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════╝\n\n")
	
	sb.WriteString("📊 SUMMARY\n")
	sb.WriteString("─────────────────────────────────────────────────────────\n")
	sb.WriteString(wrapText(response.Summary, 70))
	sb.WriteString("\n\n")
	
	if len(response.Recommendations) > 0 {
		sb.WriteString("💡 KEY RECOMMENDATIONS\n")
		sb.WriteString("─────────────────────────────────────────────────────────\n")
		for i, rec := range response.Recommendations {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, wrapText(rec, 67)))
		}
		sb.WriteString("\n")
	}
	
	return sb.String()
}

func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}
	
	var result strings.Builder
	words := strings.Fields(text)
	lineLen := 0
	
	for _, word := range words {
		if lineLen+len(word)+1 > width {
			result.WriteString("\n")
			lineLen = 0
		}
		if lineLen > 0 {
			result.WriteString(" ")
			lineLen++
		}
		result.WriteString(word)
		lineLen += len(word)
	}
	
	return result.String()
}
