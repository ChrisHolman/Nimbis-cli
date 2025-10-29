package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var archAliases = map[string][]string{
	"amd64": {"amd64", "x86_64"},
	"arm64": {"arm64", "aarch64"},
}

// ScannerInstaller handles automatic installation of scanners
type ScannerInstaller struct {
	cacheDir string
}

// InstallationResult tracks what happened during installation
type InstallationResult struct {
	Name      string
	Installed bool
	Skipped   bool
	Failed    bool
	Error     string
	Message   string
}

// NewScannerInstaller creates a new installer
func NewScannerInstaller() (*ScannerInstaller, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cacheDir := filepath.Join(homeDir, ".nimbis", "scanners")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}

	return &ScannerInstaller{
		cacheDir: cacheDir,
	}, nil
}

// InstallAll installs all available scanners
func (i *ScannerInstaller) InstallAll() error {
	fmt.Printf("\n%s╔════════════════════════════════════════════════════════════╗%s\n", BrightCyan, Reset)
	fmt.Printf("%s║  🔧 AUTO-INSTALLING SECURITY SCANNERS                     ║%s\n", BrightCyan, Reset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", BrightCyan, Reset)
	
	fmt.Println("📦 Installing scanners to:", i.cacheDir)
	fmt.Println("⏱️  This may take a few minutes on first run...")
	fmt.Println()

	scanners := []struct {
		name    string
		install func() (*InstallationResult, error)
	}{
		{"Trivy", i.installTrivy},
		{"Grype", i.installGrype},
		{"Syft", i.installSyft},
		{"TruffleHog", i.installTruffleHog},
		{"Checkov", i.installCheckov},
		{"OpenGrep", i.installOpenGrep},
	}

	results := []InstallationResult{}
	
	for _, scanner := range scanners {
		fmt.Printf("   📥 Installing %s...", scanner.name)
		result, err := scanner.install()
		
		if err != nil {
			if result == nil {
				result = &InstallationResult{
					Name:   scanner.name,
					Failed: true,
					Error:  err.Error(),
				}
			}
		}
		
		results = append(results, *result)
		
		// Print immediate feedback
		if result.Installed {
			fmt.Printf(" %s✓%s\n", BrightGreen, Reset)
		} else if result.Skipped {
			fmt.Printf(" %s⊘%s %s\n", Yellow, Reset, result.Message)
		} else if result.Failed {
			fmt.Printf(" %s✗%s %s\n", BrightRed, Reset, result.Message)
		}
	}

	// Print summary
	i.printInstallationSummary(results)

	// Check if we installed at least one scanner
	installedCount := 0
	for _, r := range results {
		if r.Installed {
			installedCount++
		}
	}

	if installedCount == 0 {
		return fmt.Errorf("failed to install any scanners")
	}

	// Add to PATH for current session
	currentPath := os.Getenv("PATH")
	if !strings.Contains(currentPath, i.cacheDir) {
		os.Setenv("PATH", i.cacheDir+string(os.PathListSeparator)+currentPath)
	}

	return nil
}

// printInstallationSummary prints a detailed summary of what was installed
func (i *ScannerInstaller) printInstallationSummary(results []InstallationResult) {
	installed := []InstallationResult{}
	skipped := []InstallationResult{}
	failed := []InstallationResult{}

	for _, r := range results {
		if r.Installed {
			installed = append(installed, r)
		} else if r.Skipped {
			skipped = append(skipped, r)
		} else if r.Failed {
			failed = append(failed, r)
		}
	}

	fmt.Println()
	fmt.Printf("%s╔════════════════════════════════════════════════════════════╗%s\n", Bold, Reset)
	fmt.Printf("%s║  INSTALLATION SUMMARY                                      ║%s\n", Bold, Reset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", Bold, Reset)

	if len(installed) > 0 {
		fmt.Printf("%s✅ Successfully Installed (%d):%s\n", BrightGreen, len(installed), Reset)
		for _, r := range installed {
			fmt.Printf("   %s✓%s %s\n", BrightGreen, Reset, r.Name)
		}
		fmt.Println()
	}

	if len(skipped) > 0 {
		fmt.Printf("%s⊘ Skipped (%d):%s\n", Yellow, len(skipped), Reset)
		for _, r := range skipped {
			fmt.Printf("   %s⊘%s %s\n", Yellow, Reset, r.Name)
			if r.Message != "" {
				fmt.Printf("      %s→ %s%s\n", Dim, r.Message, Reset)
			}
		}
		fmt.Println()
	}

	if len(failed) > 0 {
		fmt.Printf("%s✗ Failed to Install (%d):%s\n", BrightRed, len(failed), Reset)
		for _, r := range failed {
			fmt.Printf("   %s✗%s %s\n", BrightRed, Reset, r.Name)
			if r.Message != "" {
				fmt.Printf("      %s→ %s%s\n", Dim, r.Message, Reset)
			}
		}
		fmt.Println()
	}

	// Print manual installation instructions for failed/skipped
	if len(skipped) > 0 || len(failed) > 0 {
		fmt.Printf("%s💡 Manual Installation Instructions:%s\n", Bold, Reset)
		fmt.Println()

		for _, r := range append(skipped, failed...) {
			switch r.Name {
			case "Checkov":
				fmt.Printf("%s   Checkov (IaC Scanner):%s\n", Bold, Reset)
				fmt.Println("      Requires: Python 3 and pip")
				fmt.Println("      Command:  pip3 install checkov")
				fmt.Println("      Or:       pip install checkov")
				fmt.Println()

			case "OpenGrep":
				fmt.Printf("%s   OpenGrep (SAST):%s\n", Bold, Reset)
				fmt.Println("      May not have pre-built binaries for your platform")
				if runtime.GOOS == "windows" {
					fmt.Println("      Windows:  Download from https://github.com/semgrep/semgrep/releases")
				} else if runtime.GOOS == "darwin" {
					fmt.Println("      macOS:    brew install semgrep")
				} else {
					fmt.Println("      Linux:    pip3 install semgrep")
				}
				fmt.Println()

			case "Trivy":
				fmt.Printf("%s   Trivy (IaC/Secrets/Vulnerabilities):%s\n", Bold, Reset)
				if runtime.GOOS == "windows" {
					fmt.Println("      Windows:  choco install trivy")
					fmt.Println("      Or:       Download from https://github.com/aquasecurity/trivy/releases")
				} else if runtime.GOOS == "darwin" {
					fmt.Println("      macOS:    brew install trivy")
				} else {
					fmt.Println("      Linux:    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -")
					fmt.Println("                sudo apt-get install trivy")
				}
				fmt.Println()

			case "Grype":
				fmt.Printf("%s   Grype (Vulnerability Scanner):%s\n", Bold, Reset)
				if runtime.GOOS == "windows" {
					fmt.Println("      Windows:  choco install grype")
					fmt.Println("      Or:       Download from https://github.com/anchore/grype/releases")
				} else if runtime.GOOS == "darwin" {
					fmt.Println("      macOS:    brew install grype")
				} else {
					fmt.Println("      Linux:    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh")
				}
				fmt.Println()

			case "Syft":
				fmt.Printf("%s   Syft (SBOM Generator):%s\n", Bold, Reset)
				if runtime.GOOS == "windows" {
					fmt.Println("      Windows:  choco install syft")
					fmt.Println("      Or:       Download from https://github.com/anchore/syft/releases")
				} else if runtime.GOOS == "darwin" {
					fmt.Println("      macOS:    brew install syft")
				} else {
					fmt.Println("      Linux:    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh")
				}
				fmt.Println()

			case "TruffleHog":
				fmt.Printf("%s   TruffleHog (Secret Scanner):%s\n", Bold, Reset)
				if runtime.GOOS == "windows" {
					fmt.Println("      Windows:  choco install trufflehog")
					fmt.Println("      Or:       Download from https://github.com/trufflesecurity/trufflehog/releases")
				} else if runtime.GOOS == "darwin" {
					fmt.Println("      macOS:    brew install trufflehog")
				} else {
					fmt.Println("      Linux:    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh")
				}
				fmt.Println()
			}
		}
	}

	fmt.Printf("%s💡 Tip:%s After manual installation, restart your terminal and run nimbis again\n\n", Bold, Reset)
}

// installTrivy installs Trivy scanner
func (i *ScannerInstaller) installTrivy() (*InstallationResult, error) {
	result := &InstallationResult{Name: "Trivy"}
	
	binaryName := "trivy"
	if runtime.GOOS == "windows" {
		binaryName = "trivy.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		result.Installed = true
		result.Message = "already installed"
		return result, nil
	}

	version := "0.55.2"
	owner := "aquasecurity"
	repo := "trivy"
	tag := "v" + version

	var filters []string
	if runtime.GOOS == "windows" {
		filters = []string{"windows", ".zip"}
		if runtime.GOARCH == "amd64" {
			filters = append(filters, "64bit")
		}
	} else {
		filters = []string{runtime.GOOS, ".tar.gz"}
		if a, ok := archAliases[runtime.GOARCH]; ok {
			filters = append(filters, a...)
		} else {
			filters = append(filters, runtime.GOARCH)
		}
	}

	assetURL, err := i.getGitHubAssetURL(owner, repo, tag, filters)
	if err != nil {
		result.Failed = true
		result.Message = "binary not available for your platform"
		result.Error = err.Error()
		return result, err
	}

	if err := i.downloadAndExtract(assetURL, binaryName, binaryPath); err != nil {
		result.Failed = true
		result.Message = "download/extract failed"
		result.Error = err.Error()
		return result, err
	}

	result.Installed = true
	return result, nil
}

// installTruffleHog installs TruffleHog scanner
func (i *ScannerInstaller) installTruffleHog() (*InstallationResult, error) {
	result := &InstallationResult{Name: "TruffleHog"}
	
	binaryName := "trufflehog"
	if runtime.GOOS == "windows" {
		binaryName = "trufflehog.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		result.Installed = true
		result.Message = "already installed"
		return result, nil
	}

	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		result.Skipped = true
		result.Message = fmt.Sprintf("only available for amd64/arm64, not %s", runtime.GOARCH)
		return result, nil
	}

	version := "3.82.13"
	owner := "trufflesecurity"
	repo := "trufflehog"
	tag := "v" + version

	filters := []string{runtime.GOOS, ".tar.gz"}
	if a, ok := archAliases[runtime.GOARCH]; ok {
		filters = append(filters, a...)
	} else {
		filters = append(filters, runtime.GOARCH)
	}

	assetURL, err := i.getGitHubAssetURL(owner, repo, tag, filters)
	if err != nil {
		result.Failed = true
		result.Message = "binary not available for your platform"
		result.Error = err.Error()
		return result, err
	}

	if err := i.downloadAndExtract(assetURL, binaryName, binaryPath); err != nil {
		result.Failed = true
		result.Message = "download/extract failed"
		result.Error = err.Error()
		return result, err
	}

	result.Installed = true
	return result, nil
}

// installGrype installs Grype scanner
func (i *ScannerInstaller) installGrype() (*InstallationResult, error) {
	result := &InstallationResult{Name: "Grype"}
	
	binaryName := "grype"
	if runtime.GOOS == "windows" {
		binaryName = "grype.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		result.Installed = true
		result.Message = "already installed"
		return result, nil
	}

	version := "0.84.0"
	owner := "anchore"
	repo := "grype"
	tag := "v" + version

	var filters []string
	if runtime.GOOS == "windows" {
		filters = []string{"windows", ".zip"}
	} else {
		filters = []string{runtime.GOOS, ".tar.gz"}
	}

	if a, ok := archAliases[runtime.GOARCH]; ok {
		filters = append(filters, a...)
	} else {
		filters = append(filters, runtime.GOARCH)
	}

	assetURL, err := i.getGitHubAssetURL(owner, repo, tag, filters)
	if err != nil {
		result.Failed = true
		result.Message = "binary not available for your platform"
		result.Error = err.Error()
		return result, err
	}

	if err := i.downloadAndExtract(assetURL, binaryName, binaryPath); err != nil {
		result.Failed = true
		result.Message = "download/extract failed"
		result.Error = err.Error()
		return result, err
	}

	result.Installed = true
	return result, nil
}

// installSyft installs Syft scanner
func (i *ScannerInstaller) installSyft() (*InstallationResult, error) {
	result := &InstallationResult{Name: "Syft"}
	
	binaryName := "syft"
	if runtime.GOOS == "windows" {
		binaryName = "syft.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		result.Installed = true
		result.Message = "already installed"
		return result, nil
	}

	version := "1.17.0"
	owner := "anchore"
	repo := "syft"
	tag := "v" + version

	var filters []string
	if runtime.GOOS == "windows" {
		filters = []string{"windows", ".zip"}
	} else {
		filters = []string{runtime.GOOS, ".tar.gz"}
	}

	if a, ok := archAliases[runtime.GOARCH]; ok {
		filters = append(filters, a...)
	} else {
		filters = append(filters, runtime.GOARCH)
	}

	assetURL, err := i.getGitHubAssetURL(owner, repo, tag, filters)
	if err != nil {
		result.Failed = true
		result.Message = "binary not available for your platform"
		result.Error = err.Error()
		return result, err
	}

	if err := i.downloadAndExtract(assetURL, binaryName, binaryPath); err != nil {
		result.Failed = true
		result.Message = "download/extract failed"
		result.Error = err.Error()
		return result, err
	}

	result.Installed = true
	return result, nil
}

// installCheckov installs Checkov using pip
func (i *ScannerInstaller) installCheckov() (*InstallationResult, error) {
	result := &InstallationResult{Name: "Checkov"}
	
	var pipCmd string
	if _, err := exec.LookPath("pip3"); err == nil {
		pipCmd = "pip3"
	} else if _, err := exec.LookPath("pip"); err == nil {
		pipCmd = "pip"
	} else {
		result.Skipped = true
		result.Message = "Python/pip not found"
		return result, nil
	}

	// Check if already installed
	checkCmd := exec.Command(pipCmd, "show", "checkov")
	if err := checkCmd.Run(); err == nil {
		result.Installed = true
		result.Message = "already installed"
		return result, nil
	}

	// Install checkov
	installCmd := exec.Command(pipCmd, "install", "--user", "checkov")
	output, err := installCmd.CombinedOutput()
	if err != nil {
		result.Failed = true
		result.Message = "pip install failed"
		result.Error = string(output)
		return result, fmt.Errorf("pip install failed: %w", err)
	}

	result.Installed = true
	return result, nil
}

// installOpenGrep installs OpenGrep
func (i *ScannerInstaller) installOpenGrep() (*InstallationResult, error) {
	result := &InstallationResult{Name: "OpenGrep"}
	
	binaryName := "opengrep"
	if runtime.GOOS == "windows" {
		binaryName = "opengrep.exe"
	}

	binaryPath := filepath.Join(i.cacheDir, binaryName)
	if _, err := os.Stat(binaryPath); err == nil {
		result.Installed = true
		result.Message = "already installed"
		return result, nil
	}

	version := "1.101.0"
	owner := "opengrep"
	repo := "opengrep"
	tag := "v" + version

	var filters []string
	if runtime.GOOS == "windows" {
		filters = []string{"windows", ".zip"}
	} else {
		filters = []string{runtime.GOOS, ".tar.gz"}
	}

	if a, ok := archAliases[runtime.GOARCH]; ok {
		filters = append(filters, a...)
	} else {
		filters = append(filters, runtime.GOARCH)
	}

	assetURL, err := i.getGitHubAssetURL(owner, repo, tag, filters)
	if err != nil {
		result.Skipped = true
		result.Message = "pre-built binary not available"
		return result, nil
	}

	if err := i.downloadAndExtract(assetURL, binaryName, binaryPath); err != nil {
		result.Failed = true
		result.Message = "download/extract failed"
		result.Error = err.Error()
		return result, err
	}

	result.Installed = true
	return result, nil
}

// getGitHubAssetURL queries the GitHub Releases API and returns the download URL
func (i *ScannerInstaller) getGitHubAssetURL(owner, repo, tag string, filters []string) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tag)
	resp, err := http.Get(apiURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to query releases: %s", resp.Status)
	}

	var release struct {
		Assets []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	var bestMatch string
	bestMatchCount := 0

	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		matchCount := 0

		for _, filter := range filters {
			if strings.Contains(name, strings.ToLower(filter)) {
				matchCount++
			}
		}

		if matchCount > bestMatchCount {
			bestMatch = asset.BrowserDownloadURL
			bestMatchCount = matchCount
		}
	}

	if bestMatchCount >= 2 {
		return bestMatch, nil
	}

	return "", fmt.Errorf("no matching asset found for %s/%s %s (platform: %s/%s)", owner, repo, tag, runtime.GOOS, runtime.GOARCH)
}

// downloadAndExtract downloads and extracts a binary
func (i *ScannerInstaller) downloadAndExtract(url, binaryName, binaryPath string) error {
	tempFile := filepath.Join(os.TempDir(), filepath.Base(url))

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	out, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	defer out.Close()
	defer os.Remove(tempFile)

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	out.Close()

	if strings.HasSuffix(url, ".tar.gz") {
		return i.extractTarGz(tempFile, binaryName, binaryPath)
	} else if strings.HasSuffix(url, ".zip") {
		return i.extractZip(tempFile, binaryName, binaryPath)
	}

	return fmt.Errorf("unsupported archive format")
}

// extractTarGz extracts a tar.gz file
func (i *ScannerInstaller) extractTarGz(archivePath, binaryName, binaryPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		headerBase := filepath.Base(hdr.Name)
		if headerBase != binaryName && headerBase != strings.TrimSuffix(binaryName, ".exe") {
			continue
		}

		if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
			return err
		}

		out, err := os.Create(binaryPath)
		if err != nil {
			return err
		}

		const maxExtractSize = 200 * 1024 * 1024
		limited := io.LimitReader(tr, maxExtractSize)
		if _, err := io.Copy(out, limited); err != nil {
			out.Close()
			return err
		}
		out.Close()

		if runtime.GOOS != "windows" {
			if err := os.Chmod(binaryPath, 0755); err != nil {
				return err
			}
		}

		return nil
	}

	return fmt.Errorf("binary %s not found in archive", binaryName)
}

// extractZip extracts a zip file
func (i *ScannerInstaller) extractZip(archivePath, binaryName, binaryPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if filepath.Base(f.Name) != binaryName {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
			return err
		}

		out, err := os.Create(binaryPath)
		if err != nil {
			return err
		}

		const maxExtractSize = 200 * 1024 * 1024
		limited := io.LimitReader(rc, maxExtractSize)
		if _, err := io.Copy(out, limited); err != nil {
			out.Close()
			return err
		}
		out.Close()

		if runtime.GOOS != "windows" {
			if err := os.Chmod(binaryPath, 0755); err != nil {
				return err
			}
		}

		return nil
	}

	return fmt.Errorf("binary %s not found in zip archive", binaryName)
}

// AddToPath adds the cache directory to PATH permanently
func (i *ScannerInstaller) AddToPath() {
	currentPath := os.Getenv("PATH")
	if !strings.Contains(currentPath, i.cacheDir) {
		os.Setenv("PATH", i.cacheDir+string(os.PathListSeparator)+currentPath)
	}
}

// GetCacheDir returns the cache directory
func (i *ScannerInstaller) GetCacheDir() string {
	return i.cacheDir
}