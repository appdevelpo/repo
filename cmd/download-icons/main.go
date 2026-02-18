package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	repoDir     = "repo"
	iconDir     = "icon"
	baseIconURL = "https://raw.githubusercontent.com/appdevelpo/repo/refs/heads/miru_alpha/icon"
)

func main() {
	// Create icon directory if it doesn't exist
	if err := os.MkdirAll(iconDir, 0755); err != nil {
		log.Fatalf("Failed to create icon directory: %v", err)
	}

	// Read all extension files
	files, err := os.ReadDir(repoDir)
	if err != nil {
		log.Fatalf("Failed to read repo directory: %v", err)
	}

	fmt.Println("Starting icon download and update process...")
	fmt.Printf("Total files to process: %d\n\n", len(files))

	successCount := 0
	skipCount := 0
	errorCount := 0
	var failedFiles []string

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(repoDir, file.Name())
		pkg := extractPackageName(filePath)

		if pkg == "" {
			log.Printf("⊘ SKIP %s: Could not extract package name\n", file.Name())
			skipCount++
			continue
		}

		iconURL := extractIconURL(filePath)
		if iconURL == "" {
			log.Printf("⊘ SKIP %s (%s): No @icon found\n", file.Name(), pkg)
			skipCount++
			continue
		}

		// Download icon
		iconPath, ext, err := downloadIcon(iconURL, pkg)
		if err != nil {
			log.Printf("✗ ERROR %s (%s): Failed to download icon: %v\n", file.Name(), pkg, err)
			failedFiles = append(failedFiles, file.Name())
			errorCount++
			continue
		}

		// Update @icon property in extension file
		newIconURL := fmt.Sprintf("%s/%s.%s", baseIconURL, pkg, ext)
		if err := updateIconProperty(filePath, newIconURL); err != nil {
			log.Printf("✗ ERROR %s (%s): Failed to update @icon property: %v\n", file.Name(), pkg, err)
			failedFiles = append(failedFiles, file.Name())
			errorCount++
			// Clean up downloaded icon on failure
			os.Remove(iconPath)
			continue
		}

		log.Printf("✓ SUCCESS %s (%s): Downloaded and updated icon\n", file.Name(), pkg)
		successCount++
	}

	// Write failed files to a log file
	failedLog := filepath.Join(iconDir, "failed_files.txt")
	failedContent := strings.Join(failedFiles, "\n")
	os.WriteFile(failedLog, []byte(failedContent), 0644)

	fmt.Printf("\n\n=== Summary ===\n")
	fmt.Printf("Successful: %d\n", successCount)
	fmt.Printf("Skipped: %d\n", skipCount)
	fmt.Printf("Errors: %d\n", errorCount)
	fmt.Printf("Total: %d\n", len(files))
	fmt.Printf("\nFailed files list saved to: %s\n", failedLog)
}

// extractPackageName extracts the @package property from an extension file
func extractPackageName(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	r := regexp.MustCompile(`// @package\s+(.+?)[\r\n]`)
	matches := r.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// extractIconURL extracts the @icon property from an extension file
func extractIconURL(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	r := regexp.MustCompile(`// @icon\s+(.+?)[\r\n]`)
	matches := r.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// downloadIcon downloads an icon from the given URL and saves it to the icon directory
// Returns the saved file path, file extension, and any error
func downloadIcon(iconURL, pkg string) (string, string, error) {
	// Parse URL to get file extension
	parsedURL, err := url.Parse(iconURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %w", err)
	}

	// Get file extension from URL path
	ext := filepath.Ext(parsedURL.Path)
	if ext == "" {
		ext = "png" // Default to PNG if no extension
	} else {
		ext = strings.TrimPrefix(ext, ".") // Remove the dot
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Download the file
	resp, err := client.Get(iconURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Save to file
	iconPath := filepath.Join(iconDir, fmt.Sprintf("%s.%s", pkg, ext))
	outFile, err := os.Create(iconPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to write file: %w", err)
	}

	return iconPath, ext, nil
}

// updateIconProperty updates the @icon property in an extension file
func updateIconProperty(filePath, newIconURL string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	content := string(data)

	// Replace the @icon property
	r := regexp.MustCompile(`// @icon\s+.+?[\r\n]`)
	newContent := r.ReplaceAllString(content, fmt.Sprintf("// @icon         %s\n", newIconURL))

	// Write back to file
	return os.WriteFile(filePath, []byte(newContent), 0644)
}
