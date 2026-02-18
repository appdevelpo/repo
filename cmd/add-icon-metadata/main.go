package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	iconDir := "icon"
	repoDir := "repo"

	// Read all files from icon directory
	files, err := os.ReadDir(iconDir)
	if err != nil {
		log.Fatalf("Error reading icon directory: %v\n", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		iconFileName := file.Name()
		// Extract package name from icon filename (e.g., "345movie.net.ico" -> "345movie.net")
		packageName := strings.TrimSuffix(iconFileName, filepath.Ext(iconFileName))

		// Find corresponding extension file in repo directory
		extFilePath := path.Join(repoDir, packageName+".js")

		if _, err := os.Stat(extFilePath); os.IsNotExist(err) {
			log.Printf("Warning: Extension file not found for icon %s (expected %s)\n", iconFileName, extFilePath)
			continue
		}

		// Read extension file
		content, err := os.ReadFile(extFilePath)
		if err != nil {
			log.Printf("Error reading extension file %s: %v\n", extFilePath, err)
			continue
		}

		contentStr := string(content)

		// Check if @icon already exists
		if strings.Contains(contentStr, "// @icon") {
			log.Printf("Skipping %s - @icon already exists\n", extFilePath)
			continue
		}

		// Build the icon URL
		iconURL := fmt.Sprintf("https://raw.githubusercontent.com/appdevelpo/repo/refs/heads/miru_alpha/icon/%s", iconFileName)

		// Add @icon property after @webSite or after @package if @webSite doesn't exist
		newContent := addIconProperty(contentStr, iconURL)

		// Write back to file
		err = os.WriteFile(extFilePath, []byte(newContent), 0644)
		if err != nil {
			log.Printf("Error writing extension file %s: %v\n", extFilePath, err)
			continue
		}

		log.Printf("✓ Updated %s with icon: %s\n", extFilePath, iconURL)
	}

	log.Println("Icon metadata addition completed!")
}

func addIconProperty(content string, iconURL string) string {
	// Pattern to find the @webSite line
	websitePattern := regexp.MustCompile(`(// @webSite\s+.*)`)

	// Check if @webSite exists
	if websitePattern.MatchString(content) {
		// Add @icon after @webSite
		return websitePattern.ReplaceAllString(content, "$1\n// @icon        "+iconURL)
	}

	// If @webSite doesn't exist, add after @type
	typePattern := regexp.MustCompile(`(// @type\s+.*)`)
	if typePattern.MatchString(content) {
		return typePattern.ReplaceAllString(content, "$1\n// @icon        "+iconURL)
	}

	// Fallback: add after @package
	packagePattern := regexp.MustCompile(`(// @package\s+.*)`)
	if packagePattern.MatchString(content) {
		return packagePattern.ReplaceAllString(content, "$1\n// @icon        "+iconURL)
	}

	// Last resort: add after @license
	licensePattern := regexp.MustCompile(`(// @license\s+.*)`)
	return licensePattern.ReplaceAllString(content, "$1\n// @icon        "+iconURL)
}
