package main

import (
"fmt"
"log"
"os"
"path/filepath"
"regexp"
"strings"
)

const (
repoDir      = "repo"
iconDir      = "icon"
failedFilesPath = "icon/failed_files.txt"
)

func main() {
// Read the failed files list
data, err := os.ReadFile(failedFilesPath)
if err != nil {
log.Fatalf("Failed to read failed files list: %v", err)
}

failedFiles := strings.Split(strings.TrimSpace(string(data)), "\n")
fmt.Printf("Processing %d failed files to remove @icon properties...\n\n", len(failedFiles))

successCount := 0
errorCount := 0

for _, filename := range failedFiles {
if filename == "" {
continue
}

filePath := filepath.Join(repoDir, filename)

// Check if file exists
if _, err := os.Stat(filePath); err != nil {
fmt.Printf("⊘ SKIP %s: File not found\n", filename)
continue
}

// Remove the @icon property
if err := removeIconProperty(filePath); err != nil {
fmt.Printf("✗ ERROR %s: Failed to remove @icon property: %v\n", filename, err)
errorCount++
continue
}

fmt.Printf("✓ SUCCESS %s: Removed @icon property\n", filename)
successCount++
}

fmt.Printf("\n\n=== Summary ===\n")
fmt.Printf("Successful: %d\n", successCount)
fmt.Printf("Errors: %d\n", errorCount)
fmt.Printf("Total: %d\n", len(failedFiles))
}

// removeIconProperty removes the @icon property line from an extension file
func removeIconProperty(filePath string) error {
data, err := os.ReadFile(filePath)
if err != nil {
return err
}

content := string(data)

// Remove the entire @icon property line
r := regexp.MustCompile(`// @icon\s+.+?[\r\n]`)
newContent := r.ReplaceAllString(content, "")

// Write back to file
return os.WriteFile(filePath, []byte(newContent), 0644)
}
