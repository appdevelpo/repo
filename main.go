package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
)

func main() {
	extensions := readRepoExtensions()
	f, err := os.Create("index.json")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	b, err := json.MarshalIndent(extensions, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	f.Write(b)

	f2, err2 := os.Create("README.md")
	if err2 != nil {
		log.Fatal(err)
	}
	defer f2.Close()

	readme := `
# Miru-Repo

Miru extensions repository | [Miru App Download](https://github.com/miru-project/miru-app) |

## List
|  Name   | Package | Version | Author | Language | Type | Source |
|  ----   | ---- | --- | ---  | ---  | --- | --- |
`

	for _, v := range extensions {
		url := fmt.Sprintf("[Source Code](%s)", "https://github.com/miru-project/repo/blob/main/repo/"+v["url"])
		nsfw := v["nsfw"] == "true"
		if nsfw {
			continue
		}
		readme += fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n", v["name"], v["package"], v["version"], v["author"], v["lang"], v["type"], url)
	}
	f2.WriteString(readme)
}

func readRepoExtensions() []map[string]string {
	de, err := os.ReadDir("repo")
	if err != nil {
		log.Fatal(err)
	}
	var extensions []map[string]string
	for _, de2 := range de {
		b, err := os.ReadFile(path.Join("repo", de2.Name()))
		if err != nil {
			log.Println("error:", err)
			continue
		}

		// Extract MiruExtension block
		r, _ := regexp.Compile(`MiruExtension([\s\S]+?)/MiruExtension`)
		data := r.FindAllString(string(b), -1)
		if len(data) < 1 {
			log.Println("error: not extension")
			continue
		}

		// Parse metadata from the content
		extension := parseExtensionMetadata(data[0], de2.Name())
		if extension != nil {
			extension["url"] = de2.Name()
			extensions = append(extensions, extension)
		}
	}
	return extensions
}

func parseExtensionMetadata(content string, fileName string) map[string]string {
	extension := make(map[string]string)

	// Regex to match @key value pattern
	re := regexp.MustCompile(`@(\w+)\s+(.*)`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		key := match[1]
		value := strings.TrimSpace(match[2])

		switch key {
		case "name":
			extension["name"] = value
		case "version":
			extension["version"] = value
		case "author":
			extension["author"] = value
		case "license":
			extension["license"] = value
		case "lang":
			extension["lang"] = value
		case "icon":
			extension["icon"] = value
		case "package":
			extension["package"] = value
		case "webSite":
			extension["webSite"] = value
		case "description":
			extension["description"] = value
		case "api":
			extension["api"] = value
		case "type":
			extension["type"] = value
		case "tags":
			// Split tags by comma and trim whitespace
			extension["tags"] = value
		}
	}

	// Validate package name matches file name
	pkg, exists := extension["package"]
	if !exists || pkg+".js" != fileName {
		log.Printf("warning: package name does not match file name | file: %s | package: %s\n", fileName, pkg)
		return nil
	}

	return extension
}
