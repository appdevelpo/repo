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

## Develop your own extension

This repo doubles as the extension development bench. See [plug/README.md](plug/README.md).

- The plug/ folder is a plug-and-play test bench for Go (Scriggo V2) extensions.
- Copy an existing extension as your starting point — for Go: repo/golang/rawkuma.go.
- Edit your plug, then run the dual harness: cd plug && go test -v . (or press F5 in
  VS Code — see .vscode/launch.json). Every entry point runs natively AND through
  the Scriggo VM, printing each result as JSON.
- To publish: the plug file must live at repo/golang/<package>.go (Go) or
  repo/js/<package>.js (JavaScript), with the @package header matching the file
  name and @apiVersion 2. The index.json regenerates automatically on push.

> The bench needs a Go >= 1.27 toolchain (the index generator itself is
> stdlib-only). Locally, point the bench at a miru-core checkout via go.work —
> see plug/README.md.

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
	// Extensions live in per-runtime subdirectories: repo/js for the
	// JavaScript (goja) runtime and repo/golang for Go (Scriggo).
	subdirs := []string{"js", "golang"}
	var extensions []map[string]string
	for _, sub := range subdirs {
		de, err := os.ReadDir(path.Join("repo", sub))
		if err != nil {
			log.Println("error:", err)
			continue
		}
		for _, de2 := range de {
			b, err := os.ReadFile(path.Join("repo", sub, de2.Name()))
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
				// The download URL must carry the subdirectory so the app can
				// fetch e.g. js/345movie.net.js or golang/rawkuma.go.
				extension["url"] = sub + "/" + de2.Name()
				extensions = append(extensions, extension)
			}
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
		case "apiVersion":
			extension["apiVersion"] = value
		case "nsfw":
			extension["nsfw"] = value
		case "type":
			extension["type"] = value
		case "tags":
			// Split tags by comma and trim whitespace
			extension["tags"] = value
		}
	}

	// Validate package name matches file name (both runtimes: js and golang)
	pkg, exists := extension["package"]
	if !exists {
		log.Printf("warning: missing package name | file: %s\n", fileName)
		return nil
	}
	if strings.HasSuffix(fileName, ".js") {
		if pkg+".js" != fileName {
			log.Printf("warning: package name does not match file name | file: %s | package: %s\n", fileName, pkg)
			return nil
		}
	} else if strings.HasSuffix(fileName, ".go") {
		if pkg+".go" != fileName {
			log.Printf("warning: package name does not match file name | file: %s | package: %s\n", fileName, pkg)
			return nil
		}
	} else {
		log.Printf("warning: unsupported extension file | file: %s\n", fileName)
		return nil
	}

	return extension
}
