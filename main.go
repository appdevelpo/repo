// Command repo-gen regenerates index.json and README.md from the extension
// sources in repo/.
//
// This repository publishes V2-API extensions ONLY. The generator enforces
// that: a JavaScript extension is V2 only when it opts in explicitly with
// "@apiVersion 2" (miru-core routes anything else to the legacy V1 runtime),
// and a Go (Scriggo) extension is V2 by definition -- the Go runtime has a
// single API version. An extension that does not satisfy its runtime's V2
// rule is rejected with an error instead of being published, so a stray V1
// file can never reach the app.
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

// apiVersion is the only API version this repository publishes.
const apiVersion = "2"

func main() {
	extensions, err := readRepoExtensions()
	if err != nil {
		log.Fatal(err)
	}
	if len(extensions) == 0 {
		log.Fatal("no extensions found in repo/ -- refusing to publish an empty index")
	}

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
		log.Fatal(err2)
	}
	defer f2.Close()

	readme := `
# Miru-Repo

Miru extensions repository | [Miru App Download](https://github.com/miru-project/miru-app) |

This repository publishes **V2 API** extensions only. See
[docs/V2-API.md](docs/V2-API.md) for the full contract.

## Develop your own extension

This repo doubles as the extension development bench. See [plug/README.md](plug/README.md).

- The plug/ folder is a plug-and-play test bench for Go (Scriggo V2) extensions.
- Copy an existing extension as your starting point — for Go: repo/golang/rawkuma.net.go.
- Edit your plug, then run the dual harness: cd plug && go test -v . (or press F5 in
  VS Code — see .vscode/launch.json). Every entry point runs natively AND through
  the Scriggo VM, printing each result as JSON.
- To publish: the plug file must live at repo/golang/<package>.go (Go) or
  repo/js/<package>.js (JavaScript), with the @package header matching the file
  name and @apiVersion 2. The index.json regenerates automatically on push.

> The bench needs a Go >= 1.27 toolchain (the index generator itself is
> stdlib-only). The V2 runtime (miru-core) is vendored as a git submodule, so
> the bench always builds against the pinned upstream API — run
> git submodule update --init --recursive after cloning.

## List
|  Name   | Package | Version | Author | Language | Type | API | Source |
|  ----   | ---- | --- | ---  | --- | --- | --- | --- |
`

	for _, v := range extensions {
		url := fmt.Sprintf("[Source Code](%s)", "https://github.com/miru-project/repo/blob/main/repo/"+v["url"])
		nsfw := v["nsfw"] == "true"
		if nsfw {
			continue
		}
		readme += fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |\n", v["name"], v["package"], v["version"], v["author"], v["lang"], v["type"], v["apiVersion"], url)
	}
	f2.WriteString(readme)
}

// readRepoExtensions scans the runtime subdirectories of repo/ and returns the
// metadata of every extension that qualifies for publication.
//
// Extensions live in per-runtime subdirectories: repo/js for the JavaScript
// (goja) runtime and repo/golang for Go (Scriggo). The subdirectory is not
// cosmetic — it is what tells the two runtimes apart on the app side, so the
// download URL must carry it.
func readRepoExtensions() ([]map[string]string, error) {
	subdirs := []string{"js", "golang"}
	var extensions []map[string]string
	for _, sub := range subdirs {
		de, err := os.ReadDir(path.Join("repo", sub))
		if err != nil {
			return nil, fmt.Errorf("read repo/%s: %w", sub, err)
		}
		for _, de2 := range de {
			if de2.IsDir() {
				continue
			}
			// Only extension sources are published. The directory may also
			// hold bookkeeping files (e.g. the go.mod that fences these
			// sources off the Go module graph) -- they are not extensions.
			if !isExtensionFile(de2.Name()) {
				continue
			}
			b, err := os.ReadFile(path.Join("repo", sub, de2.Name()))
			if err != nil {
				return nil, fmt.Errorf("read repo/%s/%s: %w", sub, de2.Name(), err)
			}

			// Extract MiruExtension block
			r, _ := regexp.Compile(`MiruExtension([\s\S]+?)/MiruExtension`)
			data := r.FindAllString(string(b), -1)
			if len(data) < 1 {
				return nil, fmt.Errorf("repo/%s/%s: not an extension (no ==MiruExtension== header)", sub, de2.Name())
			}

			// Parse metadata from the content
			extension, err := parseExtensionMetadata(data[0], de2.Name(), sub)
			if err != nil {
				return nil, fmt.Errorf("repo/%s/%s: %w", sub, de2.Name(), err)
			}
			// The download URL must carry the subdirectory so the app can
			// fetch e.g. js/345movie.net.js or golang/rawkuma.go.
			extension["url"] = sub + "/" + de2.Name()
			extensions = append(extensions, extension)
		}
	}
	return extensions, nil
}

// isExtensionFile reports whether a file in a runtime subdirectory is an
// extension source. The suffix decides the runtime: .js is the JavaScript
// (goja) runtime, .go is the Go (Scriggo) runtime. Any other file (a go.mod,
// a README, a .txt) is bookkeeping and is not published.
func isExtensionFile(name string) bool {
	return strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".go")
}

// parseExtensionMetadata parses the ==MiruExtension== header of an extension
// and validates it against the V2-API contract of its runtime.
//
// The validation is deliberately strict and returns an error instead of
// warning: this repository publishes V2 extensions only, so a file that
// cannot run on the V2 API is a publishing error, not a warning to be
// ignored. The app would otherwise install it and route it to the legacy V1
// runtime.
func parseExtensionMetadata(content string, fileName string, runtime string) (map[string]string, error) {
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
		return nil, fmt.Errorf("missing @package header")
	}
	switch {
	case strings.HasSuffix(fileName, ".js"):
		if pkg+".js" != fileName {
			return nil, fmt.Errorf("@package %q does not match file name", pkg)
		}
	case strings.HasSuffix(fileName, ".go"):
		if pkg+".go" != fileName {
			return nil, fmt.Errorf("@package %q does not match file name", pkg)
		}
	default:
		return nil, fmt.Errorf("unsupported extension file")
	}

	// Enforce the V2 API contract per runtime.
	//
	// JavaScript: V2 must be opted into EXPLICITLY with "@apiVersion 2".
	// miru-core routes a .js extension with a missing, empty or unrecognised
	// tag to the legacy V1 runtime, so anything but an exact "2" means this
	// file is a V1 extension and must not be published here.
	//
	// Go (Scriggo): the runtime has exactly one API version (V2) and is
	// routed by file suffix, never by the tag. A missing tag is therefore
	// still V2; an explicit non-2 tag is a contradiction worth rejecting.
	switch runtime {
	case "js":
		if extension["apiVersion"] != apiVersion {
			return nil, fmt.Errorf("not a V2 extension: a JavaScript extension must declare %q (got %q)", "@apiVersion 2", extension["apiVersion"])
		}
	case "golang":
		if v, ok := extension["apiVersion"]; ok && v != apiVersion {
			return nil, fmt.Errorf("not a V2 extension: the Go runtime is V2-only, so %q must be %q (got %q)", "@apiVersion", apiVersion, v)
		}
		extension["apiVersion"] = apiVersion
	default:
		return nil, fmt.Errorf("unknown runtime %q", runtime)
	}

	return extension, nil
}
