# Miru V2 Extension API

This repository publishes **V2 API** extensions only. A V1 extension is
rejected at publish time — the index generator fails with an error rather
than shipping it, because the app would otherwise route it to the legacy V1
runtime.

Two runtimes implement the same V2 contract:

| Runtime | Location | Entry points |
|---|---|---|
| JavaScript (goja) | `repo/js/<package>.js` | `load`, `latest`, `search`, `detail`, `watch`, `mirror`, `createFilter` |
| Go (Scriggo) | `repo/golang/<package>.go` | `Load`, `Latest`, `Search`, `Detail`, `Watch`, `Mirror`, `CreateFilter` |

The V2 API is defined by [miru-core](https://github.com/miru-project/miru-core),
which is vendored here as the `miru-core` git submodule. The submodule is
pinned to a known-good commit, so an extension always builds and runs against
the exact runtime it was written for.

```
git submodule update --init --recursive
```

---

## The API version rule

| Runtime | How V2 is selected | Anything else |
|---|---|---|
| JavaScript | `@apiVersion 2` in the header | **V1** — rejected by the generator |
| Go (Scriggo) | always V2 (routed by file suffix) | — |

JavaScript must opt in **explicitly**. A `.js` file with a missing, empty or
unrecognised `@apiVersion` tag is V1 as far as the runtime is concerned, and
this repository will not publish it. The Go runtime has exactly one API
version, so a Go extension is V2 by definition — but it should still declare
`@apiVersion 2` for consistency.

---

## Writing a JavaScript (V2) extension

A V2 JavaScript extension is a module of top-level functions. There is no
class, no `this`, and no `export default class ... extends Extension` — that
is the V1 shape.

```js
// ==MiruExtension==
// @name         Example V2
// @version      v0.0.1
// @author       you
// @lang         en
// @license      MIT
// @package      example.v2
// @type         manga
// @webSite      https://www.example.com
// @nsfw         false
// @apiVersion   2
// ==/MiruExtension==

var baseUrl = "https://www.example.com"

var load = async () => {
  await registerSetting({
    title: "Domain",
    key: "domain",
    type: "input",
    description: "Site domain",
    defaultValue: baseUrl,
  })
}

var latest = async (page) => {
  const { parseHTML } = require("linkedom")
  const res = await fetch(baseUrl + "/latest?page=" + page)
  const { document } = parseHTML(await res.text())
  return Array.from(document.querySelectorAll(".item")).map((el) => ({
    title: el.querySelector(".title").textContent.trim(),
    url: el.querySelector("a").href,
    cover: el.querySelector("img").src,
  }))
}
```

`repo/js/example.v2.js` is a working template — copy it.

### Entry points

| Function | Signature | Returns |
|---|---|---|
| `load` | `()` | — (runs once at load) |
| `latest` | `(page)` | `[{ title, url, cover }]` |
| `search` | `(keyword, page)` | `[{ title, url, cover }]` |
| `detail` | `(url)` | `{ title, cover, intro, episodes: [...] }` |
| `watch` | `(url)` | **a list of mirrors** (see below) |
| `mirror` | `(url)` | the final watchable resource |
| `createFilter` | `()` | filter definitions |

### watch() returns mirrors, not the final link

This is the single biggest difference from V1. Under V2, `watch()` returns a
**list of mirrors**; the user picks one and the app calls `mirror(url)` to
resolve it into the final resource. JS V2 and Go V2 share this contract so
the frontend drives both identically.

```js
var watch = async (url) => {
  return {
    groups: [
      {
        title: "Server 1",
        mirrors: [{ name: "Mirror 1", url: "https://.../1", headers: {} }],
      },
    ],
  }
}

var mirror = async (url) => {
  return {
    type: "mp4",              // content type: hls | mp4 | torrent | magnet
    url: url,
    headers: { "User-Agent": "Mozilla/5.0 ..." },
  }
}
```

The `type` field is the **content** type, never the extension type
(`bangumi`). If `mirror` is not defined, the host echoes the chosen mirror
URL back as the link itself.

### Host API available in V2

| Call | Purpose |
|---|---|
| `fetch(url, opts)` | HTTP request |
| `jsRequest(url, opts)` | HTTP request (raw) |
| `openWebView(url, opts)` | request with a real browser TLS/UA identity |
| `registerSetting({...})` / `getSetting(key)` / `setSetting(...)` | settings |
| `getCookies(url)` / `setCookies(url, list)` | cookies |
| `btoa(str)` / `atob(str)` | base64 |
| `require("linkedom")` | HTML parsing (`linkedom`, `crypto-js`, `md5`, `jsencrypt` are bundled) |

### State across calls

The goja VM is disposed after **every** call. The host keeps a structural
snapshot of the extension's own globals and restores it onto the fresh VM
before the next call, so:

- store state on `globalThis.x = ...` (a top-level `var` or an implicit
  global), and it survives;
- a top-level `let` / `const` binding is **not** on `globalThis` and resets
  per call by design;
- functions, objects, `Date`, `RegExp`, `Map`, `Set`, typed arrays and
  `BigInt` all keep their structure.

---

## Writing a Go (Scriggo V2) extension

A Go extension is a single file in `package plug`. The host compiles it on
its own with Scriggo and calls the entry points by name.

```go
// ==MiruExtension==
// @name         Example Go
// @version      v0.0.1
// @author       you
// @lang         en
// @license      MIT
// @package      example.go
// @type         manga
// @webSite      https://www.example.com
// @nsfw         false
// @apiVersion   2
// ==/MiruExtension==

package plug

import (
	"fmt"

	sdk "github.com/miru-project/miru-core/pkg/extension/golang/sdk"
)

func Latest(pkg string, page int) ([]sdk.ExtensionListItem, error) {
	return []sdk.ExtensionListItem{{Title: "One", URL: "https://example.com/1"}}, nil
}

func Search(pkg, kw string, page int, filter sdk.Filter) ([]sdk.ExtensionListItem, error) {
	return nil, nil
}

func Detail(pkg, url string) (*sdk.ExtensionDetail, error) {
	return &sdk.ExtensionDetail{Title: "One"}, nil
}

func Watch(pkg, url string) (*sdk.ExtensionWatch, error) {
	return &sdk.ExtensionWatch{
		Title:  "Example",
		Type:   "manga",
		Groups: []sdk.ExtensionMirrorGroup{{Title: "Chapter", Mirrors: []sdk.ExtensionMirror{{Name: "Source", URL: url}}}},
	}, nil
}

func Mirror(pkg, url string) (*sdk.ExtensionMangaWatchMirror, error) {
	return &sdk.ExtensionMangaWatchMirror{URLs: []string{url}}, nil
}

func CreateFilter(pkg string, filter sdk.Filter) map[string]sdk.FilterDefinition {
	return map[string]sdk.FilterDefinition{
		"type": sdk.NewSelect("Type", "manga").Option("manga", "Manga").Build(),
	}
}
```

`repo/golang/rawkuma.net.go` and `repo/golang/royalroad.com.go` are complete
worked examples.

### Entry points

`Latest(pkg, page)`, `Search(pkg, keyword, page, filter)`,
`Detail(pkg, url)`, `Watch(pkg, url)`, `Mirror(pkg, url)`,
`CreateFilter(pkg, filter)`, and an optional `Load()` that runs once.

### State across calls

Every entry point also runs in a **fresh** VM, so package-level variables
would normally reset. The runtime handles this for you: it instruments the
extension source so that every package-level variable is captured when an
entry point returns and restored before the next one runs.

So keep cross-call state in a plain package-level variable:

```go
var cachedNonce string

func nonce() (string, error) {
	if cachedNonce != "" {
		return cachedNonce, nil
	}
	// ... fetch it ...
	cachedNonce = fetched
	return cachedNonce, nil
}
```

There is **no** explicit cache API. (`sdk.SaveCache` / `sdk.GetCache` were
removed upstream — do not use them.)

Two limits worth knowing:

- a package-level variable initialised by a **function call** has no
  statically known type and is therefore *not* persisted — give it an
  explicit type (`var cachedNonce string`) or a literal initialiser;
- a **field** assignment chain on a package variable (`cfg.Nested.Flag =
  true`) silently no-ops in the Scriggo VM. Assign the whole value instead.

---

## Publishing

1. The file lives at `repo/js/<package>.js` or `repo/golang/<package>.go`.
2. `@package` in the header must match the file name.
3. `@apiVersion 2` is mandatory for JavaScript.
4. `index.json` and `README.md` regenerate automatically on push — the
   generator (`go run ./...`) fails the build if any extension breaks the
   rules above.

## Testing

`plug/` is a plug-and-play bench: drop one extension file in it and every
entry point is run twice — natively and through the Scriggo VM, exactly like
the app. See [plug/README.md](../plug/README.md).

```
cd plug && go test -v .
```
