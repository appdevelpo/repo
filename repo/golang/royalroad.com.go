// ==MiruExtension==
// @name         RoyalRoad
// @version      v0.1.0
// @author       appdevelpo
// @lang         en
// @license      MIT
// @package      royalroad.com
// @type         fikushon
// @webSite      https://www.royalroad.com
// @icon         https://raw.githubusercontent.com/appdevelpo/repo/refs/heads/miru_alpha/icon/royalroad.com.ico
// @apiVersion   2
// @nsfw         false
// ==/MiruExtension==

// RoyalRoad — a Go (Scriggo V2) extension for royalroad.com, the web-fiction
// site. It is a port of the JavaScript RoyalRoad plugin, keeping the same
// three data flows and adding everything the Go entry points can express that
// the JS one could not.
//
// Data flow:
//
//   - Latest/Search both render the site's search pages (Latest uses the
//     dedicated /fictions/latest-updates listing). Every result card is a
//     .fiction-list-item block holding the title anchor and the cover <img>.
//   - Detail fetches the fiction page and reads the table of contents out of
//     the `window.chapters` JSON the page ships (falling back to the rendered
//     #chapters rows when that JSON is absent), then groups the chapters into
//     episode groups. When the fiction defines volumes (`window.volumes`,
//     exposed as data-volume-id on each row) the chapters are grouped per
//     volume, which is the Go equivalent of the JS plugin's volume view;
//     otherwise a single "Chapters" group is emitted.
//   - Watch lists the chapter as the one available mirror, and Mirror parses
//     the chapter page into plain-text lines: the .chapter-content paragraphs
//     plus the author's note, with the site's anti-scraping hidden element
//     removed (its class is a per-page random token declared in a <style>
//     block with `display: none`, exactly as the JS plugin detects it).
//
// Filters map onto RoyalRoad's real search form. The JS plugin exposes free
// text boxes (keyword / author) and an excludable checkbox group; the Go V2
// filter model only offers Select / MultiSelect / Range, so:
//
//   - the search box the app already provides is routed by the `searchField`
//     select (title / keyword = title or description / author), which covers
//     the JS plugin's text inputs;
//   - genres / tags / content warnings become three multi-selects (on the site
//     all three are plain `tags`) whose include-vs-exclude direction is chosen
//     by the `tagMode` select, which is what `tagsAdd` vs `tagsRemove` needs;
//   - pages and rating become range filters (rating is expressed in tenths
//     because range values are integers, 50 meaning 5.0).
package plug

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"

	sdk "github.com/miru-project/miru-core/pkg/extension/golang/sdk"
)

const (
	rrBase = "https://www.royalroad.com/"
	rrUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

// rrTLS routes every request through the browser-impersonating client so the
// site's bot protection sees a Chrome TLS fingerprint, not fasthttp's.
func rrTLS() *sdk.TLSConfig {
	return &sdk.TLSConfig{Profile: "chrome_133", UserAgent: rrUA}
}

func rrHeaders() map[string]string {
	return map[string]string{
		"User-Agent":      rrUA,
		"Accept":          "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.9",
	}
}

// rrGet performs a GET and returns the body, failing on transport errors and
// non-200 statuses.
func rrGet(url string) (string, error) {
	body, status, errStr := sdk.Fetch(url, "GET", rrHeaders(), "", rrTLS())
	if errStr != "" {
		return "", fmt.Errorf("GET %s: %s", url, errStr)
	}
	if status != 200 {
		return "", fmt.Errorf("GET %s: HTTP %d", url, status)
	}
	return body, nil
}

// rrAbs resolves a possibly-relative URL against the site root, the way the
// JS plugin's isUrlAbsolute helper does.

// ---------------------------------------------------------------------------
// HTML helpers
//
// The Go sandbox has no DOM library, so the page is walked with regexps and a
// small div-balancing scanner. Scriggo cannot compile method declarations on
// user-defined types, so every helper is a free function.
// ---------------------------------------------------------------------------

var (
	// RoyalRoad orders the two classes differently on its two result pages
	// ("fiction-list-item row" on latest-updates, "row fiction-list-item" on
	// search), so the marker must not assume a position.
	rrReItemStart = regexp.MustCompile(`<div class="[^"]*\bfiction-list-item\b[^"]*"`)
	rrReTitleLink = regexp.MustCompile(`(?s)<h2 class="fiction-title">.*?<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>`)
	rrReImgAlt    = regexp.MustCompile(`(?s)<img[^>]*alt="([^"]*)"`)
	rrReImgSrc    = regexp.MustCompile(`(?s)<img[^>]*src="([^"]+)"`)
	rrReH1        = regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`)
	rrReAuthor    = regexp.MustCompile(`(?s)<a[^>]*href="/profile/\d+"[^>]*>(.*?)</a>`)
	rrReStatus    = regexp.MustCompile(`(?is)<span class="label label-default label-sm[^"]*"[^>]*>\s*([A-Z]+)\s*</span>`)
	rrReTagAnchor = regexp.MustCompile(`(?s)<a[^>]*class="[^"]*fiction-tag[^"]*"[^>]*>(.*?)</a>`)
	rrReHidden    = regexp.MustCompile(`(?s)<style>\s*\.([A-Za-z0-9_-]+)\s*\{[^{}]*display:\s*none;`)
	rrReChapters  = regexp.MustCompile(`window\.chapters\s*=\s*`)
	rrReVolumes   = regexp.MustCompile(`window\.volumes\s*=\s*`)
	rrReRow       = regexp.MustCompile(`(?s)<tr[^>]*class="chapter-row"[^>]*>(.*?)</tr>`)
	rrReDataURL   = regexp.MustCompile(`data-url="([^"]+)"`)
	rrReRowAnchor = regexp.MustCompile(`(?s)<a[^>]*>(.*?)</a>`)

	rrReDiv   = regexp.MustCompile(`(?i)<(/?)div\b[^>]*>`)
	rrReBreak = regexp.MustCompile(`(?i)</p\s*>|<br\s*/?>|</div\s*>|</h[1-6]\s*>|<hr\s*/?>`)
	rrReTag   = regexp.MustCompile(`(?s)<[^>]*>`)
	rrReSpace = regexp.MustCompile(`[ \t]+`)
)

// rrStatuses are the words RoyalRoad prints in the status label; the first
// label-sm span on a page is the fiction type ("Original"), so the status is
// the label that matches this set.
var rrStatuses = []string{"ONGOING", "COMPLETED", "HIATUS", "DROPPED", "STUB"}

// rrDivInner returns the inner HTML of the element opened by marker, matching
// nested <div> tags so a `.chapter-content` block is captured whole instead of
// stopping at the first child. ok is false when the marker is absent.
func rrDivInner(s, marker string) (string, bool) {
	i := strings.Index(s, marker)
	if i < 0 {
		return "", false
	}
	rest := s[i+len(marker):]
	depth := 1
	for _, m := range rrReDiv.FindAllStringSubmatchIndex(rest, -1) {
		if rest[m[2]] == '/' {
			depth--
		} else {
			depth++
		}
		if depth == 0 {
			return rest[:m[0]], true
		}
	}
	return rest, true
}

// rrElemInner returns everything in s up to the close tag matching the
// already-consumed opening tag name, honouring same-name nesting.
func rrElemInner(s, name string) string {
	tags := regexp.MustCompile(`(?i)<(/?)` + regexp.QuoteMeta(name) + `\b[^>]*>`)
	depth := 1
	for _, m := range tags.FindAllStringSubmatchIndex(s, -1) {
		if s[m[2]] == '/' {
			depth--
		} else {
			depth++
		}
		if depth == 0 {
			return s[:m[0]]
		}
	}
	return ""
}

// rrDropHidden removes every element whose class attribute carries the given
// per-page hidden token. It is the equivalent of the JS plugin's InHidden
// parsing state: the site wraps an anti-scraping notice in
// `<span class="<random>">` and declares that class `display: none` in a
// <style> block, and the notice must never reach the reader.
func rrDropHidden(s, hidden string) string {
	if hidden == "" {
		return s
	}
	open := regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9]*)[^>]*class="[^"]*` + regexp.QuoteMeta(hidden) + `[^"]*"[^>]*>`)
	for {
		loc := open.FindStringSubmatchIndex(s)
		if loc == nil {
			return s
		}
		s = s[:loc[0]] + rrElemInner(s[loc[1]:], s[loc[2]:loc[3]])
	}
}

func rrAbs(u string) string {
	if u == "" {
		return ""
	}
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "//") {
		return u
	}
	return rrBase + strings.TrimPrefix(u, "/")
}

// rrJSONArray returns the JSON array literal that starts at or after index
// start, tracking bracket depth and string state so a `];` inside a chapter
// title cannot truncate the value (a plain non-greedy regexp would).
func rrJSONArray(s string, start int) string {
	depth := 0
	inStr, esc := false, false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// rrJSArray pulls the array assigned to a `window.<name> = [...]` script
// variable. An empty string means it was not present.
func rrJSArray(body string, re *regexp.Regexp) string {
	loc := re.FindStringIndex(body)
	if loc == nil {
		return ""
	}
	off := strings.Index(body[loc[1]:], "[")
	if off < 0 {
		return ""
	}
	return rrJSONArray(body, loc[1]+off)
}

// rrLines turns a block of reader HTML into trimmed plain-text lines: block
// boundaries become newlines, remaining tags are dropped, entities are
// decoded and runs of whitespace collapse.
func rrLines(inner string) []string {
	inner = rrReBreak.ReplaceAllString(inner, "\n")
	inner = rrReTag.ReplaceAllString(inner, "")
	lines := []string{}
	for _, ln := range strings.Split(html.UnescapeString(inner), "\n") {
		ln = strings.TrimSpace(rrReSpace.ReplaceAllString(ln, " "))
		if ln != "" {
			lines = append(lines, ln)
		}
	}
	return lines
}

// rrText flattens a block of HTML into a single whitespace-normalised string,
// decoding entities so a title like "Where &amp; When" reads correctly.
func rrText(inner string) string {
	plain := rrReTag.ReplaceAllString(inner, " ")
	return strings.TrimSpace(rrReSpace.ReplaceAllString(html.UnescapeString(plain), " "))
}

// rrStatus extracts the fiction status word, matching only the labels Royal
// Road actually uses for a status (the sibling label is the fiction type).
func rrStatus(body string) string {
	for _, m := range rrReStatus.FindAllStringSubmatch(body, -1) {
		for _, s := range rrStatuses {
			if m[1] == s {
				return s
			}
		}
	}
	return ""
}

// rrTags returns the fiction's genre/tag labels in document order.
func rrTags(body string) []string {
	out := []string{}
	for _, m := range rrReTagAnchor.FindAllStringSubmatch(body, -1) {
		if t := rrText(m[1]); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// List parsing (Latest / Search)
// ---------------------------------------------------------------------------

// rrParseList turns a RoyalRoad results page into list items. Each card is a
// .fiction-list-item block; consecutive blocks are located by index so no
// lookahead (unsupported by the sandbox's regexp engine) is needed.
func rrParseList(body string) []sdk.ExtensionListItem {
	items := []sdk.ExtensionListItem{}
	starts := rrReItemStart.FindAllStringIndex(body, -1)
	for i, loc := range starts {
		end := len(body)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		chunk := body[loc[0]:end]

		// The title anchor is authoritative; the cover <img alt> is the
		// fallback the JS plugin relies on.
		title, path := "", ""
		if m := rrReTitleLink.FindStringSubmatch(chunk); m != nil {
			path, title = m[1], rrText(m[2])
		} else if m := rrReImgAlt.FindStringSubmatch(chunk); m != nil {
			title = html.UnescapeString(m[1])
		}
		if title == "" || path == "" {
			continue
		}
		cover := ""
		if m := rrReImgSrc.FindStringSubmatch(chunk); m != nil {
			cover = rrAbs(html.UnescapeString(m[1]))
		}
		items = append(items, sdk.ExtensionListItem{
			Title: title,
			URL:   rrAbs(path),
			Cover: cover,
		})
	}
	return items
}

// ---------------------------------------------------------------------------
// Search query
// ---------------------------------------------------------------------------

// rrEscape percent-encodes a query value. Only the characters that actually
// occur in filter values and search terms are handled, which is all the
// sandbox's minimal net/url surface would be needed for.
func rrEscape(s string) string {
	r := strings.NewReplacer(
		"%", "%25", "&", "%26", "+", "%2B", " ", "%20",
		"#", "%23", "?", "%3F", "=", "%3D", "/", "%2F", "'", "%27",
	)
	return r.Replace(s)
}

// rrTenths renders a rating bound held as tenths (50 -> "5.0") for the site's
// decimal minRating / maxRating fields.
func rrTenths(s string) string {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return "0"
	}
	if n < 0 {
		n = 0
	}
	return strconv.FormatFloat(float64(n)/10, 'f', 1, 64)
}

// rrQuery assembles a /fictions/search query string from the UI selections.
// It reproduces the site's own search form field names (verified against the
// live form: keyword, author, tagsAdd, tagsRemove, minPages, maxPages,
// minRating, maxRating, status, orderBy, dir, type, title).
func rrQuery(kw string, page int, f sdk.Filter) string {
	q := []string{"page=" + strconv.Itoa(page)}

	// The app's search box is routed by `searchField`, which stands in for the
	// JS plugin's separate keyword / author / title text inputs.
	kw = strings.TrimSpace(kw)
	if kw != "" {
		switch sdk.FirstSelection(f, "searchField") {
		case "keyword":
			q = append(q, "keyword="+rrEscape(kw))
		case "author":
			q = append(q, "author="+rrEscape(kw))
		default:
			q = append(q, "title="+rrEscape(kw))
		}
	}

	// Genres, tags and content warnings are all plain `tags` on the site, so
	// the include/exclude direction chosen by `tagMode` decides whether the
	// selections become tagsAdd or tagsRemove.
	exclude := sdk.FirstSelection(f, "tagMode") == "exclude"
	for _, name := range []string{"genres", "tags", "contentWarnings"} {
		for _, v := range sdk.SelectionsOf(f, name) {
			if v == "" {
				continue
			}
			if exclude {
				q = append(q, "tagsRemove="+rrEscape(v))
			} else {
				q = append(q, "tagsAdd="+rrEscape(v))
			}
		}
	}

	// Numeric ranges arrive as the two stringified bounds the app sends for a
	// range filter.
	if b := sdk.SelectionsOf(f, "pages"); len(b) == 2 {
		q = append(q, "minPages="+rrEscape(b[0]), "maxPages="+rrEscape(b[1]))
	}
	if b := sdk.SelectionsOf(f, "rating"); len(b) == 2 {
		q = append(q, "minRating="+rrTenths(b[0]), "maxRating="+rrTenths(b[1]))
	}

	if v := sdk.FirstSelection(f, "status"); v != "" && v != "ALL" {
		q = append(q, "status="+rrEscape(v))
	}
	if v := sdk.FirstSelection(f, "type"); v != "" && v != "ALL" {
		q = append(q, "type="+rrEscape(v))
	}
	if v := sdk.FirstSelection(f, "orderBy"); v != "" {
		q = append(q, "orderBy="+rrEscape(v))
	}
	if v := sdk.FirstSelection(f, "dir"); v != "" {
		q = append(q, "dir="+rrEscape(v))
	}
	return strings.Join(q, "&")
}

// ---------------------------------------------------------------------------
// Detail + chapter list
// ---------------------------------------------------------------------------

// rrChapter and rrVolume are the entries of the `window.chapters` /
// `window.volumes` arrays the fiction page ships.
type rrChapter struct {
	ID       int    `json:"id"`
	VolumeID *int   `json:"volumeId"`
	Title    string `json:"title"`
	Date     string `json:"date"`
	Order    int    `json:"order"`
	URL      string `json:"url"`
}

type rrVolume struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Order int    `json:"order"`
}

// rrChaptersFromRows is the fallback for a page whose `window.chapters` JSON
// is missing: scrape the rendered #chapters table rows instead.
func rrChaptersFromRows(body string) []rrChapter {
	out := []rrChapter{}
	for _, row := range rrReRow.FindAllStringSubmatch(body, -1) {
		u := rrReDataURL.FindStringSubmatch(row[1])
		if u == nil {
			continue
		}
		name := ""
		if a := rrReRowAnchor.FindStringSubmatch(row[1]); a != nil {
			name = rrText(a[1])
		}
		if name == "" {
			name = "Chapter " + strconv.Itoa(len(out)+1)
		}
		out = append(out, rrChapter{Title: name, Order: len(out), URL: u[1]})
	}
	return out
}

// rrEpisodes turns the chapter list into episode groups. Without volumes that
// is a single "Chapters" group; with volumes each volume becomes its own
// group, the Go equivalent of the JS plugin's volume view.
func rrEpisodes(body string) []sdk.ExtensionEpisodeGroup {
	var chapters []rrChapter
	if raw := rrJSArray(body, rrReChapters); raw != "" {
		if err := json.Unmarshal([]byte(raw), &chapters); err != nil || len(chapters) == 0 {
			chapters = nil
		}
	}
	if chapters == nil {
		chapters = rrChaptersFromRows(body)
	}
	if len(chapters) == 0 {
		return []sdk.ExtensionEpisodeGroup{}
	}

	var volumes []rrVolume
	if raw := rrJSArray(body, rrReVolumes); raw != "" {
		_ = json.Unmarshal([]byte(raw), &volumes)
	}

	byVolume := map[int][]sdk.ExtensionEpisode{}
	plain := []sdk.ExtensionEpisode{}
	for _, c := range chapters {
		if c.URL == "" {
			continue
		}
		name := c.Title
		if name == "" {
			name = "Chapter " + strconv.Itoa(c.Order+1)
		}
		ep := sdk.ExtensionEpisode{Name: name, URL: rrAbs(c.URL)}
		if c.VolumeID != nil {
			byVolume[*c.VolumeID] = append(byVolume[*c.VolumeID], ep)
		} else {
			plain = append(plain, ep)
		}
	}

	groups := []sdk.ExtensionEpisodeGroup{}
	if len(plain) > 0 {
		groups = append(groups, sdk.ExtensionEpisodeGroup{Title: "Chapters", Episodes: plain})
	}
	for _, v := range volumes {
		eps := byVolume[v.ID]
		if len(eps) == 0 {
			continue
		}
		title := v.Title
		if title == "" {
			title = "Volume " + strconv.Itoa(v.Order+1)
		}
		groups = append(groups, sdk.ExtensionEpisodeGroup{Title: title, Episodes: eps})
	}
	// A fiction that references volume ids the page did not declare still gets
	// its chapters, appended as one ungrouped set.
	if len(groups) == 0 {
		rest := []sdk.ExtensionEpisode{}
		for _, eps := range byVolume {
			rest = append(rest, eps...)
		}
		if len(rest) > 0 {
			groups = append(groups, sdk.ExtensionEpisodeGroup{Title: "Chapters", Episodes: rest})
		}
	}
	return groups
}

// ---------------------------------------------------------------------------
// Entry points: Latest + Search
// ---------------------------------------------------------------------------

// Latest returns the most recently updated fictions.
func Latest(pkg string, page int) ([]sdk.ExtensionListItem, error) {
	body, err := rrGet(rrBase + "fictions/latest-updates?page=" + strconv.Itoa(page))
	if err != nil {
		return nil, err
	}
	return rrParseList(body), nil
}

// Search runs RoyalRoad's search form with the UI's filter selections.
func Search(pkg, kw string, page int, filter sdk.Filter) ([]sdk.ExtensionListItem, error) {
	body, err := rrGet(rrBase + "fictions/search?" + rrQuery(kw, page, filter))
	if err != nil {
		return nil, err
	}
	return rrParseList(body), nil
}

// ---------------------------------------------------------------------------
// Entry point: Detail
// ---------------------------------------------------------------------------

// Detail resolves a fiction page into its metadata and chapter list. RoyalRoad
// has no dedicated field for the author, the status or the genre labels, so
// they are folded into the description header the way the JS plugin exposes
// them as separate SourceNovel properties.
func Detail(pkg, url string) (*sdk.ExtensionDetail, error) {
	body, err := rrGet(rrAbs(url))
	if err != nil {
		return nil, err
	}

	title := ""
	if m := rrReH1.FindStringSubmatch(body); m != nil {
		title = rrText(m[1])
	}
	cover := ""
	if inner, ok := rrDivInner(body, `<div class="cover-art-container">`); ok {
		if m := rrReImgSrc.FindStringSubmatch(inner); m != nil {
			cover = rrAbs(html.UnescapeString(m[1]))
		}
	}
	author := ""
	if m := rrReAuthor.FindStringSubmatch(body); m != nil {
		author = rrText(m[1])
	}

	// The synopsis lives in .description > .hidden-content (the collapsed
	// body the "show more" checkbox reveals).
	summary := ""
	if inner, ok := rrDivInner(body, `<div class="hidden-content">`); ok {
		summary = strings.Join(rrLines(inner), "\n\n")
	}

	meta := []string{}
	if author != "" {
		meta = append(meta, "Author: "+author)
	}
	if s := rrStatus(body); s != "" {
		meta = append(meta, "Status: "+s)
	}
	if tags := rrTags(body); len(tags) > 0 {
		meta = append(meta, "Genres: "+strings.Join(tags, ", "))
	}
	desc := summary
	if len(meta) > 0 {
		desc = strings.Join(meta, "\n") + "\n\n" + summary
	}

	return &sdk.ExtensionDetail{
		Title:       title,
		URL:         rrAbs(url),
		Cover:       cover,
		Type:        "fikushon",
		Description: desc,
		Desc:        desc,
		Chapters:    rrEpisodes(body),
	}, nil
}

// ---------------------------------------------------------------------------
// Entry points: Watch + Mirror
// ---------------------------------------------------------------------------

// Watch lists the mirrors for a chapter. RoyalRoad serves every chapter from
// its own reader, so the list carries the single mirror the reader page is
// served from.
func Watch(pkg, url string) (*sdk.ExtensionWatch, error) {
	return &sdk.ExtensionWatch{
		Title: "RoyalRoad",
		Type:  "fikushon",
		Groups: []sdk.ExtensionMirrorGroup{
			{
				Title: "Chapter",
				Mirrors: []sdk.ExtensionMirror{
					{Name: "RoyalRoad", URL: rrAbs(url)},
				},
			},
		},
	}, nil
}

// rrNoteHeader introduces the author's note inside the chapter text; the JS
// plugin separates its three blocks with an <hr class="notes-separator">.
const rrNoteHeader = "——— Author's note ———"

// rrChapterText parses a chapter page into reader lines. The author's note is a
// sibling portlet, so its position in the document decides whether it is
// prepended or appended to the chapter body.
func rrChapterText(body string) (string, []string) {
	hidden := ""
	if m := rrReHidden.FindStringSubmatch(body); m != nil {
		hidden = m[1]
	}

	content, _ := rrDivInner(body, `<div class="chapter-inner chapter-content">`)
	// The anti-scraping notice lives inside the chapter body; drop it before
	// the text is flattened.
	chapter := rrLines(rrDropHidden(content, hidden))

	noteHTML, hasNote := rrDivInner(body, `<div class="portlet-body author-note">`)
	note := rrLines(rrDropHidden(noteHTML, hidden))

	title := ""
	if m := rrReH1.FindStringSubmatch(body); m != nil {
		title = rrText(m[1])
	}

	lines := []string{}
	if hasNote && len(note) > 0 &&
		strings.Index(body, `portlet-body author-note`) < strings.Index(body, "chapter-inner chapter-content") {
		lines = append(lines, rrNoteHeader)
		lines = append(lines, note...)
	}
	lines = append(lines, chapter...)
	if hasNote && len(note) > 0 &&
		strings.Index(body, `portlet-body author-note`) > strings.Index(body, "chapter-inner chapter-content") {
		lines = append(lines, rrNoteHeader)
		lines = append(lines, note...)
	}
	return title, lines
}

// Mirror resolves the chapter into the reader's text: the chapter's own
// paragraphs plus its author's note, with the site's hidden anti-scraping
// element removed.
func Mirror(pkg, url string) (*sdk.ExtensionFikushonWatchMirror, error) {
	body, err := rrGet(rrAbs(url))
	if err != nil {
		return nil, err
	}
	title, lines := rrChapterText(body)
	if len(lines) == 0 {
		return nil, fmt.Errorf("no chapter content found at %s", url)
	}
	return &sdk.ExtensionFikushonWatchMirror{
		Content: lines,
		Title:   title,
	}, nil
}

// ---------------------------------------------------------------------------
// Entry point: CreateFilter
// ---------------------------------------------------------------------------

// rrGenres, rrTagsList and rrWarnings are RoyalRoad's own filter values, read
// off the live search form (its Genres buttons, its tagsAdd <select> and its
// Content Warnings buttons) so the extension offers exactly what the site
// accepts.
var rrGenres = [][2]string{
	{"action", "Action"}, {"adventure", "Adventure"}, {"comedy", "Comedy"},
	{"contemporary", "Contemporary"}, {"drama", "Drama"}, {"fantasy", "Fantasy"},
	{"historical", "Historical"}, {"horror", "Horror"}, {"mystery", "Mystery"},
	{"psychological", "Psychological"}, {"romance_main", "Romance"},
	{"satire", "Satire"}, {"sci_fi", "Sci-fi"}, {"one_shot", "Short Story"},
	{"thriller", "Thriller"}, {"tragedy", "Tragedy"},
}

var rrWarnings = [][2]string{
	{"ai_assisted", "AI-Assisted Content"}, {"ai_generated", "AI-Generated Content"},
	{"graphic_violence", "Graphic Violence"}, {"profanity", "Profanity"},
	{"sensitive", "Sensitive Content"}, {"sexuality", "Sexual Content"},
}

var rrTagsList = [][2]string{
	{"anti-hero_lead", "Anti-Hero Lead"}, {"antivillain_lead", "Anti-Villain Lead"},
	{"apocalypse", "Apocalypse"}, {"artificial_intelligence", "Artificial Intelligence"},
	{"attractive_lead", "Attractive Lead"}, {"chivalry", "Chivalry"},
	{"competing_love", "Competing Love Interest"}, {"cozy", "Cozy"},
	{"crafting", "Crafting"}, {"cultivation", "Cultivation"}, {"cyberpunk", "Cyberpunk"},
	{"deck_building", "Deck Building"}, {"dungeon_core", "Dungeon Core"},
	{"dungeon_crawler", "Dungeon Crawler"}, {"dystopia", "Dystopia"},
	{"female_lead", "Female Lead"}, {"first_contact", "First Contact"},
	{"gamelit", "GameLit"}, {"gender_bender", "Gender Bender"},
	{"genetically_engineered", "Genetically Engineered"}, {"grimdark", "Grimdark"},
	{"hard_sci-fi", "Hard Sci-fi"}, {"high_fantasy", "High Fantasy"},
	{"kingdom_building", "Kingdom Building"}, {"lesbian_romance", "Lesbian Romance"},
	{"litrpg", "LitRPG"}, {"local_protagonist", "Local Protagonist"},
	{"low_fantasy", "Low Fantasy"}, {"magic", "Magic"}, {"magical_girl", "Magical Girl"},
	{"magitech", "Magitech"}, {"gay_romance", "Male Gay Romance"},
	{"male_lead", "Male Lead"}, {"martial_arts", "Martial Arts"}, {"mecha", "Mecha"},
	{"modern_knowledge", "Modern Knowledge"}, {"monster_evolution", "Monster Evolution"},
	{"multiple_lead", "Multiple Lead Characters"}, {"harem", "Multiple Lovers"},
	{"mythos", "Mythos"}, {"non-human_lead", "Non-Human Lead"},
	{"nonhumanoid_lead", "Non-Humanoid Lead"}, {"otome", "Otome"},
	{"summoned_hero", "Portal Fantasy / Isekai"}, {"post_apocalyptic", "Post Apocalyptic"},
	{"progression", "Progression"}, {"reader_interactive", "Reader Interactive"},
	{"reincarnation", "Reincarnation"}, {"romance", "Romance Subplot"},
	{"ruling_class", "Ruling Class"}, {"school_life", "School Life"},
	{"secret_identity", "Secret Identity"}, {"slice_of_life", "Slice of Life"},
	{"soft_sci-fi", "Soft Sci-fi"}, {"space_opera", "Space Opera"}, {"sports", "Sports"},
	{"steampunk", "Steampunk"}, {"strategy", "Strategy"}, {"strong_lead", "Strong Lead"},
	{"super_heroes", "Super Heroes"}, {"supernatural", "Supernatural"},
	{"survival", "Survival"}, {"system_invasion", "System Invasion"},
	{"technologically_engineered", "Technologically Engineered"}, {"loop", "Time Loop"},
	{"time_travel", "Time Travel"}, {"tower", "Tower"},
	{"urban_fantasy", "Urban Fantasy"}, {"villainous_lead", "Villainous Lead"},
	{"virtual_reality", "Virtual Reality"}, {"war_and_military", "War and Military"},
	{"wuxia", "Wuxia"},
}

// CreateFilter declares RoyalRoad's search filters. See the package comment for
// how the JS plugin's text inputs and excludable checkbox group are mapped onto
// the Select / MultiSelect / Range kinds the Go V2 filter model offers.
func CreateFilter(pkg string, filter sdk.Filter) map[string]sdk.FilterDefinition {
	multi := func(title string, opts [][2]string) sdk.FilterDefinition {
		b := sdk.NewMultiSelect(title, 0, int32(len(opts)))
		for _, o := range opts {
			b.Option(o[0], o[1])
		}
		return b.Build()
	}
	return map[string]sdk.FilterDefinition{
		// Routes the app's search box, standing in for the JS plugin's
		// keyword / author / title text inputs.
		"searchField": sdk.NewSelect("Search in", "title").
			Option("title", "Title").
			Option("keyword", "Title or description").
			Option("author", "Author").
			Build(),
		// Chooses whether the tag selections below are included or excluded,
		// i.e. tagsAdd vs tagsRemove.
		"tagMode": sdk.NewSelect("Tag mode", "include").
			Option("include", "Include matching").
			Option("exclude", "Exclude matching").
			Build(),
		"genres":          multi("Genres", rrGenres),
		"tags":            multi("Tags", rrTagsList),
		"contentWarnings": multi("Content warnings", rrWarnings),
		"status": sdk.NewSelect("Status", "ALL").
			Option("ALL", "All").
			Option("COMPLETED", "Completed").
			Option("DROPPED", "Dropped").
			Option("ONGOING", "Ongoing").
			Option("HIATUS", "Hiatus").
			Option("STUB", "Stub").
			Build(),
		"orderBy": sdk.NewSelect("Order by", "relevance").
			Option("relevance", "Relevance").
			Option("popularity", "Popularity").
			Option("rating", "Average rating").
			Option("last_update", "Last update").
			Option("release_date", "Release date").
			Option("followers", "Followers").
			Option("length", "Number of pages").
			Option("views", "Views").
			Option("title", "Title").
			Option("author", "Author").
			Build(),
		"dir": sdk.NewSelect("Direction", "desc").
			Option("asc", "Ascending").
			Option("desc", "Descending").
			Build(),
		"type": sdk.NewSelect("Type", "ALL").
			Option("ALL", "All").
			Option("fanfiction", "Fan fiction").
			Option("original", "Original").
			Build(),
		// Rating is expressed in tenths because range bounds are integers:
		// 50 means a 5.0 rating.
		"pages":  sdk.NewRange("Pages", 0, 20000, 0, 20000).Build(),
		"rating": sdk.NewRange("Rating (tenths, 50 = 5.0)", 0, 50, 0, 50).Build(),
	}
}
