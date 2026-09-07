// ==MiruExtension==
// @name         Rawkuma
// @version      v0.1.0
// @author       you
// @lang         ja
// @license      MIT
// @icon         https://rawkuma.net/wp-content/uploads/2025/09/Rawkuma-Logo.png
// @package      rawkuma
// @type         manga
// @webSite      https://rawkuma.net
// @apiVersion   2
// @nsfw         false
// ==/MiruExtension==

// Rawkuma — a Go (Scriggo V2) extension for the Japanese raw manga site
// rawkuma.net, a WordPress "Natsu" theme source (NatsuId multisrc port).
//
// Data flow, mirroring the Tachiyomi NatsuId source:
//
//   - Popular/Latest/Search all go through the theme's advanced_search AJAX
//     endpoint (multipart form + search nonce), whose HTML result cards are
//     resolved against the WordPress REST API (/wp-json/wp/v2/manga?slug[]=&_embed).
//   - Detail fetches the REST entry by slug (cover, terms, description) and
//     the chapter list from admin-ajax chapter_list (HTML).
//   - Watch/Mirror fetch the chapter page and extract the page images from
//     the data-image-data sections.
package plug

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
	"time"

	sdk "github.com/miru-project/miru-core/pkg/extension/golang/sdk"
)

const (
	rkBase = "https://rawkuma.net"
	rkUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)

// rkTLS makes every request go through the browser-impersonating client so
// the site's bot protection sees a Chrome TLS fingerprint, not fasthttp's.
func rkTLS() *sdk.TLSConfig {
	return &sdk.TLSConfig{Profile: "chrome_133", UserAgent: rkUA}
}

func rkHeaders() map[string]string {
	return map[string]string{
		"User-Agent":      rkUA,
		"Accept":          "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
		"Accept-Language": "ja,en;q=0.8",
	}
}

// rkGet performs a GET and returns the body, failing on transport and
// non-200 statuses.
func rkGet(url string) (string, error) {
	body, status, errStr := sdk.Fetch(url, "GET", rkHeaders(), "", rkTLS())
	if errStr != "" {
		return "", fmt.Errorf("GET %s: %s", url, errStr)
	}
	if status != 200 {
		return "", fmt.Errorf("GET %s: HTTP %d", url, status)
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// WordPress REST DTOs (NatsuId Dto.kt port)
// ---------------------------------------------------------------------------

type rkRendered struct {
	Rendered string `json:"rendered"`
}

type rkTerm struct {
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Taxonomy string `json:"taxonomy"`
}

type rkMedia struct {
	SourceURL string `json:"source_url"`
}

type rkEmbedded struct {
	FeaturedMedia []rkMedia  `json:"wp:featuredmedia"`
	Terms         [][]rkTerm `json:"wp:term"`
}

type rkManga struct {
	ID       int        `json:"id"`
	Slug     string     `json:"slug"`
	Title    rkRendered `json:"title"`
	Content  rkRendered `json:"content"`
	Embedded rkEmbedded `json:"_embedded"`
}

// rkTerms returns the names of the term group with the given taxonomy
// ("status", "genre", "series-author", "artist", "type").
func rkTerms(m rkManga, tax string) []string {
	for _, group := range m.Embedded.Terms {
		if len(group) > 0 && group[0].Taxonomy == tax {
			names := make([]string, 0, len(group))
			for _, t := range group {
				names = append(names, t.Name)
			}
			return names
		}
	}
	return nil
}

// rkCover returns the featured media URL, or "" when there is none.
func rkCover(m rkManga) string {
	if len(m.Embedded.FeaturedMedia) > 0 {
		return m.Embedded.FeaturedMedia[0].SourceURL
	}
	return ""
}

// rkIsNovel reports whether the entry is a novel. The site hosts novels in
// the same manga post type, but the reader must not show them — NatsuId
// filters them out with filterNot { it.isNovel }.
func rkIsNovel(m rkManga) bool {
	for _, t := range rkTerms(m, "type") {
		if t == "Novel" {
			return true
		}
	}
	return false
}

// rkText strips HTML tags from rendered WordPress content and unescapes
// entities, approximating Jsoup's wholeText().
func rkText(content string) string {
	plain := rkReTags.ReplaceAllString(content, " ")
	plain = html.UnescapeString(plain)
	return strings.TrimSpace(rkReSpaces.ReplaceAllString(plain, " "))
}

var (
	rkReTags   = regexp.MustCompile(`(?s)<[^>]*>`)
	rkReSpaces = regexp.MustCompile(`\s+`)
)

// ---------------------------------------------------------------------------
// Search nonce (NatsuId getNonce port)
// ---------------------------------------------------------------------------

var (
	rkReNonce    = regexp.MustCompile(`(?i)<input[^>]+name=['"]search_nonce['"][^>]*value=['"]([^'"]+)['"]`)
	rkReNonceRev = regexp.MustCompile(`(?i)<input[^>]+value=['"]([^'"]+)['"][^>]*name=['"]search_nonce['"]`)
)

// rkNonce returns the search nonce, cached host-side via SaveCache so it is
// fetched once per session (every VM call runs in a fresh VM).
func rkNonce(pkg string) (string, error) {
	if v, ok := sdk.GetCache(pkg, "nonce"); ok {
		if s, ok := v.(string); ok && s != "" {
			return s, nil
		}
	}
	body, err := rkGet(rkBase + "/wp-admin/admin-ajax.php?type=search_form&action=get_nonce")
	if err != nil {
		return "", err
	}
	m := rkReNonce.FindStringSubmatch(body)
	if m == nil {
		m = rkReNonceRev.FindStringSubmatch(body)
	}
	if m == nil {
		return "", fmt.Errorf("search nonce not found in response")
	}
	sdk.SaveCache(pkg, "nonce", m[1])
	return m[1], nil
}

// ---------------------------------------------------------------------------
// Advanced search (NatsuId getSearchMangaList + parseSearchManga port)
// ---------------------------------------------------------------------------

const rkBoundary = "miruRawkumaForm7MA4YWxkTrZu0gW"

var (
	rkReAnchor  = regexp.MustCompile(`(?is)<a[^>]+href="([^"]*/manga/[^"]*)"[^>]*>(.*?)</a>`)
	rkReSlug    = regexp.MustCompile(`/manga/([^/]+)/?`)
	rkReNextBtn = regexp.MustCompile(`(?is)<button[^>]*>.{0,400}?<svg`)
)

// rkJSON encodes a string list the way the site's search form expects
// (a JSON array body part, "[]" when empty).
func rkJSON(vals []string) string {
	if len(vals) == 0 {
		return "[]"
	}
	out, err := json.Marshal(vals)
	if err != nil {
		return "[]"
	}
	return string(out)
}

// rkSearch posts the advanced_search multipart form and parses the result
// cards into list items.
func rkSearch(pkg, kw string, page int, orderby, order string, types, statuses, genres []string) ([]sdk.ExtensionListItem, bool, error) {
	nonce, err := rkNonce(pkg)
	if err != nil {
		return nil, false, err
	}

	var b strings.Builder
	part := func(name, value string) {
		fmt.Fprintf(&b, "--%s\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n", rkBoundary, name, value)
	}
	part("nonce", nonce)
	part("inclusion", "OR")
	part("exclusion", "OR")
	part("page", strconv.Itoa(page))
	part("genre", rkJSON(genres))
	part("genre_exclude", "[]")
	part("author", "[]")
	part("artist", "[]")
	part("project", "0")
	part("type", rkJSON(types))
	part("status", rkJSON(statuses))
	part("order", order)
	part("orderby", orderby)
	part("query", strings.TrimSpace(kw))
	fmt.Fprintf(&b, "--%s--\r\n", rkBoundary)

	headers := rkHeaders()
	headers["Content-Type"] = "multipart/form-data; boundary=" + rkBoundary
	body, status, errStr := sdk.Fetch(
		rkBase+"/wp-admin/admin-ajax.php?action=advanced_search",
		"POST", headers, b.String(), rkTLS())
	if errStr != "" {
		return nil, false, fmt.Errorf("search: %s", errStr)
	}
	if status != 200 {
		return nil, false, fmt.Errorf("search: HTTP %d", status)
	}
	return rkParseSearch(body)
}

// rkParseSearch extracts /manga/ card links that contain an <img> child (the
// NatsuId selector div > a[href*=/manga/]:has(> img)), resolves them against
// the REST API in one batched request, and keeps the card order.
func rkParseSearch(body string) ([]sdk.ExtensionListItem, bool, error) {
	slugs := []string{}
	seen := map[string]bool{}
	for _, m := range rkReAnchor.FindAllStringSubmatch(body, -1) {
		href, inner := m[1], m[2]
		if !strings.Contains(inner, "<img") {
			continue
		}
		sm := rkReSlug.FindStringSubmatch(href)
		if sm == nil || seen[sm[1]] {
			continue
		}
		seen[sm[1]] = true
		slugs = append(slugs, sm[1])
	}
	if len(slugs) == 0 {
		return []sdk.ExtensionListItem{}, false, nil
	}

	mangas, err := rkMangasBySlugs(slugs)
	if err != nil {
		return nil, false, err
	}
	bySlug := map[string]rkManga{}
	for _, mg := range mangas {
		bySlug[mg.Slug] = mg
	}
	items := []sdk.ExtensionListItem{}
	for _, slug := range slugs {
		mg, ok := bySlug[slug]
		if !ok || rkIsNovel(mg) {
			continue
		}
		items = append(items, sdk.ExtensionListItem{
			Title: html.UnescapeString(mg.Title.Rendered),
			URL:   rkBase + "/manga/" + mg.Slug + "/",
			Cover: rkCover(mg),
			Image: rkCover(mg),
			Type:  "manga",
		})
	}
	return items, rkReNextBtn.MatchString(body), nil
}

// rkMangasBySlugs resolves slugs against the WordPress REST API with _embed,
// which bundles the featured image and term groups into each entry.
func rkMangasBySlugs(slugs []string) ([]rkManga, error) {
	q := rkBase + "/wp-json/wp/v2/manga?_embed&per_page=" + strconv.Itoa(len(slugs)+1)
	for _, s := range slugs {
		q += "&slug[]=" + s
	}
	body, err := rkGet(q)
	if err != nil {
		return nil, err
	}
	var mangas []rkManga
	if err := json.Unmarshal([]byte(body), &mangas); err != nil {
		return nil, fmt.Errorf("manga JSON: %v", err)
	}
	return mangas, nil
}

// ---------------------------------------------------------------------------
// Entry points: Latest + Search
// ---------------------------------------------------------------------------

// Latest returns the latest updates (NatsuId maps latest to orderby=updated).
func Latest(pkg string, page int) ([]sdk.ExtensionListItem, error) {
	items, _, err := rkSearch(pkg, "", page, "updated", "desc", nil, nil, nil)
	return items, err
}

// Search runs the advanced search with the UI's filter selections.
func Search(pkg, kw string, page int, filter sdk.Filter) ([]sdk.ExtensionListItem, error) {
	orderby := sdk.FirstSelection(filter, "sort")
	if orderby == "" {
		orderby = "popular"
	}
	order := sdk.FirstSelection(filter, "order")
	if order == "" {
		order = "desc"
	}
	items, _, err := rkSearch(pkg, kw, page, orderby, order,
		sdk.SelectionsOf(filter, "type"),
		sdk.SelectionsOf(filter, "status"),
		sdk.SelectionsOf(filter, "genre"))
	return items, err
}

// ---------------------------------------------------------------------------
// Detail + chapter list (NatsuId getMangaDetails + getChapterList port)
// ---------------------------------------------------------------------------

var (
	rkReChapter = regexp.MustCompile(`(?is)<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>`)
	rkReSpan    = regexp.MustCompile(`(?is)<span[^>]*>(.*?)</span>`)
)

// rkChapters scrapes the admin-ajax chapter_list HTML: each chapter is an
// anchor containing a <time> element, with its name in a <span>.
func rkChapters(mangaID int) ([]sdk.ExtensionEpisodeGroup, error) {
	// A random page number above 3 keeps hidden chapters visible, exactly as
	// the NatsuId source does (Random.nextInt(99, 9999)).
	page := time.Now().UnixNano()%9900 + 99
	u := fmt.Sprintf("%s/wp-admin/admin-ajax.php?manga_id=%d&page=%d&action=chapter_list", rkBase, mangaID, page)
	body, err := rkGet(u)
	if err != nil {
		return nil, err
	}
	groups := []sdk.ExtensionEpisodeGroup{}
	for _, m := range rkReChapter.FindAllStringSubmatch(body, -1) {
		href, inner := m[1], m[2]
		if !strings.Contains(inner, "<time") {
			continue
		}
		name := "Chapter"
		if sm := rkReSpan.FindStringSubmatch(inner); sm != nil {
			name = rkText(sm[1])
		}
		groups = append(groups, sdk.ExtensionEpisodeGroup{
			Title: html.UnescapeString(name),
			URLs:  []string{href},
		})
	}
	return groups, nil
}

// Detail resolves the manga page URL to its REST entry (cover, terms,
// description) and attaches the chapter list.
func Detail(pkg, url string) (*sdk.ExtensionDetail, error) {
	sm := rkReSlug.FindStringSubmatch(url)
	if sm == nil {
		return nil, fmt.Errorf("cannot extract manga slug from %s", url)
	}
	mangas, err := rkMangasBySlugs([]string{sm[1]})
	if err != nil {
		return nil, err
	}
	if len(mangas) == 0 {
		return nil, fmt.Errorf("manga %q not found", sm[1])
	}
	m := mangas[0]
	chapters, err := rkChapters(m.ID)
	if err != nil {
		return nil, err
	}
	desc := rkText(m.Content.Rendered)
	return &sdk.ExtensionDetail{
		Title:       html.UnescapeString(m.Title.Rendered),
		URL:         url,
		Cover:       rkCover(m),
		Image:       rkCover(m),
		Type:        "manga",
		Description: desc,
		Desc:        desc,
		Chapters:    chapters,
	}, nil
}

// ---------------------------------------------------------------------------
// Watch + Mirror (NatsuId getPageList port)
// ---------------------------------------------------------------------------

var (
	rkReSection = regexp.MustCompile(`(?is)<section[^>]*data-image-data[^>]*>(.*?)</section>`)
	rkReImg     = regexp.MustCompile(`(?is)<img[^>]+src=['"]([^'"]+)['"]`)
)

// rkPages extracts the page images from the chapter page's data-image-data
// sections (the NatsuId selector main .relative section > img).
func rkPages(body string) []string {
	urls := []string{}
	seen := map[string]bool{}
	for _, sec := range rkReSection.FindAllStringSubmatch(body, -1) {
		for _, im := range rkReImg.FindAllStringSubmatch(sec[1], -1) {
			if !seen[im[1]] {
				seen[im[1]] = true
				urls = append(urls, im[1])
			}
		}
	}
	return urls
}

// Watch lists the mirrors for the chapter page (the V2 flow: Watch presents
// the mirror list, the user picks one, Mirror resolves it into the final
// page images). Rawkuma serves every chapter from a single source, so the
// list carries one mirror pointing at the chapter page itself.
func Watch(pkg, url string) (*sdk.ExtensionWatch, error) {
	return &sdk.ExtensionWatch{
		Title: "Rawkuma",
		Type:  "manga",
		Groups: []sdk.ExtensionMirrorGroup{
			{
				Title: "Chapter",
				Mirrors: []sdk.ExtensionMirror{
					{Name: "Rawkuma", URL: url},
				},
			},
		},
	}, nil
}

// Mirror resolves the chosen mirror URL into the final page images. For
// manga the mirror URL is the chapter page, so this fetches it and extracts
// the page images from the data-image-data sections.
func Mirror(pkg, url string) (*sdk.ExtensionMangaWatchMirror, error) {
	body, err := rkGet(url)
	if err != nil {
		return nil, err
	}
	pages := rkPages(body)
	if len(pages) == 0 {
		return nil, fmt.Errorf("no page images found at %s", url)
	}
	return &sdk.ExtensionMangaWatchMirror{
		URLs:    pages,
		Headers: map[string]string{"Referer": rkBase + "/"},
	}, nil
}

// ---------------------------------------------------------------------------
// Filters (NatsuId getFilterList + fetchFilterData port)
// ---------------------------------------------------------------------------

// CreateFilter declares the search filters. Genre options are fetched live
// from the REST API like NatsuId's supportsFilterFetching; when the fetch
// fails the genre filter is simply omitted.
func CreateFilter(pkg string, filter sdk.Filter) map[string]sdk.FilterDefinition {
	filters := map[string]sdk.FilterDefinition{
		"sort": sdk.NewSelect("Sort", "popular").
			Option("popular", "Popular").
			Option("rating", "Rating").
			Option("updated", "Updated").
			Option("bookmarked", "Bookmarked").
			Option("title", "Title").
			Build(),
		"order": sdk.NewSelect("Order", "desc").
			Option("desc", "Descending").
			Option("asc", "Ascending").
			Build(),
		"type": sdk.NewMultiSelect("Type", 0, 3).
			Option("manga", "Manga").
			Option("manhwa", "Manhwa").
			Option("manhua", "Manhua").
			Build(),
		"status": sdk.NewMultiSelect("Status", 0, 5).
			Option("ongoing", "Ongoing").
			Option("completed", "Completed").
			Option("cancelled", "Cancelled").
			Option("on-hiatus", "On Hiatus").
			Option("unknown", "Unknown").
			Build(),
	}
	if genres := rkGenres(); len(genres) > 0 {
		b := sdk.NewMultiSelect("Genre", 0, int32(len(genres)))
		for _, g := range genres {
			b.Option(g.Slug, g.Name)
		}
		filters["genre"] = b.Build()
	}
	return filters
}

// rkGenres fetches the genre terms, ordered by usage count like the source.
func rkGenres() []rkTerm {
	body, err := rkGet(rkBase + "/wp-json/wp/v2/genre?per_page=100&page=1&orderby=count&order=desc")
	if err != nil {
		return nil
	}
	var terms []rkTerm
	if err := json.Unmarshal([]byte(body), &terms); err != nil {
		return nil
	}
	return terms
}

// ---------------------------------------------------------------------------
// Load hook — warm the search nonce once at startup.
// ---------------------------------------------------------------------------

func Load() {
	const pkg = "rawkuma"
	_, _ = rkNonce(pkg)
}
