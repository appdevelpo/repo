// The plug-and-play test harness for Go extensions.
//
// Drop exactly ONE extension file into this folder — declared as
// `package plug`, with @package matching its file name — then run:
//
//	go test ./plug/ -v
//
// or press F5 in VS Code ("plug: run tests"). The harness discovers the
// plug, reads its @package from the ==MiruExtension== header, and runs
// every entry point twice: natively (direct Go call) and through the
// Scriggo VM (exactly like the miru-core host does).
package plug

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/miru-project/miru-core/pkg/extension"
	golang "github.com/miru-project/miru-core/pkg/extension/golang"
	sdk "github.com/miru-project/miru-core/pkg/extension/golang/sdk"
	"github.com/miru-project/miru-core/pkg/network"
	"github.com/miru-project/miru-core/proto/generate/proto"
)

// TestMain plays the host's startup role: the miru-core app calls
// network.Init() in its main to create the persistent cookie jar and start
// the DNS resolver. Without it, any extension sdk.Fetch call (native or VM)
// panics on a nil cookie jar.
func TestMain(m *testing.M) {
	network.Init()
	os.Exit(m.Run())
}

// probeDetailURL derives a real detail URL from the plug's own Latest result,
// so Detail tests exercise real content URLs regardless of which plug is in
// the folder (the old constant example.com URL only worked for the example).
func probeDetailURL(t *testing.T, p string) string {
	t.Helper()
	items, err := Latest(p, 1)
	if err != nil {
		t.Fatalf("probe Latest for detail URL: %v", err)
	}
	if len(items) == 0 {
		t.Skip("probe Latest returned no results — cannot derive a detail URL")
	}
	return items[0].URL
}

// probeChapterURL derives a real chapter URL from the plug's own Detail. It
// walks the first few Latest results until one has chapters (a list can
// contain entries without readable chapters, e.g. novels).
func probeChapterURL(t *testing.T, p string) string {
	t.Helper()
	items, err := Latest(p, 1)
	if err != nil {
		t.Fatalf("probe Latest for chapter URL: %v", err)
	}
	n := len(items)
	if n > 3 {
		n = 3
	}
	for i := 0; i < n; i++ {
		d, err := Detail(p, items[i].URL)
		if err != nil || d == nil {
			continue
		}
		if len(d.Chapters) > 0 && len(d.Chapters[0].URLs) > 0 {
			return d.Chapters[0].URLs[0]
		}
	}
	t.Skip("probe could not find a latest item with chapters in the first 3 results")
	return ""
}

// findPlug scans this directory for the extension plug: a non-test .go file
// carrying a ==MiruExtension== header. It returns the plug's @package value
// after verifying the file name matches — the Scriggo host resolves the
// extension as <pkg>.go, so a mismatch would silently miss the file.
func findPlug(t *testing.T) (dir, pkg string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir = filepath.Dir(file)

	var pkgs []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read plug dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !strings.Contains(string(b), "==MiruExtension==") {
			continue
		}
		meta, err := extension.ParseExtensionMetadata(string(b), name)
		if err != nil {
			t.Fatalf("%s: bad extension metadata: %v", name, err)
		}
		if meta.Pkg == "" {
			t.Fatalf("%s: missing @package in the ==MiruExtension== header", name)
		}
		if meta.Pkg+".go" != name {
			t.Fatalf("%s: @package %q must match the file name — rename it to %s.go",
				name, meta.Pkg, meta.Pkg)
		}
		pkgs = append(pkgs, meta.Pkg)
	}

	switch len(pkgs) {
	case 0:
		t.Skipf("no extension plug found in %s — add yours (<pkg>.go, package plug, "+
			"with a ==MiruExtension== header) and re-run", dir)
	case 1:
		return dir, pkgs[0]
	default:
		t.Fatalf("multiple extension plugs found %v — keep only ONE at a time", pkgs)
	}
	return "", ""
}

// setupVM points the golang endpoint at this directory so the Scriggo VM
// compiles the plug from here, exactly like the host does.
func setupVM(t *testing.T) (pkg string) {
	t.Helper()
	dir, pkg := findPlug(t)
	golang.ExtensionDir = dir
	return pkg
}

// printStage marshals an entry-point result to indented JSON and logs it.
func printStage(t *testing.T, name string, v any, err error) {
	t.Helper()
	if err != nil {
		t.Logf("[%s] error: %v", name, err)
		return
	}
	b, mErr := json.MarshalIndent(v, "", "  ")
	if mErr != nil {
		t.Logf("[%s] <marshal error: %v>", name, mErr)
		return
	}
	t.Logf("[%s]\n%s", name, string(b))
}

// nativeFilter builds the strongly-typed sdk.Filter the native entry points
// take — the counterpart of what the runtime decodes for the VM.
func nativeFilter(entries map[string][]string) sdk.Filter {
	if len(entries) == 0 {
		return sdk.Filter{}
	}
	sel := make(map[string]sdk.FilterSelection, len(entries))
	for name, vals := range entries {
		sel[name] = sdk.FilterSelection{Values: vals}
	}
	return sdk.Filter{Selections: sel}
}

// vmFilter builds the proto.FilterSelection the golang endpoint passes into
// the VM — the VM-mode counterpart of nativeFilter.
func vmFilter(entries map[string][]string) *proto.FilterSelection {
	if len(entries) == 0 {
		return nil
	}
	sel := make(map[string]*proto.FilterSelectionValue, len(entries))
	for name, vals := range entries {
		sel[name] = &proto.FilterSelectionValue{Values: vals}
	}
	return &proto.FilterSelection{Selections: sel}
}

// ---------------------------------------------------------------------------
// Latest
// ---------------------------------------------------------------------------

func TestLatest_Native(t *testing.T) {
	_, p := findPlug(t)
	t.Log("=== Latest: native ===")
	res, err := Latest(p, 1)
	printStage(t, "Latest/native", res, err)
	if err != nil {
		t.Fatalf("Latest native: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("Latest native: expected at least one result")
	}
}

func TestLatest_VM(t *testing.T) {
	p := setupVM(t)
	t.Log("=== Latest: Scriggo VM ===")
	res, err := golang.Latest(p, 1)
	printStage(t, "Latest/vm", res, err)
	if err != nil {
		t.Fatalf("Latest VM: %v", err)
	}
	if len(res) == 0 {
		t.Fatal("Latest VM: expected at least one result")
	}
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

func TestSearch_Native(t *testing.T) {
	_, p := findPlug(t)
	t.Log("=== Search: native (no filter) ===")
	res, err := Search(p, "test", 1, nativeFilter(nil))
	printStage(t, "Search/native", res, err)
	if err != nil {
		t.Fatalf("Search native: %v", err)
	}
	if len(res) == 0 {
		t.Skipf("search %q returned no results on this source — try a keyword the site knows", "test")
	}
}

func TestSearch_VM(t *testing.T) {
	p := setupVM(t)
	t.Log("=== Search: Scriggo VM (no filter) ===")
	res, err := golang.Search(p, 1, "test", nil)
	printStage(t, "Search/vm", res, err)
	if err != nil {
		t.Fatalf("Search VM: %v", err)
	}
	if len(res) == 0 {
		t.Skipf("search %q returned no results on this source — try a keyword the site knows", "test")
	}
}

func TestSearch_Filter_Native(t *testing.T) {
	_, p := findPlug(t)
	t.Log("=== Search: native (filter: type=manga) ===")
	res, err := Search(p, "test", 1, nativeFilter(map[string][]string{"type": {"manga"}}))
	printStage(t, "Search(type=manga)/native", res, err)
	if err != nil {
		t.Fatalf("Search with filter native: %v", err)
	}
	if len(res) == 0 {
		t.Skip("search with filter returned no results on this source")
	}
}

func TestSearch_Filter_VM(t *testing.T) {
	p := setupVM(t)
	t.Log("=== Search: Scriggo VM (filter: type=manga) ===")
	res, err := golang.Search(p, 1, "test", vmFilter(map[string][]string{"type": {"manga"}}))
	printStage(t, "Search(type=manga)/vm", res, err)
	if err != nil {
		t.Fatalf("Search with filter VM: %v", err)
	}
	if len(res) == 0 {
		t.Skip("search with filter returned no results on this source")
	}
}

// ---------------------------------------------------------------------------
// Detail
// ---------------------------------------------------------------------------

func TestDetail_Native(t *testing.T) {
	_, p := findPlug(t)
	t.Log("=== Detail: native ===")
	res, err := Detail(p, probeDetailURL(t, p))
	printStage(t, "Detail/native", res, err)
	if err != nil {
		t.Fatalf("Detail native: %v", err)
	}
	if res == nil {
		t.Fatal("Detail native: expected non-nil result")
	}
}

func TestDetail_VM(t *testing.T) {
	p := setupVM(t)
	t.Log("=== Detail: Scriggo VM ===")
	res, err := golang.Detail(p, probeDetailURL(t, p))
	printStage(t, "Detail/vm", res, err)
	if err != nil {
		t.Fatalf("Detail VM: %v", err)
	}
	if res == nil {
		t.Fatal("Detail VM: expected non-nil result")
	}
}

// ---------------------------------------------------------------------------
// Watch
// ---------------------------------------------------------------------------

func TestWatch_Native(t *testing.T) {
	_, p := findPlug(t)
	t.Log("=== Watch: native ===")
	res, err := Watch(p, probeChapterURL(t, p))
	printStage(t, "Watch/native", res, err)
	if err != nil {
		t.Fatalf("Watch native: %v", err)
	}
	if res == nil {
		t.Fatal("Watch native: expected non-nil result")
	}
}

func TestWatch_VM(t *testing.T) {
	p := setupVM(t)
	t.Log("=== Watch: Scriggo VM ===")
	res, _, err := golang.Watch(p, probeChapterURL(t, p))
	printStage(t, "Watch/vm", res, err)
	if err != nil {
		t.Fatalf("Watch VM: %v", err)
	}
	if res == nil {
		t.Fatal("Watch VM: expected non-nil result")
	}
}

// ---------------------------------------------------------------------------
// Mirror
// ---------------------------------------------------------------------------

func TestMirror_Native(t *testing.T) {
	_, p := findPlug(t)
	t.Log("=== Mirror: native ===")
	res, err := Mirror(p, probeChapterURL(t, p))
	printStage(t, "Mirror/native", res, err)
	if err != nil {
		t.Fatalf("Mirror native: %v", err)
	}
	if res == nil {
		t.Fatal("Mirror native: expected non-nil result")
	}
}

func TestMirror_VM(t *testing.T) {
	p := setupVM(t)
	t.Log("=== Mirror: Scriggo VM ===")
	res, err := golang.Mirror(p, probeChapterURL(t, p))
	printStage(t, "Mirror/vm", res, err)
	if err != nil {
		t.Fatalf("Mirror VM: %v", err)
	}
	if res == nil {
		t.Fatal("Mirror VM: expected non-nil result")
	}
}

// ---------------------------------------------------------------------------
// CreateFilter
// ---------------------------------------------------------------------------

func TestCreateFilter_Native(t *testing.T) {
	_, p := findPlug(t)
	t.Log("=== CreateFilter: native ===")
	filters := CreateFilter(p, nativeFilter(nil))
	printStage(t, "CreateFilter/native", filters, nil)
	if len(filters) == 0 {
		t.Fatal("CreateFilter native: expected at least one filter")
	}
}

func TestCreateFilter_Selection_Native(t *testing.T) {
	_, p := findPlug(t)
	t.Log("=== CreateFilter: native (with selection) ===")
	filters := CreateFilter(p, nativeFilter(map[string][]string{"type": {"manga"}}))
	printStage(t, "CreateFilter(selection)/native", filters, nil)
	if len(filters) == 0 {
		t.Fatal("CreateFilter with selection native: expected at least one filter")
	}
}

func TestCreateFilter_VM(t *testing.T) {
	p := setupVM(t)
	t.Log("=== CreateFilter: Scriggo VM ===")
	filters, err := golang.CreateFilter(p, nil)
	printStage(t, "CreateFilter/vm", filters, err)
	if err != nil {
		t.Fatalf("CreateFilter VM: %v", err)
	}
	if len(filters) == 0 {
		t.Fatal("CreateFilter VM: expected at least one filter")
	}
}
