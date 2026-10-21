// The Go extensions in this directory are SINGLE-FILE Scriggo programs, not
// a Go package.
//
// The miru-core Go runtime compiles each extension on its own: it reads one
// <pkg>.go file and hands it to Scriggo as a one-file program (see
// pkg/extension/golang/vm.go, Compile -> scriggo.Files{"main.go": ...}).
// Two extensions therefore cannot live in one Go package -- they all declare
// the same entry points (Latest, Search, Detail, Watch, Mirror,
// CreateFilter) and would redeclare each other.
//
// This go.mod makes the directory a separate module, which keeps the Go
// tool from trying to build these sources as a single package when the
// repository root is built or vetted. The files themselves are published
// verbatim: the app downloads <pkg>.go from this directory over HTTP and
// compiles it with Scriggo, so nothing here is ever linked into a binary.
//
// The development bench (plug/) is where a Go extension is actually compiled
// and run -- see plug/README.md.
module miru-repo/extensions/golang

go 1.27
