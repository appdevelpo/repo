# Plug — extension test folder

Drop your extension here, run tests, see JSON. Native (direct Go call) and
VM (Scriggo, exactly like the app) on every entry point.

## How to use

1. Delete `example.go` (the placeholder).
2. Add your extension as `<pkg>.go` — where `<pkg>` is the `@package` value
   in its `==MiruExtension==` header. The file must declare `package plug`:

   ```go
   // ==MiruExtension==
   // @package      mysite
   // ...
   // ==/MiruExtension==

   package plug
   ```

3. Run the tests:
   - **VS Code:** F5 → "plug: run tests" (or "plug: run one stage" to pick
     Latest / Search / Detail / Watch / Mirror / CreateFilter from a list)
   - **Terminal:** `go test ./plug/ -v`
4. Every test logs its result as indented JSON, labeled `native` or `vm`.

## Rules

- Exactly **one** plug file at a time (plus `plug_test.go`).
- The package header value must match the file name: `@package mysite` →
  `mysite.go`. The Scriggo host resolves extensions as `<pkg>.go`, and the
  harness enforces this with a clear error if they differ.
- Your plug file is gitignored — it never gets committed.
- With **no** plug in the folder, `go test ./plug/` fails to compile with
  `undefined: Latest` — that is the cue to add your extension (native tests
  call its functions directly, so Go needs the file at compile time).

## What gets tested

| Stage        | Native | VM |
|--------------|--------|----|
| Latest       | ✅     | ✅ |
| Search       | ✅     | ✅ |
| Search+filter| ✅     | ✅ |
| Detail       | ✅     | ✅ |
| Watch        | ✅     | ✅ |
| Mirror       | ✅     | ✅ |
| CreateFilter | ✅     | ✅ |

Native = direct Go call. VM = Scriggo, exactly like the miru-core host.
Running both catches Scriggo-specific issues (code that works natively but
fails in the VM) before you publish.
