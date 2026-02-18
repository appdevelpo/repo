# Icon Downloader Script

A Go utility that processes Miru extension files to automatically download icons from `@icon` URLs and update the extension metadata with GitHub raw content URLs.

## Features

- Iterates through all extension files in the `repo/` directory
- Extracts the `@icon` URL from extension metadata
- Downloads icons to `icon/${package}.{extension}` 
- Updates the `@icon` property with GitHub raw content URLs
- Handles errors gracefully with detailed logging
- Preserves original file extensions (png, jpg, ico, webp, etc.)
- Skips extensions that don't have icons

## Usage

```bash
cd /path/to/repo
./cmd/download-icons/download-icons
```

### Building from Source

```bash
cd /path/to/repo
go build -o ./cmd/download-icons/download-icons ./cmd/download-icons
```

## How It Works

1. **Icon Directory**: Creates `icon/` directory at project root if it doesn't exist
2. **Metadata Extraction**: Parses each `.js` extension file for `@package` and `@icon` properties
3. **Download**: Downloads the icon file from the URL specified in `@icon`
4. **File Storage**: Saves as `icon/${pkg}.{ext}` (e.g., `icon/gogo.anime.png`)
5. **Update**: Replaces the `@icon` URL with:
   ```
   https://raw.githubusercontent.com/appdevelpo/repo/refs/heads/miru_alpha/icon/${pkg}.{ext}
   ```
6. **Error Handling**: Logs failures and continues processing remaining files

## Output

The script provides a summary with statistics:
- **Successful**: Number of icons successfully downloaded and updated
- **Skipped**: Number of files without icons (no `@icon` property)
- **Errors**: Number of download/update failures (network errors, missing files, etc.)
- **Total**: Total files processed

Example output:
```
Starting icon download and update process...
Total files to process: 167

✓ SUCCESS 345movie.net.js (345movie.net): Downloaded and updated icon
✓ SUCCESS 360zy.com.js (360zy.com): Downloaded and updated icon
⊘ SKIP example.js (example): No @icon found
✗ ERROR broken.js (broken): Failed to download icon: HTTP 404

=== Summary ===
Successful: 84
Skipped: 5
Errors: 78
Total: 167
```

## Directory Structure

```
repo/
├── cmd/
│   └── download-icons/
│       ├── main.go           # Source code
│       └── download-icons    # Compiled executable
├── repo/
│   ├── *.js                  # Extension files
│   └── ... (167 extension files)
└── icon/                     # Generated icon directory
    ├── 345movie.net.ico
    ├── 360zy.com.ico
    ├── gogo.anime.png
    └── ... (downloaded icons)
```

## Implementation Details

### Functions

- **`main()`**: Orchestrates the entire process
- **`extractPackageName()`**: Extracts `@package` property using regex
- **`extractIconURL()`**: Extracts `@icon` property using regex
- **`downloadIcon()`**: Downloads icon from URL with 30-second timeout
- **`updateIconProperty()`**: Replaces `@icon` URL in extension file

### Configuration

Constants in `main.go`:
- `repoDir`: Source directory containing extensions (`"repo"`)
- `iconDir`: Destination directory for icons (`"icon"`)
- `baseIconURL`: GitHub raw content base URL

## Error Handling

The script handles various error scenarios:
- **Certificate errors**: TLS certificate validation failures
- **Network errors**: DNS resolution, connection timeouts
- **HTTP errors**: 403 Forbidden, 404 Not Found, etc.
- **File I/O errors**: Failed to read/write files

Failed downloads don't prevent processing of remaining files. Icons are cleaned up on failure.

## Performance

- HTTP client timeout: 30 seconds per icon
- Processes ~167 extensions in ~9 minutes (depending on network)
- Parallel operations: Sequential processing per extension (no concurrent requests)
