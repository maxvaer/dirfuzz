# dirfuzz

Fast web path brute-forcer with **smart 404 detection**, written in Go.

```
     _ _       __
  __| (_)_ __ / _|_   _ ________
 / _` | | '__| |_| | | |_  /_  /
| (_| | | |  |  _| |_| |/ / / /
 \__,_|_|_|  |_|  \__,_/___/___/
```

dirfuzz discovers hidden files and directories on web servers by brute-forcing paths from a wordlist. Unlike similar tools, it includes a **smart filter** that automatically detects and hides custom 404 pages — those annoying "soft-404s" that return HTTP 200 but are actually error pages.

## Features

- **Smart 404 Detection** — Automatically calibrates against the target before scanning, then filters out soft-404 responses in real time using composite 2-of-3 scoring (body length, word count, line count). No manual `--exclude-size` guessing needed.
- **Duplicate Response Filter** — Automatically suppresses repeated identical responses (same status + body hash) after a configurable threshold (default: 2). Catches catch-all pages the smart filter misses.
- **Built-in Wordlists** — Ships with a 9,680-entry default path wordlist and a 5,000-entry vhost wordlist. No external files required.
- **Fast** — Concurrent scanning with configurable thread count (default: 25).
- **Recursive Scanning** — Automatically discovers directories and scans deeper. Directories inferred from crawled paths are also recursively scanned. Per-directory smart filter re-calibration enabled by default.
- **HTTP Method Fuzzing** — Try multiple HTTP methods (GET, POST, PUT, etc.) per path to find hidden endpoints.
- **Virtual Host Fuzzing** — Fuzz the Host header to discover virtual hosts on a target. Built-in top-5000 subdomain list included.
- **Crawl Discovery** — Automatically parses HTML responses for links and scans discovered paths (enabled by default). Infers parent directories from crawled URLs for recursive scanning.
- **Multiple Targets** — Scan from a URL list (`-l`), CIDR range (`--cidr`), or Burp request file (`-r`).
- **ETA-based Skipping** — Automatically skips slow targets when ETA exceeds a threshold (default: 1 hour). Useful for multi-target scans.
- **Result Hooks** — Execute shell commands for each result with JSON on stdin and placeholder expansion.
- **Resume Support** — Save and resume interrupted scans with `--resume-file`.
- **Adaptive Throttling** — Automatically backs off on 429/rate-limit responses.
- **Multiple Output Formats** — Text (colored, with column headings), JSON, CSV. Path-only output by default, `--full-url` to show complete URLs.
- **Flexible Filtering** — Filter by status code, response size, body content, or let the smart filter handle it.
- **Directory Tree** — Print a directory tree summary after scan with `--tree`.
- **Sortable Results** — Sort results by status code, path, or response size with `--sort`.
- **Self-Update** — Update to the latest version with `dirfuzz --update`.
- **Single Binary** — No dependencies. Download and run.

## Installation

### Download

Pre-built binaries for Linux, macOS, and Windows are available on the [Releases](https://github.com/maxvaer/dirfuzz/releases) page.

### From Source

```bash
go install github.com/maxvaer/dirfuzz@latest
```

### Build Locally

```bash
git clone https://github.com/maxvaer/dirfuzz.git
cd dirfuzz
go build -o dirfuzz .
```

### Update

```bash
dirfuzz --update
```

## Quick Start

```bash
# Basic scan with smart filter (enabled by default)
dirfuzz -u https://target.com

# Scan with specific extensions
dirfuzz -u https://target.com -e php,html,js

# 50 threads, exclude 403 and 500 responses
dirfuzz -u https://target.com -t 50 -x 403,500

# Use a custom wordlist, output JSON
dirfuzz -u https://target.com -w /path/to/wordlist.txt -o results.json --format json

# Disable smart filter for manual control
dirfuzz -u https://target.com --smart-filter=false

# Recursive scan up to depth 2
dirfuzz -u https://target.com --recursive -R 2

# Through a proxy with custom headers
dirfuzz -u https://target.com --proxy http://127.0.0.1:8080 -H "Authorization: Bearer token"

# Try multiple HTTP methods per path
dirfuzz -u https://target.com --methods GET,POST,PUT,DELETE

# Virtual host fuzzing (uses built-in top-5000 subdomain list)
dirfuzz -u https://target.com --vhost

# Virtual host fuzzing with a custom wordlist
dirfuzz -u https://target.com --vhost --vhost-wordlist custom-hosts.txt

# Scan a CIDR range on specific ports
dirfuzz --cidr 192.168.1.0/24 --ports 80,443,8080

# Scan multiple URLs from a file
dirfuzz -l urls.txt -w wordlist.txt

# From a Burp Suite request export
dirfuzz -r burp_request.txt -e php,html

# Run a hook command for each result
dirfuzz -u https://target.com --on-result "notify-send 'Found {url} ({status})'"

# Resume an interrupted scan
dirfuzz -u https://target.com --resume-file scan.state

# Only show responses containing a specific string
dirfuzz -u https://target.com --match-body "admin"

# Show full URLs instead of paths
dirfuzz -u https://target.com --full-url

# Sort results by status code
dirfuzz -u https://target.com --sort status

# Print a directory tree after scan
dirfuzz -u https://target.com --tree

# Disable crawl (enabled by default)
dirfuzz -u https://target.com --crawl=false

# Skip targets that would take more than 30 minutes
dirfuzz -l urls.txt --max-eta 30m

# Disable ETA-based skipping
dirfuzz -u https://target.com --max-eta 0
```

## How Smart Filter Works

Most web servers return a custom "Not Found" page with HTTP 200 for non-existent paths. Traditional tools show hundreds of these as hits, burying real results in noise.

dirfuzz solves this in two phases:

**1. Calibration** (before scanning)
- Sends 5 requests to random non-existent paths (e.g. `/dirfuzz_probe_a8f2c1e9`)
- Records the response fingerprint: status code, body hash, body size, word count, line count
- Builds a baseline per status code

**2. Runtime Filtering** (during scanning)
- Each response is compared against the baseline using three-tier matching:
  - **Exact hash match** — Body is byte-identical to the baseline (static 404 page)
  - **Composite fuzzy match** — Uses 2-of-3 scoring across body length (within byte threshold), word count (within 5%), and line count (within 10%). If at least 2 of the 3 metrics match the baseline, the response is filtered. This catches dynamic 404 pages with timestamps, tokens, or slight variations.
  - **No match** — Response is genuinely different, shown as a real result
- Empty-body 200 responses are automatically filtered as catch-all pages

**Per-directory re-calibration** (`--smart-filter-per-dir`, enabled by default) re-runs calibration for each subdirectory during recursive scans, since different directories may have different custom 404 pages.

The **duplicate response filter** (`--duplicate-threshold`, default: 2) provides a second layer of protection. After seeing the same response (status + body hash) more than the threshold number of times, subsequent duplicates are automatically suppressed. This catches catch-all pages that the smart filter baseline missed.

The smart filter auto-disables itself if calibration fails (e.g. rate-limited), so scanning always continues.

For virtual host fuzzing (`--vhost`), calibration sends requests with random subdomain Host headers instead of random paths, building a baseline for the default vhost response.

## All Options

```
TARGET:
  -u, --url string                  Target URL
  -l, --urls-file string            File with one URL per line
  -r, --request-file string         Raw HTTP request file (e.g. Burp Suite export)
  -w, --wordlist string             Custom wordlist path (default: built-in)
  -e, --extensions strings          File extensions to test (e.g. php,html,js)
  -f, --force-extensions            Append extensions to every wordlist entry
      --cidr string                 CIDR range to scan (e.g. 192.168.1.0/24)
      --ports string                Ports for CIDR targets (comma-separated)

DISCOVERY:
      --recursive                   Enable recursive scanning
  -R, --max-depth int               Maximum recursion depth (default 2)
      --crawl                       Crawl discovered pages for additional paths (default true)
      --crawl-depth int             Maximum crawl depth (link-following hops) (default 2)
      --vhost                       Enable virtual host fuzzing mode
      --vhost-wordlist string       Wordlist of hostnames for vhost fuzzing (default: built-in top-5000)

MATCHERS:
  -i, --include-status ints         Only show these status codes (comma-separated)
      --match-body string           Only show responses containing this string

FILTERS:
  -x, --exclude-status ints         Hide these status codes (comma-separated)
      --exclude-size ints           Hide responses of these sizes (comma-separated)
      --exclude-body string         Hide responses containing this string
      --smart-filter                Enable smart 404 detection (default true)
      --smart-filter-threshold int  Size tolerance in bytes for smart filter (default 50)
      --smart-filter-per-dir        Re-calibrate smart filter per subdirectory (default true)
      --duplicate-threshold int     Duplicates allowed before filtering same responses (default 2, 0 to disable)

RATE-LIMIT:
  -t, --threads int                 Number of concurrent threads (default 25)
      --timeout duration            HTTP request timeout (default 10s)
      --delay duration              Delay between requests per thread
      --adaptive-throttle           Auto back-off on 429/rate limits
      --max-eta duration            Skip target if ETA exceeds this duration (default 1h0m0s, 0 to disable)

HTTP:
  -H, --header strings              Custom headers (Key: Value), repeatable
      --user-agent string           Custom User-Agent string
      --proxy string                HTTP/SOCKS proxy URL
      --follow-redirects            Follow HTTP redirects
      --methods strings             HTTP methods to try per path (e.g. GET,POST,PUT)

OUTPUT:
  -o, --output string               Output file path
      --format string               Output format: text, json, csv (default "text")
      --full-url                    Show full URL instead of path in output
  -s, --silent                      Minimal output
      --no-color                    Disable colored output
      --sort string                 Sort results: status, path, size (buffers until scan completes)
      --tree                        Print directory tree summary after scan
      --on-result string            Shell command for each result (receives JSON on stdin)

CONFIGURATION:
      --resume-file string          File to save/load scan progress for resume

UPDATE:
      --update                      Update dirfuzz to the latest version
```

## Output Examples

### Default text output (paths only)

```
Code      Size  Path
 200      1532  /admin
 301        0  /images -> https://target.com/images/
 200      3847  /.env
 403       287  /.git/config
 200     12043  /api/swagger.json

Completed: 9680 requests | Filtered: 847 | Errors: 3 | Duration: 38.2s | 253.4 req/s
```

### Full URL output (`--full-url`)

```
Code      Size  URL
 200      1532  https://target.com/admin
 301        0  https://target.com/images -> https://target.com/images/
 200      3847  https://target.com/.env
```

Status codes are color-coded in the terminal: green (2xx), cyan (3xx), yellow (4xx), red (5xx).

### Method fuzzing output

```
Code      Size  Path
[POST] 200      0  /api/users
[PUT]  200      0  /api/config
```

### Virtual host fuzzing output

```
Code      Size  Path
[dev.target.com] 200     4521  /
[staging.target.com] 200  8732  /
```

### Directory tree output (`--tree`)

```
.
├── admin/
│   ├── config/
│   └── users/
├── api/
│   └── v1/
└── assets/
    ├── css/
    └── js/
```

## Hook System

The `--on-result` flag runs a shell command for each non-filtered result. The command receives a JSON payload on stdin and supports placeholder expansion:

| Placeholder | Value |
|-------------|-------|
| `{url}` | Full URL |
| `{path}` | Path component |
| `{status}` | HTTP status code |
| `{size}` | Response size in bytes |
| `{method}` | HTTP method |
| `{host}` | Host header (vhost mode) |

```bash
# Desktop notification
dirfuzz -u https://target.com --on-result "notify-send 'Found {url}'"

# Log to file
dirfuzz -u https://target.com --on-result "echo '{method} {status} {url}' >> hits.log"

# Pipe JSON to jq
dirfuzz -u https://target.com --on-result "jq -r '.url' >> urls.txt"
```

## Wordlist Credits

dirfuzz ships with built-in wordlists so you can start scanning without downloading external files:

- **Path wordlist** (`dicc.txt`, 9,680 entries) — From [dirsearch](https://github.com/maurosoria/dirsearch) by Mauro Soria. A curated list of common web paths, files, and directory names with `%EXT%` extension placeholders.
- **VHost wordlist** (`vhosts.txt`, 5,000 entries) — `subdomains-top1million-5000.txt` from [SecLists](https://github.com/danielmiessler/SecLists) by Daniel Miessler, Jason Haddix, and community contributors. The top 5,000 most common subdomains ranked by real-world frequency.

Both wordlists can be overridden with `-w` (paths) or `--vhost-wordlist` (vhosts).

## License

MIT
