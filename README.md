# dirfuzz

Fast web path brute-forcer with **smart 404 detection**, written in Go.

```
     ___  _      ______
    / _ \(_)____/ ____/_  __________
   / // / / __/ /_/ / / / /_  /_  /
  / ___/ / / / __/ / /_/ / / /_/ /_
 /_/  /_/_/ /_/   \__,_/ /___/___/
```

dirfuzz discovers hidden files and directories on web servers by brute-forcing paths from a wordlist. Unlike similar tools, it includes a **smart filter** that automatically detects and hides custom 404 pages — those annoying "soft-404s" that return HTTP 200 but are actually error pages.

## Features

- **Smart 404 Detection** — Automatically calibrates against the target before scanning, then filters out soft-404 responses in real time. No manual `--exclude-size` guessing needed.
- **Built-in Wordlist** — Ships with a 9,680-entry default wordlist (same as dirsearch). No external files required.
- **Fast** — Concurrent scanning with configurable thread count (default: 25).
- **Recursive Scanning** — Automatically discovers directories and scans deeper.
- **Multiple Output Formats** — Text (colored), JSON, CSV.
- **Flexible Filtering** — Filter by status code, response size, or let the smart filter handle it.
- **Single Binary** — No dependencies. Download and run.

## Installation

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
dirfuzz -u https://target.com -r -R 2

# Through a proxy with custom headers
dirfuzz -u https://target.com --proxy http://127.0.0.1:8080 -H "Authorization: Bearer token"
```

## How Smart Filter Works

Most web servers return a custom "Not Found" page with HTTP 200 for non-existent paths. Traditional tools show hundreds of these as hits, burying real results in noise.

dirfuzz solves this in two phases:

**1. Calibration** (before scanning)
- Sends 5 requests to random non-existent paths (e.g. `/dirfuzz_probe_a8f2c1e9`)
- Records the response fingerprint: status code, body hash, body size, word count
- Builds a baseline per status code

**2. Runtime Filtering** (during scanning)
- Each response is compared against the baseline using three-tier matching:
  - **Exact hash match** — Body is byte-identical to the baseline (static 404 page)
  - **Fuzzy match** — Body size within threshold (default: 50 bytes) AND word count within 5% (dynamic 404 with timestamps/tokens)
  - **No match** — Response is genuinely different, shown as a real result

The smart filter auto-disables itself if calibration fails (e.g. rate-limited), so scanning always continues.

## All Options

```
Target:
  -u, --url string             Target URL (required)
  -w, --wordlist string        Custom wordlist path (default: built-in)
  -e, --extensions strings     File extensions to test (e.g. php,html,js)
  -f, --force-extensions       Append extensions to every wordlist entry

Performance:
  -t, --threads int            Number of concurrent threads (default 25)
      --timeout duration       HTTP request timeout (default 10s)
      --delay duration         Delay between requests per thread

Smart Filter:
      --smart-filter           Enable smart 404 detection (default true)
      --smart-filter-threshold Size tolerance in bytes (default 50)

Filtering:
  -i, --include-status ints    Only show these status codes (comma-separated)
  -x, --exclude-status ints    Hide these status codes (comma-separated)
      --exclude-size ints      Hide responses of these sizes (comma-separated)

Output:
  -o, --output string          Output file path
      --format string          Output format: text, json, csv (default "text")
  -q, --quiet                  Minimal output
      --no-color               Disable colored output

Recursion:
  -r, --recursive              Enable recursive scanning
  -R, --max-depth int          Maximum recursion depth (default 3)

HTTP:
  -H, --header strings         Custom headers (Key: Value), repeatable
      --user-agent string      Custom User-Agent string
      --proxy string           HTTP/SOCKS proxy URL
      --follow-redirects       Follow HTTP redirects
```

## Output Example

```
 200      1532  https://target.com/admin
 301        0  https://target.com/images -> https://target.com/images/
 200      3847  https://target.com/.env
 403       287  https://target.com/.git/config
 200     12043  https://target.com/api/swagger.json

Completed: 9680 requests | Filtered: 847 | Errors: 3 | Duration: 38.2s | 253.4 req/s
```

Status codes are color-coded in the terminal: green (2xx), cyan (3xx), yellow (4xx), red (5xx).

## License

MIT
