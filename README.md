# SpotSpoof CLI

[![GitHub release](https://img.shields.io/github/v/release/slimpagey/spotspoof-cli)](https://github.com/slimpagey/spotspoof-cli/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/slimpagey/spotspoof-cli/release.yml?branch=main)](https://github.com/slimpagey/spotspoof-cli/actions)
[![License](https://img.shields.io/github/license/slimpagey/spotspoof-cli)](LICENSE)
[![Rust Version](https://img.shields.io/badge/rust-1.83%2B-blue)](https://www.rust-lang.org/)

> Detect lookalike and IDN homograph phishing domains to protect against spoofing attacks

## Table of Contents

- [Features](#features)
- [Limitations](#limitations)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [Examples](#examples)
  - [API Examples](#api-examples)
- [API Server](#server-mode)
- [Development](#development)
- [Contributing](#contributing)

## Features

- **Dual Detection Modes**: Identifies both ASCII lookalike domains (paypai.com) and IDN/Punycode homograph attacks (амаzоn.com)
- **CLI and API Server**: Use as a command-line tool or run as an HTTP microservice for SOAR/security automation integration
- **Auto-Detection**: Automatically determines if a domain is ASCII or IDN and uses the appropriate lookup method
- **Flexible Output**: Export results as JSON, plain text, or CSV for easy parsing and analysis
- **Structured Logging**: Configurable logging with plain or JSON format, outputting to stdout, stderr, or file
- **Production Ready**: Built-in health check endpoint and OpenAPI documentation for easy integration
- **Lightweight**: Self-contained binary with no external dependencies required
- **Smart URL Parsing**: Strips schemes (`http://`, `https://`, `ftp://`, etc), paths/queries/fragments and ports. Only the domain & TLD are analysed.

## Limitations

- ASCII detection requires the domain database (~150MB download on first use)
- IDN detection covers common homograph attacks but may not catch all Unicode spoofing variants
- Similarity scoring is heuristic-based and may produce false positives/negatives
- Does not verify if detected lookalike domains are actually malicious

## Quick Start

```bash
# Linux example
# Download the latest release (or download using the releases page)
curl -LO https://github.com/slimpagey/spotspoof-cli/releases/latest/download/spotspoof-linux-amd64

# Make it executable
chmod +x spotspoof-linux-amd64

mv spotspoof-linux-amd64 spotspoof

# Run it
./spotspoof  --help
```

## Installation

### Pre-built Binaries (Recommended)

Download the latest release for your platform. The CLI auto-downloads the SQLite DB on first run if it’s missing.

| Platform | Download |
|----------|----------|
| Linux (x86_64) | [spotspoof-linux-amd64](https://github.com/slimpagey/spotspoof-cli/releases/latest/download/spotspoof-linux-amd64) |
| macOS (Apple Silicon) | [spotspoof-darwin-arm64](https://github.com/slimpagey/spotspoof-cli/releases/latest/download/spotspoof-darwin-arm64) |
| Windows | [spotspoof-windows-amd64.exe](https://github.com/slimpagey/spotspoof-cli/releases/latest/download/spotspoof-windows-amd64.exe) |

Or use this one-liner to download and install (Linux/macOS):

```bash
curl -fsSL https://raw.githubusercontent.com/slimpagey/spotspoof-cli/main/install.sh | bash
```

### Package Managers

```bash
# Homebrew
brew tap slimpagey/spotspoof

# Cargo
cargo install spotspoof-cli
```

### Build from Source

**Prerequisites:**
- Rust 1.83 or higher ([Install Rust](https://rustup.rs/))

**Build:**

```bash
# Clone the repository
git clone https://github.com/slimpagey/spotspoof-cli.git
cd spotspoof-cli

# Build the release binary
cargo build --release

# The binary will be at target/release/spotspoof
./target/release/spotspoof --help
```

**Install system-wide:**

```bash
cargo install --path .
```

## Usage

### Basic Usage

```bash
spotspoof [OPTIONS] <COMMAND>
```

### Commands

| Command | Description |
|---------|-------------|
| `lookup` | Auto-detect ASCII vs IDN lookup |
| `ascii` | ASCII spoof lookup |
| `idn` | IDN lookup |
| `serve` | Run an HTTP server for lookups |
| `help` | Print help information |

### Global Options

| Option | Description | Default |
|--------|-------------|---------|
| `--log-format <FORMAT>` | Log output format (`plain` or `json`) | `plain` |
| `--log-destination <DEST>` | Log destination (`stdout`, `stderr`, or `file`) | `stdout` |
| `--log-file <PATH>` | Log file path (required when `--log-destination=file`) | - |
| `-h, --help` | Print help information | - |
| `-V, --version` | Print version information | - |

### Output Formats

Supported by: `lookup`, `ascii`, and `idn` commands

| Option | Description |
|--------|-------------|
| (default) | JSON output |
| `-t, --text` | Plain text output |
| `--csv` | CSV output |
| `-o, --outfile <PATH>` | Write output to a file |

### Database Behavior

- The SQLite DB (~230MB) is auto-downloaded from GitHub releases on first ASCII lookup if missing
- Database location: `./spotspoof.sqlite` (current directory).
- Use `--no-db` on `lookup`, `ascii`, or `serve` to skip DB usage (ASCII results will be empty)

### Server Mode

Start the HTTP server:
```bash
spotspoof serve --host 127.0.0.1 --port 8080 --db spotspoof.sqlite
```

**Available Routes:**
- `GET /` - API information
- `GET /healthz` - Health check endpoint
- `POST /lookup` - Auto-detect and lookup domain
- `POST /ascii` - ASCII spoof lookup
- `POST /idn` - IDN/Punycode lookup
- `GET /docs` - API documentation

### Examples

**Example 1: Lookup usage**

With an ASCII domain:

```bash
spotspoof lookup example.com

{
  "q": "example.com",
  "ascii": true,
  "puny": false,
  "results": [
    {
      "domain": "exame.com",
      "similarity": 82
    }
  ]
}
```

With a Punycode domain:

```bash
spotspoof lookup амаzоn.com

{
  "q": "амаzоn.com",
  "ascii": false,
  "puny": true,
  "results": [
    {
      "domain": "amazon.com",
      "mappings": [
        {
          "unicode": "а",
          "ascii": "a"
        },
        {
          "unicode": "м",
          "ascii": "m"
        },
        {
          "unicode": "а",
          "ascii": "a"
        },
        {
          "unicode": "о",
          "ascii": "o"
        }
      ],
      "is_registered": true
    },
    {
      "domain": "amaz0n.com",
      "mappings": [
        {
          "unicode": "а",
          "ascii": "a"
        },
        {
          "unicode": "м",
          "ascii": "m"
        },
        {
          "unicode": "а",
          "ascii": "a"
        },
        {
          "unicode": "о",
          "ascii": "0"
        }
      ],
      "is_registered": true
    }
  ]
}
```

**Example 2: ASCII usage**
```bash
spotspoof ascii example.com

{
  "q": "example.com",
  "ascii": true,
  "puny": false,
  "results": [
    {
      "domain": "exame.com",
      "similarity": 82
    }
  ]
}
```

Non ASCII domains will not return any results:

```bash
spotspoof ascii амаzоn.com

{
  "q": "амаzоn.com",
  "ascii": true,
  "puny": false,
  "results": []
}
```

**Example 3: Punycode usage**
```bash
spotspoof idn амаzоn.com

{
  "q": "амаzоn.com",
  "ascii": false,
  "puny": true,
  "results": [
    {
      "domain": "amazon.com",
      "mappings": [
        {
          "unicode": "а",
          "ascii": "a"
        },
        {
          "unicode": "м",
          "ascii": "m"
        },
        {
          "unicode": "а",
          "ascii": "a"
        },
        {
          "unicode": "о",
          "ascii": "o"
        }
      ],
      "is_registered": true
    },
    {
      "domain": "amaz0n.com",
      "mappings": [
        {
          "unicode": "а",
          "ascii": "a"
        },
        {
          "unicode": "м",
          "ascii": "m"
        },
        {
          "unicode": "а",
          "ascii": "a"
        },
        {
          "unicode": "о",
          "ascii": "0"
        }
      ],
      "is_registered": true
    }
  ]
}
```

Non Punycode domains will not return any results:

```bash
spotspoof idn example.com

{
  "q": "example.com",
  "ascii": false,
  "puny": true,
  "results": [
    {
      "domain": "example.com",
      "mappings": [],
      "is_registered": true
    }
  ]
}
```

**Example 4: Plaintext output usage**

Lookup:

```bash
spotspoof lookup example.com -t

Domain: exame.com, Similarity: 82
```

IDN Analysis:

```bash
spotspoof idn амаzоn.com -t

Domain: amazon.com,
Mappings: a -> а, m -> м, a -> а, o -> о;
Registered: true

Domain: amaz0n.com,
Mappings: a -> а, m -> м, a -> а, 0 -> о
Registered: true
```

**Example 5: CSV output usage**
```bash
spotspoof lookup example.com --csv

domain,similarity
exame.com,82
```

### API Examples

**Check a domain for spoofing:**
```bash
curl -X POST http://localhost:8080/lookup \
  -H "Content-Type: application/json" \
  -d '{"domain": "paypai.com"}'

{
  "q":"paypai.com",
  "ascii":true,
  "puny":false,
  "results": [
    {
      "domain":"paypal.com",
      "similarity":90
    }
  ]
}
```

**ASCII-only lookup:**
```bash
curl -X POST http://localhost:8080/ascii \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

{
  "q":"example.com",
  "ascii":true,
  "puny":false,
  "results": [
    {
      "domain":"exame.com",
      "similarity":82
    }
  ]
}
```

**IDN lookup:**
```bash
curl -X POST http://localhost:8080/idn \
  -H "Content-Type: application/json" \
  -d '{"domain": "амаzоn.com"}'

{
  "q":"амаzоn.com",
  "ascii":false,
  "puny":true,
  "results": [
    {
      "domain":"amazon.com",
      "mappings": [
        {
          "unicode":"а",
          "ascii":"a"
        },
        {
          "unicode":"м",
          "ascii":"m"
        },
        {
          "unicode":"а",
          "ascii":"a"
        },
        {
          "unicode":"о",
          "ascii":"o"
        }
      ],
      "is_registered":true
    },
    {
      "domain":"amaz0n.com",
      "mappings": [
        {
          "unicode":"а",
          "ascii":"a"
        },
        {
          "unicode":"м",
          "ascii":"m"
        },
        {
          "unicode":"а",
          "ascii":"a"
        },
        {
          "unicode":"о",
          "ascii":"0"
        }
      ],
      "is_registered":true
    }
  ]
}
```

**Health check:**
```bash
curl http://localhost:8080/healthz

{
  "ok": true
}
```

## Development

### Setup Development Environment

```bash
# Clone the repo
git clone https://github.com/slimpagey/spotspoof-cli.git
cd spotspoof-cli

# Install dependencies
cargo build

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- --help
```

### Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Code Style

This project uses:
- `rustfmt` for code formatting: `cargo fmt`
- `clippy` for linting: `cargo clippy`

Please run both before submitting a PR.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Ways to Contribute

- Report bugs via [GitHub Issues](https://github.com/slimpagey/spotspoof-cli/issues/new?template=bug_report.yml)
- Suggest features via [GitHub Issues](https://github.com/slimpagey/spotspoof-cli/issues/new?template=feature_request.yml)
- Improve documentation
- Submit pull requests

## Security

See [SECURITY.md](SECURITY.md) for information on reporting security vulnerabilities.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
