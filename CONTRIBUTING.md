# Contributing to SpotSpoof

Thank you for your interest in contributing to SpotSpoof! This document provides guidelines and instructions for contributing to the project.

**This project will only accept PRs to the `dev` branch.**

## Getting Started

### Prerequisites

- Rust 1.83 or higher ([Install Rust](https://rustup.rs/))
- Git
- A GitHub account

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork:**
```bash
git clone https://github.com/YOUR_USERNAME/spotspoof-cli.git
cd spotspoof-cli
```

3. **Add the upstream remote:**
```bash
git remote add upstream https://github.com/slimpagey/spotspoof-cli.git
```

4. **Build the project:**
```bash
cargo build
```

5. **Run tests to ensure everything works:**
```bash
cargo test
```

6. **Try running the CLI:**
```bash
cargo run -- --help
```

## Development Workflow

### Creating a Feature Branch

Always create a new branch for your work:

```bash
# Update your main branch
git checkout dev
git pull upstream dev

# Create a feature branch
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `feature/add-subdomain-detection`
- `fix/idn-parsing-error`
- `docs/improve-api-examples`
- `refactor/cleanup-lookup-logic`

### Making Changes

1. **Write code** following our style guidelines (see below)
2. **Add tests** for new functionality
3. **Update documentation** if needed (README, code comments, etc.)
4. **Run the test suite:**
```bash
cargo test
```

5. **Check code formatting:**
```bash
cargo fmt
```

6. **Run the linter:**
```bash
cargo clippy
```

7. **Test manually** with various inputs to ensure it works as expected

## Security Issues

If you discover a security vulnerability, please report it by [opening a security issue](https://github.com/slimpagey/spotspoof-cli/issues/new?template=security_report.yml).

Since SpotSpoof is a public CLI tool that doesn't handle sensitive data, security reports are handled transparently through GitHub issues.

## Questions?

If you have questions about contributing:

- Check existing [GitHub Issues](https://github.com/slimpagey/spotspoof-cli/issues)
- Open a new [Discussion](https://github.com/slimpagey/spotspoof-cli/discussions)
- Review the [README](README.md) and documentation

## License

By contributing to SpotSpoof, you agree that your contributions will be licensed under the same license as the project (MIT License).
