# Contributing to kasra-sdk

Thank you for your interest in contributing to **kasra-sdk** — the Kasra Rule Engine SDK for AI security governance and code review.

We welcome contributions of all kinds, including bug fixes, new rules, feature requests, documentation improvements, and code changes.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Adding New Rules](#adding-new-rules)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Reporting Issues](#reporting-issues)
- [Security Disclosures](#security-disclosures)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you are expected to uphold this code. Please report unacceptable behavior to the maintainers.

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/your-username/kasra-sdk.git
   cd kasra-sdk
   ```
3. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Python 3.11+

### Install in development mode

```bash
pip install -e ".[dev]"
```

## Project Structure

```
kasra-sdk/
├── src/
│   └── kasra/
│       ├── core/              RuleEngine, RuleRunner, DetectionPipeline
│       ├── models/            Pydantic models (rules, results, context)
│       ├── matchers/          ReMatcher, KeywordMatcher, EntropyMatcher, CompositeMatcher
│       ├── analyzers/         LanguageDetector, LuhnValidator, DataFlowAnalyzer, ...
│       ├── scanner/           CodeReviewScanner, IncrementalScanner, checkers
│       ├── pipeline/          Input, Output, Behavior detection pipelines
│       ├── actions/           Block, Warn, Redact, Clean, Truncate, SoftAllow, Dynamic
│       ├── hooks/             Plugin lifecycle hooks, MetricsCollector
│       ├── audit/             Async logger + Console/File exporters
│       ├── rules/             RuleStore
│       ├── config/            YAML config + env vars
│       └── preprocessing/     Normalizer, Chunker
├── tests/                     Test suite
├── integration_tests/         Integration tests
└── config/                    Configuration files
```

## Adding New Rules

New detection rules are highly appreciated. To add a rule:

1. **Input/Output rules** — add your `RuleDefinition` to the appropriate rule bundle.
2. **Code review rules** — add a new checker in `src/kasra/scanner/checkers/` or a new Semgrep rule.
3. **Add tests** covering at least one positive and one negative case.
4. **Include documentation** describing what the rule detects.

## Pull Request Process

1. **Keep changes focused** — one feature or fix per PR.
2. **Write tests** for new functionality.
3. **Update documentation** if your change affects the API or adds new rules.
4. **Run tests** before submitting:
   ```bash
   pytest tests/ -v
   ```
5. **Rebase** onto the latest `main` before submitting.
6. **Describe your changes** in the PR description — what problem it solves and how.
7. PRs require at least one review before merging.

## Coding Standards

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code.
- Type hints are required for all function signatures.
- Use descriptive variable names and write docstrings for all public APIs and classes.
- Keep functions focused — prefer small, composable units.

### Commit messages

Use conventional commit format:

```
type(scope): brief description

feat:     New feature (e.g. new rule, new matcher)
fix:      Bug fix
docs:     Documentation only
style:    Formatting, no code change
refactor: Code restructuring
test:     Adding or fixing tests
chore:    Build/config changes
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=kasra --cov-report=term-missing

# Run integration tests
pytest integration_tests/ -v

# Run specific test
pytest tests/test_rule_engine.py -v -k "test_detect_input"
```

## Reporting Issues

When opening an issue, please include:

- A clear, descriptive title.
- Steps to reproduce (for bugs).
- Expected vs actual behavior.
- Environment details (OS, Python version).
- Logs or screenshots where applicable.
- For false positive/negative rule reports, include the rule ID and the relevant content.

## Security Disclosures

If you discover a security vulnerability, **do not** open a public issue. Please report it privately to the maintainers.

---

Thank you for helping make kasra-sdk better!
