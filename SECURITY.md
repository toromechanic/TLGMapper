# Security

## Scope

`TLGMapper` is a static analysis utility for IDA Pro that extracts TraceLogging metadata from x64 PE binaries.

## Safe usage

- Treat all input binaries as untrusted.
- Run analysis on isolated or controlled systems when possible.
- Do not use this tool on binaries for which you do not have the right to analyze.
- Secure exported CSV and report files to avoid leaking analysis results.

## Reporting vulnerabilities

If you discover a security issue in this repository, please report it through the repository's issue tracker or through the relevant platform security contact.

## Audit and validation

- `scripts/validate.py` performs repository validation checks.
- `.github/workflows/ci.yml` runs compile-time validation on core Python code.
- `ASSET_PROVENANCE.md` documents the origin of provider metadata assets.

## Disclaimer

This tool is provided "as is" without warranties. Use it at your own risk.
