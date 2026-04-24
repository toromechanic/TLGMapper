# Asset Provenance

This repository contains TraceLogging provider metadata extracted from Windows binaries and aggregated into provider index files and supporting assets.

## Included provenance artifacts

- `misc/AllTraceLoggingProviders/note.md`
  - Documents how provider data was extracted using the TraceLogging metadata blob parser referenced in the README.
- `TraceLoggingProviders/tlg_provider_index_Windows11_10.0.26200.7705.json`
  - Represents provider index data for Windows 11 build 10.0.26200.7705.
- `TraceLoggingProviders/tlg_provider_index_WindowsServer2025_10.0.26100.32230.json`
  - Represents provider index data for Windows Server 2025 build 10.0.26100.32230.

## Enterprise guidance

- Before redistribution, verify the source and license of the binary data used to generate the provider artifacts.
- Maintainers should keep the original extraction notes and source references intact.
- If additional TraceLogging provider datasets are added, add a corresponding provenance entry here.

## Scope

This repository is a reverse-engineering utility and a provider metadata collection. It does not itself claim ownership of Microsoft platform data; it preserves the provenance notes that describe how those datasets were generated.
