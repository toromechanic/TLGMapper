# Dependencies

`TLGMapper` is intentionally lightweight and designed to minimize supply chain risk.

## Runtime

- `IDA Pro` with IDAPython support.
  - Recommended: IDA 8.x or later.
- `x64 PE` binary input.
- Python standard library only.

## Build and validation

- `python3` for local validation and CI checks.
- `git` is optional but recommended for audit metadata extraction when generating CSV outputs.

## Not required

- No external `pip` packages are required for the core script.
- There is no `requirements.txt` or dependency manager manifest in this repository.
