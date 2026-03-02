# Documentation Changelog

Track user-facing documentation updates here, especially changes to CLI behavior, workflows, and troubleshooting guidance.

## Unreleased

### Added

- _Example:_ Added `scan repo --ref` usage examples to CLI reference.

### Changed

- _Example:_ Updated `--format unified` notes to reflect current merge behavior.

### Fixed

- _Example:_ Corrected `validate` success output text.

### Removed

- _Example:_ Removed deprecated env var guidance.

## Release Template

Use this format when cutting a release:

```md
## vX.Y.Z - YYYY-MM-DD

### Added
- ...

### Changed
- ...

### Fixed
- ...

### Removed
- ...
```

## Update Checklist

1. Update this file for any user-visible docs change.
2. Ensure [CLI Reference](./cli-reference.md) matches current argparse flags/defaults.
3. Ensure [Getting Started](./getting-started.md) commands still run as documented.
4. Ensure troubleshooting entries still match real error messages.
