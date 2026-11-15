# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog and the project uses Semantic Versioning.

## [1.0.0] - 2026-11-15

### Added
- Initial release of `dns-trace-all-in-one.ps1`
- Included `dns-trace-compare.ps1` for explicit two-phase runs
- Automated trace artifact generation (`etl`, `pcapng`, `txt`, `summary.json`, `summary.csv`)
- Optional policy rollback via `-RollbackAtEnd`
