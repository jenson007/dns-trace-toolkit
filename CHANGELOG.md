# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog and the project uses Semantic Versioning.

## [1.1.0] - 2026-11-15

### Added
- Policy state snapshot support via `-SnapshotOnly` and `-PolicyStatePath`.
- Reset-only mode via `-ResetOnly` to restore exactly the previously saved values.
- Automatic policy-state backup before each normal measurement run.

### Changed
- `-RollbackAtEnd` now restores the original saved policy state instead of bluntly deleting policy values.

## [1.0.1] - 2026-11-15

### Fixed
- Suppressed `pktmon` command output inside helper calls so phase results are always single structured objects.
- Prevented custom workload script output from polluting function return values in `dns-trace-compare.ps1`.
- Resolved the `QueryPackets` property access error during phase comparison (`baseline/optimized`).

## [1.0.0] - 2026-11-15

### Added
- Initial release of `dns-trace-all-in-one.ps1`
- Included `dns-trace-compare.ps1` for explicit two-phase runs
- Automated trace artifact generation (`etl`, `pcapng`, `txt`, `summary.json`, `summary.csv`)
- Optional policy rollback via `-RollbackAtEnd`
