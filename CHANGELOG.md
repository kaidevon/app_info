# Changelog

## [1.0.1] - 2026-10-04

### Fixed
- `app_info_parse` opened the APK file 5 times and walked the central
  directory 5 times per invocation. Now a single `open()` + single
  `mmap()` (or `pread()` for files < 4 MB), with one central directory
  pass shared across manifest, ARSC, signature, and container scans.
  Reported by @delvinru.
- README incorrectly claimed "parsing runs after a single mmap". The
  claim now matches the implementation.

### Removed
- Dead `scan_zip` / `scan_signatures_mmap` helpers.
- Duplicate `mem_find_eocd`.

## [1.0.0] - 2026-10-04

### Added
- Initial release.
- AXML / ARSC binary parsers.
- X.509 certificate extraction (Subject, Issuer, validity, serial,
  signature algorithm, MD5 / SHA1 / SHA256 fingerprints).
- Certificate export (DER / PEM).
- XAPK / APKM container support.
- CLI: `show`, `extract`, `axml`, `repack`, `name`, `package`,
  `permissions`, `cert`, `batch`, `completion`, `help`.
- Android NDK build (arm64-v8a, armeabi-v7a, x86_64).
- MIT license.