# Vendored Mbed TLS (libmbedcrypto)

- **Release:** Mbed TLS 3.6.5 (LTS), released 2025-10-14.
- **Pinned commit:** `e185d7fd85499c8ce5ca2a54f5cf8fe7dbe3f8df`, tags `mbedtls-3.6.5` / `v3.6.5`
  (annotated, tagger Minos Galanakis <minos.galanakis@arm.com>), fetched from the upstream repo
  `https://github.com/Mbed-TLS/mbedtls.git`.
- **Source:** `https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.bz2`
- **SHA-256 of the tarball:** `4a11f1777bb95bf4ad96721cac945a26e04bf19f57d905f241fe77ebeddf46d8`,
  verified on 2026-11-15 against the release's own `mbedtls-3.6.5-sha256sum.txt`. Mbed TLS publishes
  a checksum file (not a GPG tarball signature) and does not GPG-sign its git tags, so verification
  is by the official SHA-256 plus the upstream-repo-fetched pinned commit — unlike the GPG-verified
  `xz` vendoring.
- **License:** Apache License 2.0 / GPL-2.0-or-later; see `LICENSE`.
- **Why 3.6.5 (bump from 3.6.2, #1):** picks up the 2025 advisory fixes in 3.6.4/3.6.5. combolite-core
  uses only AEAD (AES-256-GCM, ChaCha20-Poly1305), ECDSA/secp256r1, and SHA-256/HMAC/HKDF
  (`src/cdb_crypto.c`), so most of those CVEs are **not reachable** (RSA, CBC+PKCS#7, PEM, LMS); the
  one plausibly-reachable item was CVE-2025-52496 (AESNI-detection race), fixed in 3.6.4. Low
  severity — dependency hygiene for a crypto-critical component.

## What is kept

- **Kept:**
  - `CMakeLists.txt` and `cmake/`, Mbed TLS's own build;
  - `include/` and `library/`, the core cryptographic library (`libmbedcrypto`);
  - `3rdparty/` (Everest Curve25519 and p256-m);
  - `framework/` (internal CMake modules);
  - `LICENSE`, `README.md`, `SECURITY.md`, `BUGS.md`, and `ChangeLog`.
- **Left out:**
  - `programs/` (command-line sample tools);
  - `tests/` (Mbed TLS's internal test suites);
  - `doxygen/` and `docs/`;
  - `visualc/`.

## How it is built

`db-combolite/CMakeLists.txt` configures and adds this directory with `EXCLUDE_FROM_ALL` and links `mbedcrypto` into `combolite`. The following options are enforced:

- `ENABLE_PROGRAMS=OFF`
- `ENABLE_TESTING=OFF`
- `MBEDTLS_FATAL_WARNINGS=OFF`
- `INSTALL_MBEDTLS_HEADERS=OFF`

## Since 2026-11-07: a git submodule

This library is the submodule `third-party/mbedtls`, pinned to the release tag, shallow; the source is
the upstream git tree at that tag rather than the release tarball, so the tarball SHA-256 above
describes the official release artifact (a provenance anchor) rather than the checked-out tree, which
is identified by the pinned commit. Mbed TLS's own `framework` sub-submodule is pinned alongside it.
Its own tests are kept out of the build.
