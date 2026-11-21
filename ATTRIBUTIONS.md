# Attributions

> Attributions for the **combolite-core** package. The umbrella `db-combolite` repository keeps the
> full project-wide attributions (including demo- and accelerator-only components); this file covers
> what combolite-core itself vendors and links, so the record resolves when the package is consumed
> standalone.

## Authorship

combolite-core is designed and owned by Casey Annis (unklStewy).

The specification and implementation were developed with the help of Claude, an AI assistant made by
Anthropic, working through Claude Code, and Gemini, an AI assistant made by Google DeepMind, working
through Antigravity. Every design decision in the specification was confirmed by the owner.

## Third-party components

| Component | Use | License | Location |
|---|---|---|---|
| [Unity](https://github.com/ThrowTheSwitch/Unity) v2.6.1 | Unit-test framework, used only in tests | MIT | `third-party/unity/` |
| [XZ Utils](https://tukaani.org/xz/) v5.8.4, liblzma only | LZMA2 compression (spec §15), built when `CDB_WITH_XZ` is on | 0BSD | `third-party/xz/` |
| [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) (libmbedcrypto) | Cryptography and authenticated encryption (spec §12) | Apache-2.0 / GPL-2.0-or-later | `third-party/mbedtls/` |

Each vendored component keeps its own license file in its directory. Optional accelerator
(`combolite_accel`, CUDA/Vulkan) and demo dependencies are linked, not vendored into the core — see
the umbrella `db-combolite/ATTRIBUTIONS.md` for those.
