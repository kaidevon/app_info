# app_info

[![Release](https://img.shields.io/github/v/release/kaidevon/app_info?style=flat)](https://github.com/kaidevon/app_info/releases)
[![Stars](https://img.shields.io/github/stars/kaidevon/app_info?style=flat)](https://github.com/kaidevon/app_info/stargazers)
[![License](https://img.shields.io/github/license/kaidevon/app_info)](./LICENSE)
[![C99](https://img.shields.io/badge/C-C99-blue)](.)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Android-lightgrey)](.)
[![CI](https://github.com/kaidevon/app_info/actions/workflows/release.yml/badge.svg)](https://github.com/kaidevon/app_info/actions/workflows/release.yml)

A pure-C `apk` parser. Zero dependencies. 19 KB binary. Native Android NDK build.

<img src="docs/demo.gif" width="900" alt="app_info demo" />

## Features

- A malware-friendly zip extractor, resistant to [BadPack](https://unit42.paloaltonetworks.com/apk-badpack-malware-tampered-headers/) header tampering;
- A full AXML (Android Binary XML) implementation;
- A full ARSC (Android Resource) implementation;
- MainActivity extraction follows the same logic as the Android OS ([reference](https://xrefandroid.com/android-16.0.0_r2/xref/frameworks/base/core/java/android/app/ApplicationPackageManager.java#310));
- Multi-locale application label resolution (`zh-CN` / `en` / `ja` / ...);
- Full component extraction: `activity`, `activity-alias`, `service`, `receiver`, `provider`;
- Full permission extraction: `uses-permission`, `uses-permission-sdk-23`, `permission`;
- Extraction of information contained in the `APK Signature Block 42`:
  - [APK Signature Scheme v1](https://source.android.com/docs/security/features/apksigning);
  - [APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2);
  - [APK Signature Scheme v3](https://source.android.com/docs/security/features/apksigning/v3);
  - [APK Signature Scheme v3.1](https://source.android.com/docs/security/features/apksigning/v3-1);
- X.509 certificate extraction: Subject / Issuer / validity / serial / signature algorithm / MD5, SHA1, SHA256 fingerprints;
- Certificate export: DER or PEM, ready for `openssl`;
- XAPK / APKM container support;
- Static library `.a` linkable into any C / C++ project, no FFI overhead;
- Pure C99, no Rust, no Python, no JVM.

## Getting Started

### Installation

From releases:

```bash
wget https://github.com/kaidevon/app_info/releases/latest/download/app_info-arm64-v8a
chmod +x app_info-arm64-v8a
```

From source:

```bash
make
./build/app_info show /path/to/app.apk
```

For Android:

```bash
cd jni
$ANDROID_NDK_HOME/ndk-build
adb push ../libs/arm64-v8a/app_info /data/local/tmp/
```

### Help

```
A command-line tool to inspect and extract APK files

Usage: app_info [COMMAND]

Commands:
  show         Show basic information about the APK file
  extract      Unpack apk files as zip archive [alias: x]
  axml         Read and pretty-print binary AndroidManifest.xml
  repack       Repack a BadPack-damaged APK into a clean, well-formed zip archive
  name         Print application label only
  package      Print package name only
  permissions  Print permission list only
  cert         Export signing certificates (DER, or --pem)
  completion   Generate shell completion
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Examples

```bash
# basic info
app_info show app.apk

# with signature and certificate details
app_info show app.apk --sigs

# with permissions
app_info show app.apk --perms

# everything
app_info show app.apk --all

# explicit locale
app_info show app.apk zh-CN

# single-field output
app_info name app.apk
app_info package app.apk
app_info permissions app.apk

# decode AndroidManifest.xml
app_info axml app.apk

# export certificates
app_info cert app.apk ./certs/           # DER
app_info cert app.apk ./certs/ --pem     # PEM

# extract / repack
app_info extract app.apk out/
app_info repack broken.apk fixed.apk
```

### C Integration

```c
#include "app_info.h"

int main(void) {
    app_info_t info;
    if (app_info_parse("app.apk", "zh-CN", APP_INFO_OPT_ALL, &info) == APP_INFO_OK) {
        printf("%s: %s\n", info.package, info.app_name);
        printf("permissions: %d\n", info.permission_count);
        if (info.certs.count > 0)
            printf("signer: %s\n", info.certs.items[0].sha256);
        app_info_free(&info);
    }
    return 0;
}
```

```bash
gcc main.c -Iinclude -Lbuild -lapp_info -lz -o demo
```

## Performance

Environment: Xiaomi Pearl (Android), arm64-v8a.

### Batch: 372 system APKs

| Mode | Total | Per APK | Speedup |
|---|---|---|---|
| `app_info batch` | **1.12 s** | **3 ms** | **13.0x** |
| `app_info show` (per-file) | 14.63 s | 39 ms | 1.0x |
| `apk-info show` (per-file) | 14.70 s | 39 ms | 0.99x |

`batch` mode processes N APKs in a single process, amortizing fork / mmap / init across the entire list.

### Single file: WeChat `base.apk` (260 MB)

| Command | Time |
|---|---|
| `app_info show` | **43 ms** |
| `app_info show --sigs --perms` | 56 ms |

Parsing runs after a single `mmap`; the central directory is scanned once; AXML stops at the first `label` match.

## Comparison with apk-info

Both projects parse APK at the binary level, handle BadPack, and extract signatures. They make different architectural choices:

| | **app_info** | **apk-info** |
|---|---|---|
| Language | C99 | Rust |
| Dependencies | zlib | Rust toolchain |
| Binary size | ~19 KB | a few MB |
| Embedding in C | direct `.a` link | FFI / CLI |
| Cross-compile | `ndk-build` | needs target + linker |
| Batch mode | **13x** | not available |
| Permission list | built-in | not available |
| Certificate export | DER / PEM | not available |
| XAPK / APKM | yes | yes |
| Stamp / Channel Block | planned | yes |
| Python bindings | planned (ctypes) | PyO3 |

**app_info** is built for embedding: the `.a` links directly into a C/C++ project, `ndk-build` cross-compiles with no toolchain overhead. **apk-info** is built for feature breadth: every corner ID in the signing block is parsed. Users pick per scenario.

## FAQ

**Why does this project exist?**

While adding Android support to my [fast_ptrscan](https://github.com/kaidevon/fast_ptrscan) project, I needed to enumerate installed apps so users could pick one. androguard and apk-info are not friendly to C/C++ integration, so I spent some time building this.

**Why C and not Rust?**

Because the goal is embedding into existing C/C++ projects and Android NDK builds. A pure C library links anywhere, compiles in seconds, and has zero runtime.

**Does it modify APKs?**

No. Read-only. `repack` only rewrites a BadPack-damaged ZIP into a well-formed one; it does not touch the contents.

**How do I sign a repacked APK?**

`repack` produces an unsigned APK. Use [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) to sign and zipalign in one pass:

```bash
java -jar uber-apk-signer.jar --apks ./fixed.apk
```

**Does it support XAPK / APKM?**

Yes. Tested on Minecraft 1.26.21.1 (arm64-v8a).

**How is this different from androguard or apk-info?**

androguard is not optimized for large-scale batch analysis, and neither androguard nor apk-info integrates cleanly into C/C++ projects. app_info targets that gap.

## Credits

- [androguard](https://github.com/androguard/androguard)
- [apk-info](https://github.com/delvinru/apk-info)

## License

MIT. See [LICENSE](LICENSE).