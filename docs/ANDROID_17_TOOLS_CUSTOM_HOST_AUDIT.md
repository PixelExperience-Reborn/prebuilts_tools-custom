# Android 17 source audit: legacy `prebuilts/tools-custom` (matrix row 160)

**Decision (2026-11-06): retain as a historical host-tool reference; do not import into the Android 17 ROM source graph.** This is a selective porting decision, not a claim that every old tool has an equivalent in AOSP17 or that `lz4c`/Perl/dtc are categorically unnecessary for future device work.

## Exact historical source

- PixelExperience-Reborn `seventeen`, `fourteen`, `thirteen`, and `twelve` resolve to **`3cdca8d9ecc9281bc488b0837da7c4b81f1d39a4`**, dated **2022-08-08**; root tree **`7275f748a09bf6d1cf7bfbf36338dc1a93f1b673`**.
- Its final commit, [`Remove lz4 prebuilts`](https://github.com/PixelExperience-Reborn/prebuilts_tools-custom/commit/3cdca8d9ecc9281bc488b0837da7c4b81f1d39a4), removes exactly six `lz4` / `lz4cat` / `unlz4` paths on Linux and Darwin while retaining `lz4c` for legacy kernels. This rationale was recorded by the old developers, and does **not** imply that mondrian's current or future kernel must invoke this binary.
- The full Git tree has **660 entries**, of which **557 are blobs** totaling **17,613,535 bytes**. Partitioned:
  - `common/perl-base`: 539 files / 3,192,940 B, including historical Perl modules and native `.so` extensions.
  - `linux-x86/bin`: 7 blobs / 9,885,561 B, including `cpio`, `lz4c`, `lzma`, `mogrify`, `perl`, `perl5.26.1`, and `nproc` symlink.
  - `linux-x86/dtc`: 1 executable / 326,120 B.
  - `darwin-x86/bin`: 5 blobs / 3,520,426 B: `cpio`, `lz4c`, `lzma`, `perl`, and `nproc` symlink.
  - `darwin-x86/dtc`: 1 executable / 134,556 B.
  - `darwin-x86/lib`: 4 libraries / 553,932 B.
- Git symlink blobs: `linux-x86/bin/nproc` targets `../../../build-tools/linux-x86/bin/toybox`; Darwin equivalent targets `../../../build-tools/darwin-x86/bin/toybox`. These are **historic relative path assumptions**. Presence of `prebuilts/build-tools` in Android 17's source manifest does **not** demonstrate these exact old binary paths still exist; no compatibility is asserted.
- These tools trace back mostly to **2019–2020**. The repo is a host executable/data archive, with **no `Android.bp`, `Android.mk` or `BUILD.bazel`** in the selected tree. Do not bulk copy these binaries into Android 17 or execute them in untrusted CI.

## Why the old repo is not an AOSP17 source requirement

The historical [`snippets/pixel-extras.xml`](https://github.com/PixelExperience-Reborn/manifest/blob/port/a17-aosp17-manifest-20261102/snippets/pixel-extras.xml) imported `prebuilts_tools-custom` at `prebuilts/tools-custom`. The modern, deliberately isolated Android17 `default.xml` does **not** import that old snippet.

The official tag `android-17.0.0_r1` uses `platform/prebuilts/build-tools`, `platform/prebuilts/tools`, `platform/prebuilts/clang/host/linux-x86` and `platform/system/tools/mkbootimg`. AOSP17's baseline manifest does **not** have an owner for `prebuilts/tools-custom`. The audited 25-stage profile graph must keep those official owners and reject any unreviewed reintroduction of the old project path or repository name. No additional `PRODUCT_PACKAGES`, Soong host module, kernel build rule or PATH override is warranted today.

There is no reviewed PE-Reborn `mondrian` device/common/vendor/kernel tree yet. Existing LF52406 sm8450-common/5.10 work is **read-only technical reference**; it cannot independently prove which host tools the new PE-Reborn vendor extraction or kernel build will need. Legacy `lz4c` (kernel packing), `dtc` (device trees), `cpio` (ramdisk) and `mogrify` (asset handling) must be evaluated against the exact future build scripts and verified modern host toolchain. Do not infer device compatibility from matching filenames.

## Applied source-only protections

- Audit branch: `audit/a17-tools-custom-host-20261106`, leaving `seventeen` untouched.
- `audit/check_tools_custom_source.py` verifies immutable SHA/tree, last historic commit's six deletions, all blob counts/byte aggregates grouped by architecture, 12 important object SHAs, two symlinks and manifest owner/exclusion. It **does not run or download old tool binaries**.
- `.github/workflows/a17-tools-custom-source.yml` uses a sparse metadata-only checkout, GitHub tree API, the manifest validator, its negative regression suite, and the official `repo manifest` parser.
- The PE-Reborn Android17 manifest validator rejects the `prebuilts/tools-custom` project path and `prebuilts_tools-custom` repository. The historical archive and its import snippet remain intact for future review.

## Required later gates

1. Build the independent PE-Reborn **mondrian-only** device/kernel/vendor/module source graph, then enumerate actual host program calls and versions, including old/external extraction tools when reaching matrix row 161 `tools/extract-utils`.
2. Select supported/reproducible tool versions, record upstream license and pinned source, check host Linux ABI, and safely test required binary behavior using controlled inputs. Do not execute archived binaries from an unknown provenance automatically.
3. Verify extraction, dynamic partition/boot/vendor_boot/DTBO image handling, kernel 5.10 modules, AVB signing policy, Soong/Make, SELinux/VINTF, CTS/VTS and actual physical mondrian boot separately.

**Not verified:** tool runtime, source reproducibility, security, host ABI, complete Android17 checkout/build or device boot.

## References

- [Old PE source](https://github.com/PixelExperience-Reborn/prebuilts_tools-custom/tree/seventeen)
- [Historical last commit](https://github.com/PixelExperience-Reborn/prebuilts_tools-custom/commit/3cdca8d9ecc9281bc488b0837da7c4b81f1d39a4)
- [AOSP17 manifest port](https://github.com/PixelExperience-Reborn/manifest/tree/port/a17-aosp17-manifest-20261102)
