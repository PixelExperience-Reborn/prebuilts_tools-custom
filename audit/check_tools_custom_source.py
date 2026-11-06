#!/usr/bin/env python3
"""AOSP17 host tool source-boundary audit: never execute archived prebuilts.

Only Git metadata, historical path names, text symlink records and manifest XML
are examined. Not a ROM/kernel build, malware analysis or host ABI test.
"""
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ORIGINAL_COMMIT = "3cdca8d9ecc9281bc488b0837da7c4b81f1d39a4"
ORIGINAL_PARENT = "214ba0cba1a5abab0a17a298a53653c9585a5350"
ORIGINAL_TREE = "7275f748a09bf6d1cf7bfbf36338dc1a93f1b673"
COUNT_ENTRIES = 660
COUNT_BLOBS = 557
BYTES = 17_613_535
GROUPS = {
    "common/perl-base": (539, 3_192_940, 0, 0),
    "darwin-x86/bin": (5, 3_520_426, 4, 1),
    "darwin-x86/dtc": (1, 134_556, 1, 0),
    "darwin-x86/lib": (4, 553_932, 0, 0),
    "linux-x86/bin": (7, 9_885_561, 6, 1),
    "linux-x86/dtc": (1, 326_120, 1, 0),
}
KEY_FILES = {
    "linux-x86/bin/cpio": ("100755", "efdcf660f0f49c81a4aae548e2bb739d55517061"),
    "linux-x86/bin/lz4c": ("100755", "9eff07e5a08b58832f8df20b9112b9bedc7e6a6e"),
    "linux-x86/bin/lzma": ("100755", "a3d253cf3df6d8b0fe289b34ed6f21950c5d83eb"),
    "linux-x86/bin/mogrify": ("100755", "41d6e03334ddd775f51eb65548a9c505f6b4c1c2"),
    "linux-x86/bin/nproc": ("120000", "1e6ef39e0c80dc51b2df8e797cf5d45245ec5645"),
    "linux-x86/bin/perl": ("100755", "e3d6c87b5ceb3704005e551714a36db927c79055"),
    "linux-x86/bin/perl5.26.1": ("100755", "e3d6c87b5ceb3704005e551714a36db927c79055"),
    "linux-x86/dtc/dtc": ("100755", "c52bfb36a6fc0af67e6f8116d339e3c9836a2cf5"),
    "darwin-x86/bin/nproc": ("120000", "0196b7405e9fa988b5d74925de681e0ce2c8abdf"),
    "darwin-x86/bin/lz4c": ("100755", "80cbb52607b39e5bd3234be10a618f14b68909d2"),
    "darwin-x86/bin/perl": ("100755", "a1fd07e0115f8e434bd53a2d7ae8f0a6b75caf47"),
    "darwin-x86/dtc/dtc": ("100755", "cb041740503bf585ebd4dcfffd4fd7287ec04f3d"),
}
LAST_COMMIT_REMOVED = {
    "darwin-x86/bin/lz4",
    "darwin-x86/bin/lz4cat",
    "darwin-x86/bin/unlz4",
    "linux-x86/bin/lz4",
    "linux-x86/bin/lz4cat",
    "linux-x86/bin/unlz4",
}

def need(test, detail):
    if not test:
        raise RuntimeError(detail)

def git(cwd, *args):
    return subprocess.check_output(
        ["git", "-C", str(cwd), *args], text=True
    ).strip()

def check_historical(root, json_path):
    actual = git(root, "rev-parse", "refs/remotes/origin/seventeen")
    need(actual == ORIGINAL_COMMIT, f"historical branch moved: {actual}")
    need(git(root, "rev-parse", f"{ORIGINAL_COMMIT}^{{tree}}") == ORIGINAL_TREE,
         "archived tree drift")
    parents = git(root, "rev-list", "--parents", "-n", "1", ORIGINAL_COMMIT).split()
    need(parents == [ORIGINAL_COMMIT, ORIGINAL_PARENT], f"unexpected history: {parents}")
    changed = git(root, "diff-tree", "--no-commit-id", "--name-status", "-r",
                  ORIGINAL_COMMIT).splitlines()
    deleted = {line.partition("\t")[2] for line in changed
               if line.startswith("D\t")}
    need(len(changed) == 6 and deleted == LAST_COMMIT_REMOVED,
         f"last historical edit was not exactly six lz4 removals: {changed}")

    obj = json.loads(json_path.read_text(encoding="utf-8"))
    need(obj.get("sha") == ORIGINAL_TREE and obj.get("truncated") is False,
         "wrong/truncated GitHub tree JSON")
    entries = obj.get("tree")
    need(isinstance(entries, list) and len(entries) == COUNT_ENTRIES,
         "tree item count drift")
    files, groups = {}, {key: [0, 0, 0, 0] for key in GROUPS}
    for e in entries:
        if e.get("type") != "blob":
            need(e.get("type") == "tree", "unexpected Git object type")
            continue
        path, sha, size, mode = (e.get("path"), e.get("sha"),
                                 e.get("size"), e.get("mode"))
        need(isinstance(path, str) and path not in files, "invalid/duplicate path")
        need(type(size) is int and size >= 0, f"bad blob length: {path}")
        need(mode in ("100644", "100755", "120000"), f"unsafe mode: {path}")
        prefix = "/".join(path.split("/")[:2])
        need(prefix in groups, f"new/unreviewed host payload directory: {path}")
        groups[prefix][0] += 1
        groups[prefix][1] += size
        groups[prefix][2] += mode == "100755"
        groups[prefix][3] += mode == "120000"
        files[path] = (mode, sha, size)
    need(len(files) == COUNT_BLOBS, f"file count drift: {len(files)}")
    need(sum(f[2] for f in files.values()) == BYTES, "byte inventory drift")
    need({k: tuple(v) for k, v in groups.items()} == GROUPS,
         f"host architecture inventory changed: {groups}")
    for name, expected in KEY_FILES.items():
        need(name in files and files[name][:2] == expected,
             f"critical old host tool / symlink changed: {name}")
    symlinks = {p for p, record in files.items() if record[0] == "120000"}
    need(symlinks == {"linux-x86/bin/nproc", "darwin-x86/bin/nproc"},
         f"unexpected symlinks: {symlinks}")
    need(not any(p.endswith(("Android.mk", "Android.bp", "BUILD.bazel"))
                 for p in files), "old bundle unexpectedly contains Android build modules")
    print("PASS: historical PE 2022 tree immutable; last change removed six lz4 binaries")
    print("PASS: 557 historical blobs / 17,613,535 bytes and all six host groups")
    print("PASS: 12 critical file SHAs and exact two symlink records")

def check_android17(manifest):
    ref = ET.parse(manifest / "aosp17_reference.xml").getroot()
    default = ref.find("default")
    need(default is not None and
         default.get("revision") == "refs/tags/android-17.0.0_r1" and
         default.get("remote") == "aosp", "not official Android17 r1 reference")
    owners = {p.get("path") or p.get("name"): p.get("name")
              for p in ref.findall("project")}
    need("prebuilts/tools-custom" not in owners,
         "unreviewed legacy PE host path imported")
    for path, upstream in {
        "prebuilts/build-tools": "platform/prebuilts/build-tools",
        "prebuilts/tools": "platform/prebuilts/tools",
        "prebuilts/clang/host/linux-x86":
            "platform/prebuilts/clang/host/linux-x86",
        "system/tools/mkbootimg": "platform/system/tools/mkbootimg",
    }.items():
        need(owners.get(path) == upstream,
             f"official Android17 owner changed: {path}")
    subprocess.run([sys.executable,
                    str(manifest / "tools/validate_aosp17_base_profiles.py")],
                   cwd=manifest, check=True)
    entry = ET.parse(manifest / "default.xml").getroot()
    need(len(entry) == 1 and entry[0].tag == "include" and
         entry[0].get("name") == "aosp17_pe_p2_kernel_configs.xml",
         "last reviewed manifest stage changed; re-audit required")
    print("PASS: AOSP17 source-only graph excludes legacy custom host tools")
    print("PASS: official build/clang/mkbootimg owners retained")

def main():
    need(len(sys.argv) == 4,
         "usage: check_tools_custom_source.py PE_ROOT GITHUB_TREE_JSON MANIFEST_ROOT")
    legacy, treefile, manifest = [Path(x).resolve() for x in sys.argv[1:]]
    need(legacy.is_dir() and treefile.is_file() and manifest.is_dir(),
         "missing source tree metadata or AOSP17 manifest checkout")
    check_historical(legacy, treefile)
    check_android17(manifest)
    print("PASS: prebuilts/tools-custom metadata-only audit")
    print("NOT TESTED: old binaries, host ABI, extraction, kernel, Soong or mondrian boot")

if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, json.JSONDecodeError,
            ValueError, subprocess.CalledProcessError, ET.ParseError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
