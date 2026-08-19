#!/usr/bin/env python3
"""Generate target.h and build preload.so from matching firmware images."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
TARGET = ROOT / "source" / "src" / "target.h"
BUILT_PRELOAD = ROOT / "source" / "build" / "bin" / "preload.so"
FINAL_PRELOAD = ROOT / "out" / "preload.so"


def regular_file(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file() or path.is_symlink():
        raise argparse.ArgumentTypeError(f"not a regular file: {path}")
    return path


def directory(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"not a directory: {path}")
    return path


def select_toolchain(ndk_root: Path, api: int) -> tuple[Path, Path]:
    prebuilt_root = ndk_root / "toolchains" / "llvm" / "prebuilt"
    if not prebuilt_root.is_dir():
        raise SystemExit(f"invalid Android NDK: missing {prebuilt_root}")

    preferred: list[str]
    if os.name == "nt":
        preferred = ["windows-x86_64"]
    elif sys.platform == "darwin":
        preferred = ["darwin-x86_64", "darwin-arm64"]
    else:
        preferred = ["linux-x86_64"]

    candidates = [prebuilt_root / name for name in preferred]
    candidates.extend(sorted(path for path in prebuilt_root.iterdir()
                             if path.is_dir() and path not in candidates))

    clang_names = [
        f"aarch64-linux-android{api}-clang",
        f"aarch64-linux-android{api}-clang.cmd",
        f"aarch64-linux-android{api}-clang.exe",
    ]
    objdump_names = ["llvm-objdump", "llvm-objdump.exe"]
    for toolchain in candidates:
        clang = next((toolchain / "bin" / name for name in clang_names
                      if (toolchain / "bin" / name).is_file()), None)
        objdump = next((toolchain / "bin" / name for name in objdump_names
                        if (toolchain / "bin" / name).is_file()), None)
        if clang and objdump:
            return clang, objdump
    raise SystemExit(
        f"no usable API {api} arm64 clang/llvm-objdump under {prebuilt_root}"
    )


def run(command: list[str], *, cwd: Path = ROOT) -> None:
    print("+", subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the X9 Ultra preload.so from matching firmware"
    )
    parser.add_argument("--boot", required=True, type=regular_file,
                        help="matching Android boot.img")
    parser.add_argument("--xbl-config", required=True, type=regular_file,
                        help="matching xbl_config.img")
    parser.add_argument("--ndk-root", required=True, type=directory,
                        help="Android NDK r27 or newer")
    parser.add_argument("--api", type=int, default=35,
                        help="Android API used for compilation (default: 35)")
    parser.add_argument("--llvm-objdump", type=regular_file,
                        help="override llvm-objdump; defaults to the NDK copy")
    parser.add_argument("--make", default="make",
                        help="GNU make executable (default: make)")
    return parser


def main() -> int:
    args = make_parser().parse_args()
    clang, ndk_objdump = select_toolchain(args.ndk_root, args.api)
    objdump = args.llvm_objdump or ndk_objdump

    run([
        sys.executable,
        str(ROOT / "generate_target.py"),
        "--boot", str(args.boot),
        "--xbl-config", str(args.xbl_config),
        "--llvm-objdump", str(objdump),
        "-o", str(TARGET),
    ])
    run([
        args.make,
        "-C", str(ROOT / "source"),
        "clean", "preload",
        f"API={args.api}",
        f"NDK_ROOT={args.ndk_root}",
        f"NDK_TOOLCHAIN={clang.parent.parent}",
        f"TARGET_CC={clang}",
    ])

    FINAL_PRELOAD.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(BUILT_PRELOAD, FINAL_PRELOAD)
    print(f"\nBuilt: {FINAL_PRELOAD}")
    print(f"SHA-256: {sha256(FINAL_PRELOAD)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
