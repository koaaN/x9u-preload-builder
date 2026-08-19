# X9 Ultra preload.so builder

Builds the CVE-2026-43499 arm64 `preload.so` from a matching X9 Ultra
`boot.img` and `xbl_config.img`.

The firmware images are used locally to recover build-specific kernel symbols,
BTF structure offsets, the futex/`pselect` stack layout, and the physical load
profile. They are never copied into the output or repository.

## Requirements

- Python 3.10 or newer
- GNU Make
- Android NDK r27 or newer
- Matching `boot.img` and `xbl_config.img` from the same firmware release

No `kallsyms` dump is required for the build.

## One-command build

Clone the repository and run:

```sh
python3 build.py \
  --boot /path/to/boot.img \
  --xbl-config /path/to/xbl_config.img \
  --ndk-root /path/to/android-ndk
```

Output:

```text
out/preload.so
```

The builder automatically selects the NDK's arm64 API-35 compiler and
`llvm-objdump`, regenerates `source/src/target.h`, cleans the previous build,
and prints the final SHA-256 digest.

### Windows

Use Python and GNU Make from Git for Windows, MSYS2, or a similar environment:

```powershell
py -3 build.py `
  --boot "C:\firmware\boot.img" `
  --xbl-config "C:\firmware\xbl_config.img" `
  --ndk-root "C:\Users\YOU\AppData\Local\Android\Sdk\ndk\27.2.12479018"
```

If GNU Make has a different name, add `--make mingw32-make` or its full path.

## Manual build

Generate the target header:

```sh
python3 generate_target.py \
  --boot /path/to/boot.img \
  --xbl-config /path/to/xbl_config.img \
  --llvm-objdump "$NDK_TOOLCHAIN/bin/llvm-objdump" \
  -o source/src/target.h
```

Then compile:

```sh
make -C source clean preload \
  NDK_ROOT=/path/to/android-ndk \
  NDK_TOOLCHAIN=/path/to/android-ndk/toolchains/llvm/prebuilt/linux-x86_64
```

The manual Make output is `source/build/bin/preload.so`.

## Important

Offsets are firmware-build-specific. Always regenerate and rebuild with the
`boot.img` and `xbl_config.img` from the exact OTA installed on the device.
Using mismatched images can panic the kernel.

For authorized security research on devices you own. Kernel exploitation can
crash or reboot the device; keep the matching firmware available for recovery.
