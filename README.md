# flutter2frida

Generate a Frida script to bypass Flutter TLS/SSL certificate verification.

Supports **ARM64** and **x86_64** (Android emulators) targets.

Forked and extended from [aancw/flutter2frida](https://github.com/aancw/flutter2frida).

## What it does

1. Extracts the Flutter snapshot hash from `libapp.so`
2. Maps it to the Flutter version via [reFlutter's enginehash.csv](https://github.com/Impact-I/reFlutter)
3. Fetches the BoringSSL source and locates the `OPENSSL_PUT_ERROR` line in `ssl_crypto_x509_session_verify_cert_chain`
4. Disassembles `libflutter.so` (ARM64 or x86_64) to find the function at that line
5. Outputs a ready-to-use Frida `.js` script

## Requirements

```
pip install lief capstone
```

## Usage

```bash
# From APK (arch auto-detected from ELF header)
python flutter2frida.py app.apk

# Force x86_64 (Android emulators)
python flutter2frida.py app.apk --arch x86_64 -o bypass.js

# From extracted directory
python flutter2frida.py path/to/extracted/

# From individual .so files
python flutter2frida.py --libapp libapp.so --libflutter libflutter.so --arch x86_64

# Use local enginehash.csv (avoids network fetch)
python flutter2frida.py app.apk -e enginehash.csv
```

## Attaching with Frida

```bash
# USB device
frida -U -n <process_name> -l bypass.js

# Remote host (emulator with forwarded port)
frida -H 127.0.0.1:27042 -n <process_name> -l bypass.js
```

## Options

| Flag                         | Description                                                |
| ---------------------------- | ---------------------------------------------------------- |
| `--arch auto\|arm64\|x86_64` | Force architecture (default: auto-detect from ELF)         |
| `-o FILE`                    | Output script filename (default: `disable-flutter-tls.js`) |
| `-e FILE`                    | Local `enginehash.csv` to skip network fetch               |
| `-q`                         | Quiet / compact output                                     |

## Differences from upstream

- **x86_64 support** — added Capstone x86-64 disassembly, x86_64-aware prologue detection, and `rdi`-based linker hook for Android x86_64 emulators
- **Arch auto-detect** — reads ELF machine type via LIEF; `--arch` overrides
- **APK tempdir fix** — analysis runs inside the temp context so extracted files are valid during processing
- **Frida template** — updated usage to `-H <host>` attach style alongside `-U` spawn

## If your Flutter version isn't found

The enginehash.csv is pulled from reFlutter at runtime. If your version is too new or not indexed:

```bash
git clone https://github.com/Impact-I/reFlutter
cd reFlutter/scripts
python gen_enginehash.py   # regenerates the CSV
python flutter2frida.py app.apk -e reFlutter/enginehash.csv
```

## Credits

- [aancw/flutter2frida](https://github.com/aancw/flutter2frida) — original tool
- [Impact-I/reFlutter](https://github.com/Impact-I/reFlutter) — enginehash.csv and snapshot hash technique
- [LIEF](https://github.com/lief-project/LIEF) — ELF parsing
- [Capstone](https://github.com/capstone-engine/capstone) — disassembly

## Disclaimer

For authorized security testing, bug bounty programs, CTF challenges, and security research only.
