# flutter2frida

Generate a Frida script to bypass Flutter TLS/SSL certificate verification, with full proxy interception support for mitmproxy.

Supports **ARM64** and **x86_64** (Android emulators) targets.

Forked and extended from [aancw/flutter2frida](https://github.com/aancw/flutter2frida).

## What it does

1. Extracts the Flutter snapshot hash from `libapp.so`
2. Maps it to the Flutter version via [reFlutter's enginehash.csv](https://github.com/Impact-I/reFlutter)
3. Fetches the BoringSSL source and locates the `OPENSSL_PUT_ERROR` line in `ssl_crypto_x509_session_verify_cert_chain`
4. Disassembles `libflutter.so` (ARM64 or x86_64) to find the function at that line
5. Outputs a ready-to-use Frida `.js` script that patches the return value to always succeed

Optionally generates `config.js` for [native-connect-hook.js](#flutter-ignores-the-system-proxy) to redirect Flutter traffic to mitmproxy at the socket level.

## Requirements

```
pip install lief capstone
```

## Usage

```bash
# From APK (arch auto-detected from ELF header)
python flutter2frida.py app.apk

# Force x86_64 (Android emulators)
python flutter2frida.py app.apk --arch x86_64

# Generate config.js for proxy interception alongside the TLS bypass script
python flutter2frida.py app.apk --proxy 192.168.1.10:8080

# Custom CA cert (default: ~/.mitmproxy/mitmproxy-ca-cert.pem)
python flutter2frida.py app.apk --proxy 192.168.1.10:8080 --cert /path/to/ca.pem

# From extracted directory or individual .so files
python flutter2frida.py path/to/extracted/
python flutter2frida.py --libapp libapp.so --libflutter libflutter.so --arch x86_64

# Use local enginehash.csv (avoids network fetch)
python flutter2frida.py app.apk -e enginehash.csv
```

## Options

| Flag                         | Description                                                       |
| ---------------------------- | ----------------------------------------------------------------- |
| `--arch auto\|arm64\|x86_64` | Force architecture (default: auto-detect from ELF)                |
| `-o FILE`                    | Output script filename (default: `disable-flutter-tls.js`)        |
| `--proxy HOST:PORT`, `-p`    | Proxy address; generates `config.js` for native-connect-hook      |
| `--cert PEM`                 | CA cert PEM file for `config.js` (default: `~/.mitmproxy/...pem`) |
| `-e FILE`                    | Local `enginehash.csv` to skip network fetch                      |
| `-q`                         | Quiet / compact output                                            |

## Full intercept workflow

Flutter's Dart VM ignores the Android system HTTP proxy setting, so simply pointing the device proxy at mitmproxy is not enough — the traffic never arrives. The solution is to redirect at the libc socket level using `native-connect-hook.js` (from [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)).

### Step 1 — generate the scripts

```bash
python flutter2frida.py app.apk --proxy 192.168.1.10:8080
```

This produces:

- `disable-flutter-tls.js` — patches `ssl_crypto_x509_session_verify_cert_chain` to always return success
- `config.js` — proxy address + CA cert, consumed by `native-connect-hook.js`

### Step 2 — start mitmproxy

```bash
mitmweb -s your_dump_addon.py
```

### Step 3 — spawn the app with all three scripts

```bash
# Spawn (recommended — catches all connections from startup)
frida -H 127.0.0.1:27042 -f com.example.app \
    -l config.js -l native-connect-hook.js -l disable-flutter-tls.js

# Attach to already-running process
frida -H 127.0.0.1:27042 -n com.example.app \
    -l config.js -l native-connect-hook.js -l disable-flutter-tls.js
```

Expected output on success:

```
[+] native-connect-hook: redirecting all TCP -> 192.168.1.10:8080
[+] libflutter.so @ 0x7baf9fc27000
Intercepting tcp -> 203.0.113.5:443
[+] session_verify_cert_chain -> 0x1
```

### TLS bypass only (no proxy needed)

If you only need to disable certificate verification without capturing traffic:

```bash
frida -H 127.0.0.1:27042 -f com.example.app -l disable-flutter-tls.js
```

## Flutter ignores the system proxy

Flutter uses its own Dart networking stack and deliberately ignores `android.net.Proxy` / `http_proxy` system settings. Two approaches work:

| Approach                             | How                                                                       |
| ------------------------------------ | ------------------------------------------------------------------------- |
| `native-connect-hook.js` (this tool) | Hooks libc `connect()` — redirects all TCP before Flutter's stack sees it |
| WireGuard / transparent routing      | Redirects at the network level, no Frida needed for routing               |

`config.js` is gitignored because it contains your CA certificate and private proxy address.

## x86_64 offset finding

x86_64 uses variable-width instructions, making backward disassembly unreliable. This tool uses a forward scan approach:

1. Single pass through `.text` tracking `ret` boundaries to build a function-start list
2. `bisect` lookup to find the enclosing function for each `MOV imm=<line>` candidate
3. Capstone `detail=True` with exact `X86_OP_IMM` matching — eliminates false positives from hex substrings (e.g. `0x6fe362` matching `"362"`)

## Differences from upstream

- **x86_64 support** — Capstone x86-64 disassembly, ret-based forward-scan prologue detection, `rdi`-based linker hook
- **Proxy interception** — `--proxy` flag generates `config.js`; bundled `native-connect-hook.js` redirects Flutter traffic at socket level
- **Arch auto-detect** — reads ELF machine type via LIEF; `--arch` overrides
- **APK tempdir fix** — analysis runs inside the temp context so extracted files remain valid
- **Frida template** — `-H <host>` attach style; both spawn and attach modes documented

## If your Flutter version isn't found

The enginehash.csv is pulled from reFlutter at runtime. If your version is too new:

```bash
git clone https://github.com/Impact-I/reFlutter
python reFlutter/scripts/gen_enginehash.py
python flutter2frida.py app.apk -e reFlutter/enginehash.csv
```

## Credits

- [aancw/flutter2frida](https://github.com/aancw/flutter2frida) — original tool
- [httptoolkit/frida-interception-and-unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning) — `native-connect-hook.js`
- [Impact-I/reFlutter](https://github.com/Impact-I/reFlutter) — enginehash.csv and snapshot hash technique
- [LIEF](https://github.com/lief-project/LIEF) — ELF parsing
- [Capstone](https://github.com/capstone-engine/capstone) — disassembly

## Disclaimer

For authorized security testing, bug bounty programs, CTF challenges, and security research only.
