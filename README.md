# Firmware Encryption Analyser

A self-contained desktop tool for identifying encryption and obfuscation in firmware binaries, designed to support security reviews and penetration testing engagements.

Drop a firmware file onto it and get an instant report covering entropy analysis, XOR key candidates, magic byte signatures, and printable string extraction — with one-click decryption where a key can be recovered.

![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat)
![License](https://img.shields.io/badge/license-MIT-green?style=flat)

---

## Screenshots

```
┌─────────────────────────────────────────────────────────────┐
│  FA  Firmware Encryption Analyser                           │
│      Entropy · XOR detection · Magic bytes · Strings        │
├─────────────────────────────────────────────────────────────┤
│  [ Drop firmware file here — .bin .img .fw .hex .rom ]      │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ File size    │ Entropy      │ High-entropy │ XOR candidates │
│ 512.0 KB     │ 7.81  ████  │ blocks: 14   │ 3              │
├─────────────────────────────────────────────────────────────┤
│ FINDINGS  │ ENTROPY MAP  │ HEX DUMP  │ STRINGS           │
│                                                             │
│ [HIGH] Very high entropy detected                           │
│        7.814 bits/byte — consistent with AES-CBC/CTR...    │
│                                                             │
│ [HIGH] XOR key candidate: 0x42                             │
│        Single-byte XOR yields 71.3% printable output       │
│                                                             │
│ [MED]  Crypto-related strings in binary                    │
│        AES_KEY · encrypt · iv_salt · pkcs7pad              │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

### Detection

| Check | Description |
|---|---|
| **Shannon entropy** | Global score + per-256-byte block map. Values above 7.2 bits/byte indicate encryption or strong compression |
| **Magic byte signatures** | 16 file format signatures: ELF, gzip, bzip2, XZ, U-Boot uImage, SquashFS, ZIP, RAR, PE, Mach-O, DER, PEM, OLE2 |
| **Single-byte XOR** | Brute-forces all 256 key values, ranks candidates by printable output ratio |
| **Rolling XOR** | Tests multi-byte repeating keys (lengths 2–8) |
| **Crypto string extraction** | Finds strings referencing `aes`, `des`, `rsa`, `cipher`, `iv`, `salt`, `hmac`, `sha`, `pkcs`, `crypt` |
| **Null-byte padding** | Detects ECB-mode padding regions and uninitialised key storage patterns |
| **High-byte density** | Flags headers with >75% bytes above 0x7F, indicating byte-substitution ciphers |
| **U-Boot header parsing** | Extracts image name, OS type, compression method, and payload size from uImage headers |

### Output tabs

- **Findings** — severity-ranked list (HIGH / MED / LOW / INFO) with plain-English explanations
- **Entropy map** — colour-coded bar chart per 256-byte block (green < 6.0, amber 6–7.2, red > 7.2)
- **Hex dump** — first 512 bytes rendered as offset + hex + ASCII
- **Strings** — all printable runs of 4+ characters extracted from the full binary

### Actions

- **XOR decrypt + save** — applies the top-ranked XOR key to the full file and downloads the result
- **Export strings** — saves all extracted strings to a `.txt` file
- No data leaves the machine — analysis runs entirely locally

---

## Getting Started

### Download (no install required)

Grab the latest release from the [Releases](../../releases) page:

| Platform | File |
|---|---|
| Windows 64-bit | `firmware-analyser-windows-amd64.exe` |
| Linux 64-bit | `firmware-analyser-linux-amd64` |
| macOS (Apple Silicon) | `firmware-analyser-darwin-arm64` |
| macOS (Intel) | `firmware-analyser-darwin-amd64` |

**Windows:** Double-click the `.exe`. A terminal window opens briefly, then your browser launches automatically.

**Linux / macOS:**
```bash
chmod +x firmware-analyser-linux-amd64
./firmware-analyser-linux-amd64
```

If the browser does not open automatically, copy the `http://127.0.0.1:<port>` URL printed in the terminal into any browser.

---

## Building from Source

### Requirements

- Go 1.22 or later — [download](https://go.dev/dl/)
- No external dependencies — the standard library is sufficient

### Build for your current platform

```bash
git clone https://github.com/your-org/firmware-analyser.git
cd firmware-analyser
go build -o firmware-analyser .
```

### Cross-compile for all platforms

```bash
make all
```

Or manually:

```bash
# Windows 64-bit
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w -H windowsgui" -o dist/firmware-analyser-windows-amd64.exe .

# Linux 64-bit
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -o dist/firmware-analyser-linux-amd64 .

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -o dist/firmware-analyser-darwin-arm64 .

# macOS Intel
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -o dist/firmware-analyser-darwin-amd64 .
```

---

## How It Works

The binary embeds a complete web application and HTTP server. On launch it:

1. Binds to a random free port on `127.0.0.1`
2. Opens the system default browser at that address
3. Serves the analysis UI from memory (no files written to disk)
4. Accepts firmware uploads via `multipart/form-data` POST to `/analyse`
5. Returns JSON analysis results; the UI renders them client-side
6. Serves decrypted files and string exports as HTTP downloads

All processing happens in the Go backend — entropy calculation, XOR brute-force, magic byte matching, and string extraction. The frontend is plain HTML/CSS/JS with no external dependencies.

Port binding is `127.0.0.1` only — the tool is not accessible from other machines on the network.

---

## Interpreting Results

### Entropy score guide

| Range | Likely cause |
|---|---|
| < 5.0 | Plaintext, structured binary (e.g. uncompressed filesystem) |
| 5.0 – 6.5 | Mixed binary — partially structured, possibly compressed sections |
| 6.5 – 7.2 | Compressed data (gzip, LZMA) or XOR-obfuscated content |
| > 7.2 | Strong encryption (AES, ChaCha20) or heavily compressed (LZMA2, brotli) |

High entropy alone does not confirm encryption — check whether a compression magic signature (gzip `1f 8b`, XZ `fd 37 7a`) is also present. If both entropy > 7.2 and no compression signature: likely encrypted.

### XOR candidates

If a single-byte XOR key is suggested, the tool has found that XOR-ing the file with that byte produces > 65% ASCII printable output in a sample. This is a strong indicator of simple XOR obfuscation. Use the **Decrypt + save** button to apply it to the full file, then re-analyse the output.

### When XOR is not enough

For AES or RSA-encrypted firmware (entropy > 7.4 with no XOR candidate), the key is not recoverable from the binary alone. Next steps for the security review:

- Extract the bootloader (U-Boot, etc.) and search for key derivation routines
- Check NVRAM / flash regions for provisioned keys
- Look for key material in companion mobile apps or update servers
- Attach JTAG/UART and intercept the key at runtime

---

## Project Structure

```
firmware-analyser/
├── main.go          # All application logic (~700 lines)
│   ├── Analysis engine (entropy, XOR, magic, strings)
│   ├── HTTP handlers (/analyse, /decrypt, /strings)
│   └── Embedded HTML/CSS/JS frontend
├── go.mod           # Module definition — no external dependencies
├── Makefile         # Cross-platform build targets
├── .gitignore
└── README.md
```

---

## Limitations

- XOR detection covers single-byte and short repeating keys only. AES, 3DES, RC4 with unknown keys, and custom stream ciphers cannot be reversed by this tool
- Files larger than 64 MB may be slow to analyse depending on hardware
- The entropy block map covers the first 16 KB (64 × 256-byte blocks); for large images the tail is not charted
- Browser must support `fetch` and `FormData` (any modern browser released after 2017)

---

## Legal

This tool is intended for authorised security testing only. Use it only on firmware you own or have explicit written permission to test. The authors accept no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE)
