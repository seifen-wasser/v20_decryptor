# v20_decryptor

<sup><sub><sup>`Chromium Browser Credential & Cookie Extractor`</sup></sub></sup>

![Rust](https://img.shields.io/badge/Rust-000000?style=flat&logo=rust&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 🔎 Overview

**v20_decryptor** is a Rust-based tool for extracting and decrypting saved credentials and cookies from Chromium-based browsers on Windows. It targets the `v10`/`v20` AES-256-GCM encryption scheme used by modern Chromium builds, unwrapping the master key via Windows DPAPI (`CryptUnprotectData`) and decrypting stored blobs in-place.

Built for speed and correctness — no Python runtime, no external DLLs, single static binary.

---

## 🧱 Core Technical Pillars

- **DPAPI Master Key Extraction** — Reads `Local State`, base64-decodes the `encrypted_key` field, strips the `DPAPI` prefix, and calls `CryptUnprotectData` to recover the AES-256 master key.
- **AES-256-GCM Decryption** — Handles both `v10` and `v20` encrypted blobs: 12-byte nonce at offset `[3..15]`, ciphertext from offset `[15..]`, decrypted with the extracted master key.
- **DPAPI Fallback** — Blobs without a `v10`/`v20` prefix are passed directly to `CryptUnprotectData` for legacy decryption.
- **Safe Database Access** — Copies locked SQLite databases to `%TEMP%` before reading, avoiding conflicts with running browser processes.

---

## ⚙️ Features

### 🔓 Core Functionality

- 🍪 **Cookie Extraction** — Decrypts all cookies from each browser profile, including host, name, value, path, expiry, and security flags.
- 🔑 **Login Extraction** — Decrypts saved usernames and passwords from `Login Data` databases.
- 🗂️ **Multi-Profile Support** — Automatically discovers and iterates `Default` and all `Profile N` directories.

### 🛡️ Stealth & Safety

- 📋 **Copy-on-Read** — Never touches the original database files; works on temporary copies.
- 🧹 **Auto-Cleanup** — Temporary database copies are deleted after extraction.
- ⚠️ **ABE Detection** — Warns when `app_bound_encrypted_key` is present (requires browser COM elevation to unwrap).

### 🌐 Supported Browsers

| Browser | Subpath |
|---------|---------|
| **Chrome** | `Google/Chrome/User Data` |
| **Edge** | `Microsoft/Edge/User Data` |
| **Brave** | `BraveSoftware/Brave-Browser/User Data` |
| **Opera** | `Opera Software/Opera Stable` |

> **Note:** Additional Chromium-based browsers can be added by extending the `BROWSERS` array in `main.rs`.

---

## 🔧 Technical Workflow

### Stage 1: Key Recovery

1. Locate `%LOCALAPPDATA%\<browser>\User Data\Local State`
2. Parse JSON → extract `os_crypt.encrypted_key`
3. Base64-decode → strip `DPAPI` (5-byte) prefix
4. Call `CryptUnprotectData` → recover 32-byte AES-256 master key

### Stage 2: Profile Discovery

1. Scan `User Data` for `Default/` and `Profile */` directories
2. Build a list of `(profile_name, profile_path)` pairs

### Stage 3: Credential Extraction

1. Copy `Cookies` (from `Network/` subfolder) and `Login Data` to `%TEMP%`
2. Open each copy with `rusqlite`
3. For each encrypted blob:
   - `v10`/`v20` prefix → AES-256-GCM decrypt with master key
   - No prefix → DPAPI fallback
4. Delete temporary copies

### Stage 4: Output

1. Write `cookies.txt` and `passwords.json` per profile under `./output/<Browser>/<Profile>/`

---

## 🚀 Build & Usage

### Prerequisites

- **Rust** (edition 2024) — install via [rustup.rs](https://rustup.rs/)
- **Windows** — requires Win32 DPAPI (not cross-compilable for use on Linux/macOS)

### Build

```bash
cargo build --release
```

The binary will be at `target/release/v20_decryptor.exe`.

### Run

```bash
.\v20_decryptor.exe
```

### Example Output

```
[*] Chrome - C:\Users\user\AppData\Local\Google\Chrome\User Data
  [+] Key: 4a6f686e...
  [+] Default
      142 cookies, 7 logins
  [+] Profile 1
      89 cookies, 3 logins
[*] Edge - C:\Users\user\AppData\Local\Microsoft\Edge\User Data
  [+] Key: 536d6974...
  [+] Default
      61 cookies, 2 logins
```

### Output Structure

```
output/
├── Chrome/
│   ├── Default/
│   │   ├── cookies.txt
│   │   └── passwords.json
│   └── Profile 1/
│       ├── cookies.txt
│       └── passwords.json
└── Edge/
    └── Default/
        ├── cookies.txt
        └── passwords.json
```

### Output Formats

🍪 **cookies.txt**

```
Host: .example.com
Name: session_id
Value: abc123
Path: /
IsSecure: true
HttpOnly: true
Expires: 13370000000000000
```

🔑 **passwords.json**

```json
[
  {
    "url": "https://example.com/login",
    "username": "user@example.com",
    "password": "••••••••"
  }
]
```

---

## 📦 Dependencies

| Crate | Purpose |
|-------|---------|
| `rusqlite` | SQLite database access (bundled) |
| `aes-gcm` | AES-256-GCM decryption |
| `base64` | Base64 decoding of encrypted keys |
| `serde` / `serde_json` | JSON parsing and serialization |
| `windows` | Win32 DPAPI + memory management |

---

## ⚠️ Disclaimer

> [!IMPORTANT]
> This tool is provided for **educational and authorized security research purposes only**.

**v20_decryptor is intended to demonstrate how Chromium stores and protects user credentials on Windows.** Use of this tool against systems or accounts you do not own or have explicit written authorization to test is illegal and unethical. The author assumes no liability for misuse. Always comply with applicable local, state, and federal laws.

---

## 📄 License

This project is licensed under the MIT License.
