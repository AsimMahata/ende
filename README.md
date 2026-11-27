# ende

> **High-Security File Encryption & Decryption CLI**  
> **Format:** `.ende`  

`ende` is a modern, fast, and cryptographically sound CLI application that converts any file into an authenticated encrypted `.ende` container and seamlessly decrypts it back to its original state.

---

## 🔒 Security Highlights

- **Authenticated Encryption:** AES-256-GCM with 96-bit unique nonces. Any tampering or corrupted byte immediately fails authentication before writing data.
- **Key Derivation:** PBKDF2-HMAC-SHA256 with 200,000 iterations and 128-bit random cryptographic salts.
- **Double Encryption (`--r`):** Two independent layers of AES-256-GCM encryption with separate salts, nonces, and passwords.
- **Data Integrity:** Embeds and verifies SHA-256 checksums to ensure decrypted files match the original bit-for-bit.
- **Secure File Shredding (`--shred`):** Overwrites files with random data and zeros before unlinking to prevent disk forensics recovery.
- **Audit History:** Automatically records an operation log in `~/.ende/history.json`.

---

## 🚀 Installation

### 1. Create and Activate Virtual Environment
```bash
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate
```

### 2. Install ende
```bash
pip install -e .
```
Now `ende` is available anywhere in your active environment as a system command!

---

## 📖 Usage & Features

### 1. Simple Encryption
To encrypt any file, simply pass it to `ende`. It will prompt you for a password (with confirmation) and create `filename.ende`:
```bash
ende document.pdf
# Output: document.pdf.ende
```

### 2. Intuitive Decryption
To decrypt, simply pass the `.ende` file. `ende` auto-detects that it's an encrypted container, prompts for the password, and recreates the original file with its original name and integrity verified:
```bash
ende document.pdf.ende
# Output: document.pdf (restored!)
```

### 3. Double Encryption (`--r`)
Apply double encryption (two layers of AES-256-GCM):

- **On a raw file:**
  ```bash
  ende secret.txt --r
  ```
  Prompts for Layer 1 password, then Layer 2 password.

- **On an existing `.ende` file:**
  ```bash
  ende secret.txt.ende --r
  ```
  Adds a second layer of encryption on top of the `.ende` container.

- **Decrypting a double-encrypted file:**
  ```bash
  ende secret.txt.ende
  ```
  `ende` automatically detects that the file is double-encrypted and prompts for the Layer 2 (Outer) password and Layer 1 (Inner) password to recreate the original file!

### 4. Audit History (`history`)
Track all encryption and decryption operations:
```bash
ende history
```
Output:
```
============================== ENDE HISTORY LOG ==============================
Total records: 3  |  Log: ~/.ende/history.json
+----+---------------------+----------------+--------------------+--------------------+--------+---------+
| ID | Timestamp           | Action         | Source             | Target             | Layers | Status  |
+----+---------------------+----------------+--------------------+--------------------+--------+---------+
| 1  | 2026-11-27 11:20:01 | ENCRYPT        | document.pdf       | document.pdf.ende  | 1      | SUCCESS |
| 2  | 2026-11-27 11:21:15 | DOUBLE_ENCRYPT | secret.txt         | secret.txt.ende    | 2      | SUCCESS |
| 3  | 2026-11-27 11:22:40 | DECRYPT        | secret.txt.ende    | secret.txt         | 2      | SUCCESS |
+----+---------------------+----------------+--------------------+--------------------+--------+---------+
```

To clear history:
```bash
ende history --clear
```

### 5. Inspect Container Info (`info`)
View header, version, and security properties without decrypting:
```bash
ende info secret.txt.ende
```

### 6. Secure Shredding (`--shred`)
Encrypt a sensitive file and securely overwrite/wipe the plaintext original:
```bash
ende financial_records.xlsx --shred
```

---

## 🛠 Command Reference

| Command / Flag | Description |
|---|---|
| `ende <file>` | Auto-detects: encrypts regular file or decrypts `.ende` file |
| `ende <file> --r` | Double encryption (2 layers) |
| `ende <file.ende> --r` | Wrap existing `.ende` file in second encryption layer |
| `ende history` | View operation history log |
| `ende history --clear` | Clear the history log |
| `ende info <file.ende>` | Inspect container metadata |
| `-o, --output <path>` | Specify custom output path |
| `-p, --password <pwd>` | Provide primary password via CLI |
| `--p2 <pwd>` | Provide secondary password for double encryption |
| `-s, --shred` | Securely wipe original file after operation |
| `-f, --force` | Overwrite destination file without confirmation |
| `--no-compress` | Disable zlib compression before encryption |
| `-v, --version` | Display version number |
