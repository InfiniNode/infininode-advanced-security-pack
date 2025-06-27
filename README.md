<p align="center">
  <img src="./icon.svg" alt="InfiniNode Pack Icon" width="128"/>
</p>

# InfiniNode Advanced Security Pack

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)

> **Part of the [InfiniNode](https://github.com/InfiniNode) suite of advanced security tools for ComfyUI.**

---

A standalone security scanner for ComfyUI environments, providing automatic offline scanning for file integrity, malware detection, vulnerability assessment, and system hardening at startup.

## Installation

1. Clone or copy this folder into your ComfyUI custom nodes directory
```bash
git clone https://github.com/InfiniNode/infininode-advanced-security-pack.git
```
2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
3. **Restart ComfyUI** - the security scanner will automatically run at startup

## What Happens at Startup

When ComfyUI starts, the security pack automatically:

1. **Scans all Python files** in the ComfyUI custom nodes directory (recursively)
2. **Performs comprehensive security checks:**
   - File integrity verification (SHA256/SHA512 hashing)
   - Digital signature verification (if .sig and .pem files exist)
   - YARA malware scanning (using `example_rules.yar`)
   - File permissions analysis
   - Vulnerability assessment (using `example_cve_db.json`)
3. **Logs all results** to `audit.log` in the security pack directory
4. **Prints scan results** to the console for immediate visibility

## Automatic Conflict Resolution

The security pack automatically detects and resolves conflicts with existing ComfyUI nodes:

- **Conflict Detection:** Identifies nodes with names that conflict with existing ComfyUI nodes
- **Automatic Renaming:** Prefixes conflicting nodes with "InfiniNode_" to prevent conflicts
- **User Notification:** Provides clear notice of which nodes were renamed and their new names
- **Seamless Integration:** No user interaction required - everything happens automatically

**Example Notice:**
```
[InfiniNode] Security Pack Notice:
  2 conflicting nodes were automatically renamed:
    • FileHashNode -> InfiniNode_FileHashNode (in file_hash_node)
    • YARAScanNode -> InfiniNode_YARAScanNode (in yara_scan_node)
  This prevents conflicts with existing ComfyUI nodes.
  Use the new names when referencing these nodes in workflows.
```

## Running Tests

To run all tests:
```sh
pip install pytest
pytest tests/
```

## Features
- **Automatic startup scanning** - no manual intervention required
- File integrity checks (multi-algorithm hashing, digital signature verification)
- Malware and anomaly scanning (YARA, heuristics, suspicious pattern detection)
- Network request filtering (domain/IP/protocol/port, DNS black/whitelists, outbound monitoring)
- System hardening (permissions check, vulnerable software scan, audit logging)
- Encryption & data protection (AES, ChaCha20, RSA, secure delete, watermarking/steganography)
- User & API security (JWT verification, rate limiting, password hashing)
- 100% offline, open-source only
- **Automatic node conflict detection and resolution**

## Logs and Output

- **Console output:** Scan results are printed to the console during startup
- **Audit log:** All scan events are logged to `audit.log` in the security pack directory
- **Scan coverage:** All Python files in the ComfyUI custom nodes directory are automatically scanned

## Security Features

### File Integrity
- Multi-algorithm hashing (SHA256, SHA512)
- Digital signature verification (RSA, ECDSA, Ed25519)
- Tamper detection and integrity validation

### Malware Detection
- YARA rule-based scanning
- Suspicious pattern detection
- Heuristic analysis of code patterns

### System Hardening
- File permissions analysis
- Vulnerability scanning against CVE database
- Audit logging with tamper-evident chains

### Network Security
- Request filtering by domain, IP, port, protocol
- DNS blacklist/whitelist support
- Outbound connection monitoring

### Data Protection
- AES, ChaCha20, and RSA encryption
- Secure file deletion with multiple overwrite passes
- Digital watermarking and steganography

### Authentication & Authorization
- JWT token verification
- Rate limiting and abuse prevention
- Secure password hashing (bcrypt, Argon2)

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions, please open an issue on GitHub or refer to the [USER_GUIDE.md](USER_GUIDE.md). 