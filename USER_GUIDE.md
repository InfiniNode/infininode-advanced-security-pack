# InfiniNode Advanced Security Pack - User Guide

## Overview

The InfiniNode Advanced Security Pack is a **standalone security scanner** designed to automatically protect your ComfyUI environment. Unlike traditional ComfyUI node packs, this tool runs automatically at startup to scan for security threats without requiring manual workflow setup.

## Quick Start

1. **Install the security pack** in your ComfyUI custom nodes directory
2. **Restart ComfyUI** - the scanner will automatically run
3. **Check the console output** for scan results
4. **Review the audit log** at `audit.log` for detailed results

## What Happens Automatically

### Startup Scan Process

When ComfyUI starts, the security pack automatically:

1. **Discovers all Python files** in the ComfyUI custom nodes directory (including subdirectories)
2. **Performs comprehensive security analysis** on each file:
   - **File Integrity:** Computes SHA256 and SHA512 hashes
   - **Digital Signatures:** Verifies signatures if .sig and .pem files exist
   - **Malware Detection:** Scans with YARA rules from `example_rules.yar`
   - **Permission Analysis:** Checks for insecure file permissions
   - **Vulnerability Assessment:** Scans against CVE database in `example_cve_db.json`
3. **Logs all findings** to `audit.log` with tamper-evident audit chains
4. **Reports results** to the console for immediate visibility

### Example Console Output

The scanner will display scan progress and results in the console, showing file names, scan status, and any security findings.

## Automatic Node Conflict Resolution

The security pack automatically handles conflicts with existing ComfyUI nodes to ensure seamless integration:

### How It Works

1. **Conflict Detection:** During startup, the security pack scans for node name conflicts
2. **Automatic Resolution:** Conflicting nodes are automatically renamed with "InfiniNode_" prefix
3. **User Notification:** A clear notice is displayed showing which nodes were renamed
4. **Continued Operation:** All functionality remains intact with the new node names

### What You'll See

When conflicts are detected, you'll see a notice like this in the console:

```
[InfiniNode] Security Pack Notice:
  2 conflicting nodes were automatically renamed:
    • FileHashNode -> InfiniNode_FileHashNode (in file_hash_node)
    • YARAScanNode -> InfiniNode_YARAScanNode (in yara_scan_node)
  This prevents conflicts with existing ComfyUI nodes.
  Use the new names when referencing these nodes in workflows.
```

### Benefits

- **No Manual Intervention:** Conflicts are resolved automatically without user input
- **Clear Communication:** Users are informed about all changes made
- **Prevents Startup Issues:** No conflicts will break ComfyUI functionality
- **Maintains Security:** All security scanning features continue to work normally

### Using Renamed Nodes

If you need to reference any renamed nodes in custom workflows or scripts, use the new names (e.g., `InfiniNode_FileHashNode` instead of `FileHashNode`).

## Understanding Scan Results

### File Integrity Results
- **sha256/sha512:** Cryptographic hashes for file integrity verification
- **signature_valid:** True if digital signature verification passes (when .sig/.pem files exist)

### Malware Detection Results
- **yara_matches:** List of YARA rule matches (empty list = no malware detected)
- **yara_error:** Error message if YARA scanning fails

### System Security Results
- **insecure_permissions:** True if file has world-readable or world-writable permissions
- **vulns:** List of vulnerabilities found (empty list = no vulnerabilities detected)

### Error Handling
- **hash_error:** Error during file hashing
- **signature_error:** Error during signature verification
- **permissions_error:** Error during permission checking
- **vuln_error:** Error during vulnerability scanning

## Audit Log

The security pack maintains a tamper-evident audit log at `audit.log`. Each entry includes timestamp, event details, and cryptographic hashes to ensure log integrity.

### Verifying Audit Log Integrity

The audit log uses cryptographic chaining - each entry's hash depends on the previous entry's hash. This prevents tampering with historical logs.

## Configuration

### YARA Rules

The scanner uses `example_rules.yar` for malware detection. You can modify this file to add custom detection rules for your specific security requirements.

### CVE Database

The vulnerability scanner uses `example_cve_db.json`. You can update this database with current CVE information or add custom vulnerabilities for your environment.

## Troubleshooting

### Common Issues

**1. Import Errors**
If you see module import errors, install missing dependencies using the requirements file.

**2. File Permission Errors**
Ensure the security pack has read access to the files it needs to scan.

**3. YARA Rule Errors**
Check your YARA rules file for syntax errors if scanning fails.

**4. Audit Log Errors**
The audit log will be created automatically on first use.

### Performance Considerations

- **Large directories:** Scanning many files may take time
- **YARA rules:** Complex rules may slow down scanning
- **CVE database:** Large databases may increase scan time

### Security Best Practices

1. **Regular updates:** Keep YARA rules and CVE database current
2. **Monitor logs:** Regularly review audit logs for suspicious activity
3. **Backup logs:** Keep copies of audit logs for forensic analysis
4. **Custom rules:** Add rules specific to your environment and threats

## Advanced Usage

### Custom Security Rules

You can extend the security pack with custom detection logic by modifying the configuration files or adding your own security checks.

### Integration with Other Tools

The security pack can be integrated with other security tools and systems for comprehensive security monitoring.

## Support and Contributing

- **Issues:** Report bugs and feature requests on GitHub
- **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines
- **Security:** Report security vulnerabilities privately to the maintainers

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 