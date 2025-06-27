import json
from vuln_scan_node import VulnScanNode

def test_vuln_scan(tmp_path):
    cve_db = {
        "openssl": [
            {"cve_id": "CVE-2020-1234", "vulnerable_versions": ["1.0.2"], "description": "Test vuln"}
        ]
    }
    cve_db_path = tmp_path / "cve_db.json"
    with open(cve_db_path, "w") as f:
        json.dump(cve_db, f)
    node = VulnScanNode()
    vulns = node.scan_software([{"name": "openssl", "version": "1.0.2"}], str(cve_db_path))
    assert vulns
    assert vulns[0]["cve"] == "CVE-2020-1234" 