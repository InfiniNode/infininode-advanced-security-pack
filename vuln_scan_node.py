"""
VulnScanNode: Scans for known vulnerable software versions using an offline CVE database.
Author: Azazeal (Azazeal04)

Example usage:
    node = VulnScanNode()
    vulns = node.scan_software([{'name': 'openssl', 'version': '1.0.2'}], 'cve_db.json')
"""

import json

class VulnScanNode:
    RETURN_TYPES = ("LIST",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "software_list": ("LIST", {"default": []}),
                "cve_db_path": ("STRING", {"default": ""}),
            },
            "optional": {}
        }

    def __init__(self):
        pass

    def scan_software(self, software_list, cve_db_path):
        """
        Scan the provided software list against the offline CVE database.
        software_list: list of dicts with 'name' and 'version'
        cve_db_path: path to JSON file with CVE data
        Returns a list of vulnerabilities found.
        """
        if not cve_db_path:
            raise ValueError("cve_db_path must be provided and not empty")
        with open(cve_db_path, 'r') as f:
            cve_db = json.load(f)
        vulns = []
        for sw in software_list:
            name = sw['name'].lower()
            version = sw['version']
            for cve in cve_db.get(name, []):
                if version in cve['vulnerable_versions']:
                    vulns.append({'software': name, 'version': version, 'cve': cve['cve_id'], 'desc': cve['description']})
        return vulns 