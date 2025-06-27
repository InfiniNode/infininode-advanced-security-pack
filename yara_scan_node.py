"""
YARAScanNode: Scans files using YARA rules for malware and suspicious patterns.
Author: Azazeal (Azazeal04)

Example usage:
    node = YARAScanNode()
    matches = node.scan_file('file.exe', 'rules.yar')
"""

import yara

class YARAScanNode:
    RETURN_TYPES = ("LIST",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "file_path": ("STRING", {"default": ""}),
                "rules_path": ("STRING", {"default": ""}),
            },
            "optional": {}
        }

    def __init__(self):
        pass

    def scan_file(self, file_path, rules_path):
        """
        Scan the file using YARA rules from the specified path.
        Returns a list of matching rule names.
        """
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(filepath=file_path)
        return [match.rule for match in matches] 