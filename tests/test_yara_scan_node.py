import os
import pytest
from yara_scan_node import YARAScanNode

def test_yara_scan(tmp_path):
    test_file = tmp_path / "malware.txt"
    test_file.write_text("evilpattern")
    rules_file = tmp_path / "rules.yar"
    rules_file.write_text('rule Malicious { strings: $a = "evilpattern" condition: $a }')
    node = YARAScanNode()
    matches = node.scan_file(str(test_file), str(rules_file))
    assert "Malicious" in matches 