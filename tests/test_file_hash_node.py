import os
import pytest
from file_hash_node import FileHashNode

def test_compute_hash(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello world")
    node = FileHashNode()
    hash_val = node.compute_hash(str(test_file), algorithm="sha256")
    assert isinstance(hash_val, str)
    assert len(hash_val) == 64  # sha256 hex length 