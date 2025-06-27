"""
AuditLogNode: Logs security events in an immutable, tamper-evident way.
Author: Azazeal (Azazeal04)

Example usage:
    node = AuditLogNode('audit.log')
    node.log_event({'event': 'file_scanned', 'file': 'test.txt'})
"""

import json
import hashlib
import os
import time

class AuditLogNode:
    RETURN_TYPES = ("NONE",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "log_path": ("STRING", {"default": "audit.log"}),
                "event": ("DICT", {"default": {}}),
            },
            "optional": {}
        }

    def __init__(self, log_path):
        self.log_path = log_path
        self.last_hash = self._get_last_hash()

    def _get_last_hash(self):
        if not self.log_path:
            raise ValueError("log_path must be provided and not empty")
        if not os.path.exists(self.log_path):
            return '0' * 64
        with open(self.log_path, 'rb') as f:
            lines = f.readlines()
            if not lines:
                return '0' * 64
            last_entry = json.loads(lines[-1].decode())
            return last_entry['entry_hash']

    def log_event(self, event):
        """
        Log a security event. Each entry is chained with the previous entry's hash.
        """
        if not self.log_path:
            raise ValueError("log_path must be provided and not empty")
        timestamp = time.time()
        entry = {
            'timestamp': timestamp,
            'event': event,
            'prev_hash': self.last_hash
        }
        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        entry_hash = hashlib.sha256(entry_bytes).hexdigest()
        entry['entry_hash'] = entry_hash
        with open(self.log_path, 'ab') as f:
            f.write(json.dumps(entry).encode() + b'\n')
        self.last_hash = entry_hash 