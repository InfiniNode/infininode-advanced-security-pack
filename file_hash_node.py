"""
FileHashNode: Computes file hashes (SHA256, SHA512, etc.) for integrity checks.
Author: Azazeal (Azazeal04)
"""

import hashlib

class FileHashNode:
    RETURN_TYPES = ("STRING",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "file_path": ("STRING", {"default": ""}),
                "algorithm": ("STRING", {"default": "sha256"}),
            },
            "optional": {}
        }

    def __init__(self):
        pass

    def compute_hash(self, file_path, algorithm='sha256'):
        """
        Compute the hash of a file using the specified algorithm.
        """
        if not file_path:
            raise ValueError("file_path must be provided and not empty")
        hash_func = getattr(hashlib, algorithm, None)
        if not hash_func:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        try:
            with open(file_path, 'rb') as f:
                hasher = hash_func()
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            raise RuntimeError(f"Hash computation failed: {e}") 