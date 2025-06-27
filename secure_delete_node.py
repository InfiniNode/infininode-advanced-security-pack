"""
SecureDeleteNode: Securely deletes files to prevent recovery.
Author: Azazeal (Azazeal04)

Example usage:
    node = SecureDeleteNode()
    node.secure_delete('file.txt')
"""

import os
import random

class SecureDeleteNode:
    RETURN_TYPES = ("NONE",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "file_path": ("STRING", {"default": ""}),
            },
            "optional": {
                "passes": ("INT", {"default": 3}),
            }
        }

    def __init__(self):
        pass

    def secure_delete(self, file_path, passes=3):
        """
        Securely delete the specified file by overwriting with random data before removal.
        passes: number of overwrite passes (default 3)
        """
        if not file_path:
            raise ValueError("file_path must be provided and not empty")
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        length = os.path.getsize(file_path)
        with open(file_path, 'ba+', buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
        os.remove(file_path) 