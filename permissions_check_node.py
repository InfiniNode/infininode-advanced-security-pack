"""
PermissionsCheckNode: Checks for insecure file permissions.
Author: Azazeal (Azazeal04)

Example usage:
    node = PermissionsCheckNode()
    insecure = node.check_permissions('file.txt')
"""

import os
import stat

class PermissionsCheckNode:
    RETURN_TYPES = ("BOOLEAN",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "file_path": ("STRING", {"default": ""}),
            },
            "optional": {}
        }

    def __init__(self):
        pass

    def check_permissions(self, file_path):
        """
        Check for insecure permissions on the specified file.
        Returns True if permissions are insecure (world-writable or world-readable), False otherwise.
        """
        st = os.stat(file_path)
        # Check world-readable or world-writable
        insecure = bool(st.st_mode & stat.S_IROTH or st.st_mode & stat.S_IWOTH)
        return insecure 