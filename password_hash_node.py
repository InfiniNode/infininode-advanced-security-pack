"""
PasswordHashNode: Securely hashes and validates passwords (bcrypt, Argon2).
Author: Azazeal (Azazeal04)

Example usage:
    node = PasswordHashNode()
    hashed = node.hash_password('secret', algorithm='bcrypt')
    valid = node.validate_password('secret', hashed, algorithm='bcrypt')
"""

import bcrypt
from argon2 import PasswordHasher

class PasswordHashNode:
    RETURN_TYPES = ("STRING",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "password": ("STRING", {"default": ""}),
                "algorithm": ("STRING", {"default": "bcrypt"}),
            },
            "optional": {
                "hashed": ("STRING", {"default": ""}),
            }
        }

    def __init__(self):
        self.argon2_hasher = PasswordHasher()

    def hash_password(self, password, algorithm='bcrypt'):
        """
        Hash a password using the specified algorithm.
        Returns the hashed password (bytes for bcrypt, str for argon2).
        """
        if algorithm == 'bcrypt':
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        elif algorithm == 'argon2':
            return self.argon2_hasher.hash(password)
        else:
            raise ValueError('Unsupported algorithm')

    def validate_password(self, password, hashed, algorithm='bcrypt'):
        """
        Validate a password against a hash using the specified algorithm.
        Returns True if valid, False otherwise.
        """
        if algorithm == 'bcrypt':
            return bcrypt.checkpw(password.encode(), hashed)
        elif algorithm == 'argon2':
            try:
                self.argon2_hasher.verify(hashed, password)
                return True
            except Exception:
                return False
        else:
            raise ValueError('Unsupported algorithm') 