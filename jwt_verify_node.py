"""
JWTVerifyNode: Verifies JWT tokens for API security.
Author: Azazeal (Azazeal04)

Example usage:
    node = JWTVerifyNode()
    is_valid = node.verify_jwt(token, public_key_path='public.pem')
"""

import jwt
from cryptography.hazmat.primitives import serialization

class JWTVerifyNode:
    RETURN_TYPES = ("DICT",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "token": ("STRING", {"default": ""}),
                "public_key_path": ("STRING", {"default": ""}),
            },
            "optional": {
                "algorithms": ("LIST", {"default": ["RS256"]}),
            }
        }

    def __init__(self):
        pass

    def verify_jwt(self, token, public_key_path, algorithms=['RS256']):
        """
        Verify a JWT token using the provided public key file.
        Returns the decoded payload if valid, raises jwt.InvalidTokenError if not.
        """
        if not public_key_path:
            raise ValueError("public_key_path must be provided and not empty")
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read())
        # Export public key in PEM format for pyjwt
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return jwt.decode(token, pem, algorithms=algorithms) 