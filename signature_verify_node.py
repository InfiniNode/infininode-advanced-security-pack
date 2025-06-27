"""
SignatureVerifyNode: Verifies digital signatures (RSA, ECDSA, Ed25519) for file authenticity.
Author: Azazeal (Azazeal04)

Example usage:
    node = SignatureVerifyNode()
    is_valid = node.verify_signature('file.txt', 'file.sig', 'public.pem', algorithm='rsa')
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec, ed25519
from cryptography.exceptions import InvalidSignature

class SignatureVerifyNode:
    RETURN_TYPES = ("BOOLEAN",)
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "file_path": ("STRING", {"default": ""}),
                "signature_path": ("STRING", {"default": ""}),
                "public_key_path": ("STRING", {"default": ""}),
                "algorithm": ("STRING", {"default": "rsa"}),
            },
            "optional": {}
        }

    def __init__(self):
        self.supported_algorithms = ['rsa', 'ecdsa', 'ed25519']

    def verify_signature(self, file_path, signature_path, public_key_path, algorithm='rsa'):
        """
        Verify the digital signature of a file using the specified algorithm.
        Returns True if valid, False otherwise.
        """
        if not file_path:
            raise ValueError("file_path must be provided and not empty")
        if not signature_path:
            raise ValueError("signature_path must be provided and not empty")
        if not public_key_path:
            raise ValueError("public_key_path must be provided and not empty")
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        with open(file_path, 'rb') as f:
            data = f.read()
        with open(signature_path, 'rb') as f:
            signature = f.read()
        with open(public_key_path, 'rb') as f:
            public_key_data = f.read()
        if algorithm == 'rsa':
            public_key = serialization.load_pem_public_key(public_key_data)
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError("Provided public key is not an RSA public key.")
            try:
                public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
            except InvalidSignature:
                return False
        elif algorithm == 'ecdsa':
            public_key = serialization.load_pem_public_key(public_key_data)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError("Provided public key is not an ECDSA public key.")
            try:
                public_key.verify(
                    signature,
                    data,
                    ec.ECDSA(hashes.SHA256())
                )
                return True
            except InvalidSignature:
                return False
        elif algorithm == 'ed25519':
            # Try to load as PEM, fallback to raw bytes
            try:
                public_key = serialization.load_pem_public_key(public_key_data)
                if not isinstance(public_key, ed25519.Ed25519PublicKey):
                    raise ValueError("Provided public key is not an Ed25519 public key.")
            except ValueError:
                # If not PEM, try loading as raw bytes
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_data)
            try:
                public_key.verify(signature, data)
                return True
            except InvalidSignature:
                return False 