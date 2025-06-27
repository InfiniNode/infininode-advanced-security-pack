"""
EncryptionNode: Provides AES, ChaCha20, and RSA encryption/decryption.
Author: Azazeal (Azazeal04)

Example usage:
    node = EncryptionNode()
    ciphertext = node.encrypt(b'secret', algorithm='aes', key=my_aes_key)
    plaintext = node.decrypt(ciphertext, algorithm='aes', key=my_aes_key)
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os

class EncryptionNode:
    RETURN_TYPES = ("BYTES",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "data": ("BYTES", {"default": b""}),
                "algorithm": ("STRING", {"default": "aes"}),
            },
            "optional": {
                "key": ("BYTES", {"default": b""}),
                "public_key_path": ("STRING", {"default": ""}),
                "private_key_path": ("STRING", {"default": ""}),
            }
        }

    def __init__(self):
        pass

    def encrypt(self, data, algorithm='aes', key=None, public_key_path=None):
        """
        Encrypt data using the specified algorithm and key.
        For RSA, provide public_key_path.
        """
        if algorithm == 'aes':
            if key is None:
                raise ValueError('AES encryption requires a key')
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            ct = encryptor.update(padded_data) + encryptor.finalize()
            return iv + ct
        elif algorithm == 'chacha20':
            if key is None:
                raise ValueError('ChaCha20 encryption requires a key')
            nonce = os.urandom(16)
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(data) + encryptor.finalize()
            return nonce + ct
        elif algorithm == 'rsa':
            if not public_key_path:
                raise ValueError('RSA encryption requires public_key_path and it must not be empty')
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError('Provided public key is not an RSA public key.')
            ct = public_key.encrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ct
        else:
            raise ValueError('Unsupported algorithm')

    def decrypt(self, data, algorithm='aes', key=None, private_key_path=None):
        """
        Decrypt data using the specified algorithm and key.
        For RSA, provide private_key_path.
        """
        if algorithm == 'aes':
            if key is None:
                raise ValueError('AES decryption requires a key')
            iv = data[:16]
            ct = data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ct) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        elif algorithm == 'chacha20':
            if key is None:
                raise ValueError('ChaCha20 decryption requires a key')
            nonce = data[:16]
            ct = data[16:]
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ct) + decryptor.finalize()
        elif algorithm == 'rsa':
            if not private_key_path:
                raise ValueError('RSA decryption requires private_key_path and it must not be empty')
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError('Provided private key is not an RSA private key.')
            pt = private_key.decrypt(
                data,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return pt
        else:
            raise ValueError('Unsupported algorithm') 