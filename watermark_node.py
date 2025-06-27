"""
WatermarkNode: Embeds and extracts watermarks/steganography for data authenticity.
Author: Azazeal (Azazeal04)

Example usage:
    node = WatermarkNode()
    watermarked = node.embed_watermark(b'data', b'WM')
    watermark = node.extract_watermark(watermarked)
"""

import numpy as np
from PIL import Image
import io
import hmac
import hashlib

class WatermarkNode:
    RETURN_TYPES = ("BYTES",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "data": ("BYTES", {"default": b""}),
                "watermark": ("BYTES", {"default": b""}),
            },
            "optional": {
                "key": ("BYTES", {"default": b""}),
                "image_path": ("STRING", {"default": ""}),
                "watermark_text": ("STRING", {"default": ""}),
                "output_path": ("STRING", {"default": ""}),
                "max_length": ("INT", {"default": 256}),
            }
        }

    def __init__(self):
        pass

    def embed_watermark_image(self, image_path, watermark_text, output_path=None):
        """
        Embed a text watermark into an image using LSB steganography.
        """
        if not image_path:
            raise ValueError("image_path must be provided and not empty")
        img = Image.open(image_path)
        img = img.convert('RGB')
        arr = np.array(img)
        flat = arr.flatten()
        # Convert watermark to bits
        watermark_bytes = watermark_text.encode('utf-8') + b'\0'  # Null-terminated
        watermark_bits = ''.join(f'{byte:08b}' for byte in watermark_bytes)
        if len(watermark_bits) > len(flat):
            raise ValueError('Watermark too large for image.')
        # Embed bits
        for i, bit in enumerate(watermark_bits):
            flat[i] = (flat[i] & ~1) | int(bit)
        arr2 = flat.reshape(arr.shape)
        watermarked_img = Image.fromarray(arr2)
        if output_path:
            watermarked_img.save(output_path)
            return output_path
        buf = io.BytesIO()
        watermarked_img.save(buf, format='PNG')
        return buf.getvalue()

    def extract_watermark_image(self, image_path, max_length=256):
        """
        Extract a text watermark from an image using LSB steganography.
        """
        if not image_path:
            raise ValueError("image_path must be provided and not empty")
        img = Image.open(image_path)
        arr = np.array(img)
        flat = arr.flatten()
        bits = [str(flat[i] & 1) for i in range(max_length * 8)]
        chars = [chr(int(''.join(bits[i:i+8]), 2)) for i in range(0, len(bits), 8)]
        out = ''.join(chars)
        return out.split('\0', 1)[0]

    def embed_watermark_data(self, data, watermark, key):
        """
        Embed a watermark in binary data using HMAC for authenticity.
        Returns data + HMAC(watermark).
        """
        mac = hmac.new(key, watermark, hashlib.sha256).digest()
        return data + b'::WMAC::' + mac

    def verify_watermark_data(self, data, watermark, key):
        """
        Verify a watermark in binary data using HMAC.
        Returns True if valid, False otherwise.
        """
        if b'::WMAC::' not in data:
            return False
        payload, mac = data.rsplit(b'::WMAC::', 1)
        expected_mac = hmac.new(key, watermark, hashlib.sha256).digest()
        return hmac.compare_digest(mac, expected_mac)

    def embed_watermark(self, data, watermark):
        """
        Embed a watermark into the data (simple append for demonstration).
        """
        return data + b'::WATERMARK::' + watermark

    def extract_watermark(self, data):
        """
        Extract a watermark from the data (simple split for demonstration).
        """
        if b'::WATERMARK::' in data:
            return data.split(b'::WATERMARK::')[-1]
        return None 