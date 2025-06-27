"""
RateLimitNode: Implements rate limiting to prevent abuse.
Author: Azazeal (Azazeal04)

Example usage:
    node = RateLimitNode()
    allowed = node.check_rate_limit('user1', 'upload')
"""

import time

class RateLimitNode:
    RETURN_TYPES = ("BOOLEAN",)

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "user_id": ("STRING", {"default": ""}),
                "action": ("STRING", {"default": ""}),
            },
            "optional": {
                "max_requests": ("INT", {"default": 5}),
                "window_seconds": ("INT", {"default": 60}),
            }
        }

    def __init__(self, max_requests=5, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.access_log = {}

    def check_rate_limit(self, user_id, action):
        """
        Check and enforce rate limits for a user/action.
        Returns True if allowed, False if rate limited.
        """
        now = time.time()
        key = (user_id, action)
        if key not in self.access_log:
            self.access_log[key] = []
        # Remove old timestamps
        self.access_log[key] = [t for t in self.access_log[key] if now - t < self.window_seconds]
        if len(self.access_log[key]) < self.max_requests:
            self.access_log[key].append(now)
            return True
        return False 