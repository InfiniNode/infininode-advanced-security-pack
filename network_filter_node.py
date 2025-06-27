"""
NetworkFilterNode: Filters or blocks network requests based on user-defined rules (domain, IP, protocol, port).
Author: Azazeal (Azazeal04)

Example usage:
    node = NetworkFilterNode()
    allowed = node.filter_request({'domain': 'example.com', 'ip': '1.2.3.4', 'port': 80}, rules)
"""

class NetworkFilterNode:
    RETURN_TYPES = ("BOOLEAN",)
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "request_info": ("DICT", {"default": {}}),
                "rules": ("DICT", {"default": {}}),
            },
            "optional": {}
        }

    def __init__(self):
        pass

    def filter_request(self, request_info, rules):
        """
        Filter or block a network request based on the provided rules.
        request_info: dict with keys like 'domain', 'ip', 'port', 'protocol'
        rules: dict with 'allow' and 'block' lists for domains, IPs, ports, protocols
        Returns True if allowed, False if blocked.
        """
        # Example rules structure:
        # rules = {
        #     'allow': {'domains': [], 'ips': [], 'ports': [], 'protocols': []},
        #     'block': {'domains': ['malicious.com'], 'ips': ['123.123.123.123'], 'ports': [666], 'protocols': ['ftp']}
        # }
        for key in ['domain', 'ip', 'port', 'protocol']:
            value = request_info.get(key)
            if value is None:
                continue
            # Block rules take precedence
            if value in rules.get('block', {}).get(f'{key}s', []):
                return False
            if rules.get('allow', {}).get(f'{key}s') and value not in rules['allow'][f'{key}s']:
                return False
        return True 