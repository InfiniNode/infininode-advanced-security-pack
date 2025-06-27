"""
InfiniNode Security Pack for ComfyUI
Author: Azazeal (Azazeal04)
"""

import sys
if sys.version_info < (3, 8):
    raise RuntimeError("InfiniNode Advanced Security Pack requires Python 3.8 or higher.")
import importlib.util
import os
import json
import glob

def import_module_from_file(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module {module_name} from {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def detect_and_resolve_conflicts(pack_name='InfiniNode'):
    custom_nodes_dir = os.path.dirname(__file__)
    node_classes = {}
    renamed_nodes = []
    
    for fname in os.listdir(custom_nodes_dir):
        if fname.endswith('.py') and fname != '__init__.py':
            mod_name = fname[:-3]
            file_path = os.path.join(custom_nodes_dir, fname)
            mod = import_module_from_file(mod_name, file_path)
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type):
                    if attr in node_classes:
                        # Conflict detected! Auto-rename
                        new_name = f'{pack_name}_{attr}'
                        setattr(mod, new_name, obj)
                        renamed_nodes.append((attr, mod_name, new_name))
                        print(f'[InfiniNode] Auto-renamed conflicting node: {attr} -> {new_name} in {mod_name}')
                    else:
                        node_classes[attr] = mod_name
    
    # Provide summary notice to user
    if renamed_nodes:
        print(f'\n[InfiniNode] Security Pack Notice:')
        print(f'  {len(renamed_nodes)} conflicting nodes were automatically renamed:')
        for old_name, module, new_name in renamed_nodes:
            print(f'    • {old_name} -> {new_name} (in {module})')
        print(f'  This prevents conflicts with existing ComfyUI nodes.')
        print(f'  Use the new names when referencing these nodes in workflows.\n')

detect_and_resolve_conflicts()

def scan_file_with_all_checks(file_path, yara_rules_path, cve_db_path, audit_log_path):
    results = {}
    # File integrity: hash (sha256, sha512)
    try:
        from .file_hash_node import FileHashNode
        hash_node = FileHashNode()
        results['sha256'] = hash_node.compute_hash(file_path, algorithm='sha256')
        results['sha512'] = hash_node.compute_hash(file_path, algorithm='sha512')
    except Exception as e:
        results['hash_error'] = str(e)
    # Digital signature verification (if .sig and .pem exist)
    try:
        from .signature_verify_node import SignatureVerifyNode
        sig_path = file_path + '.sig'
        pubkey_path = file_path + '.pem'
        if os.path.exists(sig_path) and os.path.exists(pubkey_path):
            sig_node = SignatureVerifyNode()
            results['signature_valid'] = sig_node.verify_signature(file_path, sig_path, pubkey_path)
    except Exception as e:
        results['signature_error'] = str(e)
    # YARA scan
    try:
        from .yara_scan_node import YARAScanNode
        yara_node = YARAScanNode()
        results['yara_matches'] = yara_node.scan_file(file_path, yara_rules_path)
    except Exception as e:
        results['yara_error'] = str(e)
    # Permissions check
    try:
        from .permissions_check_node import PermissionsCheckNode
        perm_node = PermissionsCheckNode()
        results['insecure_permissions'] = perm_node.check_permissions(file_path)
    except Exception as e:
        results['permissions_error'] = str(e)
    # Vulnerability scan (if file is software, e.g., .py)
    try:
        from .vuln_scan_node import VulnScanNode
        vuln_node = VulnScanNode()
        # For demo, treat each .py as a software with name=file, version='unknown'
        sw_list = [{'name': os.path.basename(file_path), 'version': 'unknown'}]
        results['vulns'] = vuln_node.scan_software(sw_list, cve_db_path)
    except Exception as e:
        results['vuln_error'] = str(e)
    # Log results
    try:
        from .audit_log_node import AuditLogNode
        audit_node = AuditLogNode(audit_log_path)
        audit_node.log_event({'event': 'startup_scan', 'file': file_path, 'results': results})
    except Exception as e:
        print(f'[InfiniNode] Audit log error: {e}')
    print(f'[InfiniNode] Scan results for {file_path}: {results}')

def scan_custom_nodes_at_startup():
    custom_nodes_dir = os.path.dirname(__file__)
    yara_rules_path = os.path.join(custom_nodes_dir, 'example_rules.yar')
    cve_db_path = os.path.join(custom_nodes_dir, 'example_cve_db.json')
    audit_log_path = os.path.join(custom_nodes_dir, 'audit.log')
    # Recursively find all .py files (excluding __init__.py)
    py_files = [f for f in glob.glob(os.path.join(custom_nodes_dir, '**', '*.py'), recursive=True) if os.path.basename(f) != '__init__.py']
    for file_path in py_files:
        rel_path = os.path.relpath(file_path, custom_nodes_dir)
        print(f'[InfiniNode] Scanning custom node: {rel_path}')
        scan_file_with_all_checks(file_path, yara_rules_path, cve_db_path, audit_log_path)

# Run security scan at startup
print("[InfiniNode] Starting security scan of ComfyUI environment...")
scan_custom_nodes_at_startup()
print("[InfiniNode] Security scan completed.")

# Empty NODE_CLASS_MAPPINGS to prevent ComfyUI from showing error
# This is not a node pack, but a security scanner
NODE_CLASS_MAPPINGS = {} 