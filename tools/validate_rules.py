#!/usr/bin/env python3
"""
Sentinel Lineage EDR - Rule Validator
Validates rules.yaml against schema, checks for conflicts, and tests regex patterns.
"""

import sys
import os
import yaml
import re
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any
from dataclasses import dataclass
from enum import Enum

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Rule flag constants
RF_REGEX = 1 << 0
RF_CMDLINE = 1 << 1
RF_BINARY = 1 << 2
RF_LINEAGE = 1 << 3
RF_UID_RANGE = 1 << 4
RF_NETWORK = 1 << 5
RF_FILE_WRITE = 1 << 6

ACTIONS = {"LOG", "ALERT", "KILL", "BLOCK", "QUARANTINE"}
SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

# MITRE ATT&CK tactic tags (valid values)
MITRE_TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-control", "exfiltration", "impact",
    "reconnaissance", "resource-development"
}

# Common tags
VALID_TAGS = MITRE_TACTICS | {
    "reverse-shell", "pipe-exec", "fileless", "lolbas", "scripting",
    "powershell", "webshell", "web-application",
    "credential-access", "etc-shadow", "ssh-keys", "sudoers", "kerberos",
    "browser", "cloud-credentials", "sudo", "suid", "library-injection",
    "cron", "systemd", "kernel", "persistence", "linux-capabilities",
    "log-tampering", "audit", "timestomp", "binary-padding", "process-injection",
    "ptrace", "rootkit", "anti-forensics", "port-scan", "system-info",
    "kubernetes", "container", "cloud", "metadata-service", "process-enum",
    "ssh", "pass-the-hash", "exploitation", "metasploit", "archiving",
    "email", "c2", "remote-access-tool", "tunneling", "proxy", "dns-tunneling",
    "geo-block", "network", "high-ports", "exfiltration", "data-transfer",
    "ransomware", "encryption", "disk-wipe", "destruction", "service-stop",
    "container-escape", "nsenter", "cve-2022-0811", "kubernetes", "rbac",
    "privileged", "container-drift", "anomaly", "cryptomining", "resource-hijacking",
    "resource", "supply-chain", "package-manager", "integrity", "unsigned-binary",
    "compliance", "pci-dss", "pan", "hipaa", "phi", "gdpr", "pii",
    "data-exfiltration", "database", "fim", "critical-file", "etc-passwd",
    "etc-shadow", "persistence", "systemd", "kernel", "bootloader",
    "silent-download", "process-substitution", "encoded-payload", "obfuscation",
    "python", "nodejs"
}

@dataclass
class ValidationResult:
    rule_id: int
    rule_name: str
    errors: List[str]
    warnings: List[str]

class RuleValidator:
    def __init__(self):
        self.results: List[ValidationResult] = []
        self.seen_ids: Set[int] = set()
        self.seen_names: Set[str] = set()

    def validate_file(self, filepath: str) -> Tuple[bool, List[ValidationResult]]:
        """Validate a rules YAML file."""
        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"[ERROR] Failed to parse YAML: {e}")
            return False, []

        if not data or 'rules' not in data:
            print("[ERROR] No 'rules' key found in YAML")
            return False, []

        rules = data.get('rules', [])
        print(f"[INFO] Validating {len(rules)} rules...")

        for rule in rules:
            self.validate_rule(rule)

        return self.report()

    def validate_rule(self, rule: Dict[str, Any]):
        """Validate a single rule."""
        errors = []
        warnings = []

        # Required fields
        rule_id = rule.get('id')
        name = rule.get('name', '')
        pattern = rule.get('pattern', '')
        binary_pattern = rule.get('binary_pattern', '')
        action = rule.get('action', '')
        severity = rule.get('severity', '')
        flags = rule.get('flags', 0)
        lineage_id = rule.get('lineage_id', 0)
        uid_min = rule.get('uid_min', 0)
        uid_max = rule.get('uid_max', 0)
        mitre = rule.get('mitre', [])
        tags = rule.get('tags', [])

        # Rule ID validation
        if rule_id is None:
            errors.append("Missing required field: id")
        elif not isinstance(rule_id, int):
            errors.append(f"Rule ID must be integer, got {type(rule_id).__name__}")
        elif rule_id <= 0:
            errors.append("Rule ID must be positive")
        elif rule_id in self.seen_ids:
            errors.append(f"Duplicate rule ID: {rule_id}")
        else:
            self.seen_ids.add(rule_id)

        # Name validation
        if not name:
            errors.append("Missing required field: name")
        elif name in self.seen_names:
            warnings.append(f"Duplicate rule name: {name}")
        else:
            self.seen_names.add(name)

        # Action validation
        if action not in ACTIONS:
            errors.append(f"Invalid action: {action}. Must be one of {ACTIONS}")

        # Severity validation
        if severity not in SEVERITIES:
            errors.append(f"Invalid severity: {severity}. Must be one of {SEVERITIES}")

        # Flags validation
        if not isinstance(flags, int) or flags < 0:
            errors.append("Flags must be non-negative integer")

        # Pattern validation based on flags
        if flags & RF_REGEX:
            # Test regex compilation
            if pattern:
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    errors.append(f"Invalid regex in pattern: {e}")
            if binary_pattern:
                try:
                    re.compile(binary_pattern, re.IGNORECASE)
                except re.error as e:
                    errors.append(f"Invalid regex in binary_pattern: {e}")

        # Consistency checks
        if flags & RF_CMDLINE and not pattern:
            errors.append("RF_CMDLINE flag set but no pattern provided")
        if flags & RF_BINARY and not binary_pattern:
            errors.append("RF_BINARY flag set but no binary_pattern provided")
        if flags & RF_LINEAGE and lineage_id == 0:
            # Dynamic lineage rule - OK but warn
            warnings.append("RF_LINEAGE flag set with lineage_id=0 (dynamic rule)")
        if flags & RF_UID_RANGE:
            if uid_min == 0 and uid_max == 0:
                warnings.append("RF_UID_RANGE flag set but no uid_min/uid_max provided")
            if uid_min > uid_max and uid_max != 0:
                errors.append("uid_min cannot be greater than uid_max")

        # Network/File rules should have no cmdline/binary patterns unless combined
        if flags & (RF_NETWORK | RF_FILE_WRITE):
            if not (flags & (RF_CMDLINE | RF_BINARY | RF_LINEAGE | RF_UID_RANGE)):
                warnings.append("Network/File rule with no matching criteria - handled separately in agent")

        # MITRE validation
        if mitre:
            for m in mitre:
                if not m.startswith('T') or not m[1:].replace('.', '').isdigit():
                    warnings.append(f"MITRE ID format unusual: {m} (expected Txxxx or Txxxx.xxx)")

        # Tags validation
        if tags:
            for tag in tags:
                if tag not in VALID_TAGS:
                    warnings.append(f"Unknown tag: {tag}")

        # Action severity consistency
        if action == "KILL" and severity in ["INFO", "LOW"]:
            warnings.append("KILL action with low severity - consider HIGH or CRITICAL")
        if action == "LOG" and severity == "CRITICAL":
            warnings.append("LOG action with CRITICAL severity - consider ALERT or KILL")

        # Performance warnings
        if flags & RF_REGEX and pattern:
            # Check for potentially slow patterns
            if '.*' in pattern and pattern.count('.*') > 3:
                warnings.append("Pattern has many .* - may be slow")
            if '(.*' in pattern or '(.+' in pattern:
                warnings.append("Pattern has capturing groups - non-capturing (?:...) preferred")

        self.results.append(ValidationResult(
            rule_id=rule_id or 0,
            rule_name=name or "UNNAMED",
            errors=errors,
            warnings=warnings
        ))

    def report(self) -> Tuple[bool, List[ValidationResult]]:
        """Print validation report and return success status."""
        total_errors = sum(len(r.errors) for r in self.results)
        total_warnings = sum(len(r.warnings) for r in self.results)

        print(f"\n{'='*60}")
        print(f"VALIDATION REPORT")
        print(f"{'='*60}")
        print(f"Rules checked: {len(self.results)}")
        print(f"Errors: {total_errors}")
        print(f"Warnings: {total_warnings}")
        print(f"{'='*60}\n")

        has_errors = False
        for result in self.results:
            if result.errors:
                has_errors = True
                print(f"[ERROR] Rule {result.rule_id} ({result.rule_name}):")
                for e in result.errors:
                    print(f"  - {e}")
            if result.warnings:
                print(f"[WARN]  Rule {result.rule_id} ({result.rule_name}):")
                for w in result.warnings:
                    print(f"  - {w}")

        if total_errors == 0:
            print("[✓] All rules passed validation")
        else:
            print(f"[✗] {total_errors} error(s) found")

        return total_errors == 0, self.results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate Sentinel Lineage rules")
    parser.add_argument('file', nargs='?', default='/etc/sentinel/rules.yaml',
                        help='Path to rules.yaml')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    parser.add_argument('--strict', action='store_true', help='Treat warnings as errors')
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)

    validator = RuleValidator()
    success, results = validator.validate_file(args.file)

    if args.json:
        output = {
            "valid": success,
            "rules": [
                {
                    "id": r.rule_id,
                    "name": r.rule_name,
                    "errors": r.errors,
                    "warnings": r.warnings
                }
                for r in results
            ]
        }
        print(json.dumps(output, indent=2))

    if args.strict:
        total_warnings = sum(len(r.warnings) for r in results)
        if total_warnings > 0:
            print(f"[STRICT] {total_warnings} warning(s) treated as errors")
            success = False

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()