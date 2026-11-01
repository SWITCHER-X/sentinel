"""
StateBackend abstraction for SENTINEL hub.
Supports InMemoryState (single-node) and RedisState (multi-worker).
"""
import os
import json
import time
import threading
from abc import ABC, abstractmethod
from collections import deque
from typing import Any, Dict, List, Optional, Set, Callable

# Try to import redis, but don't require it for InMemoryState
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class StateBackend(ABC):
    """Abstract base for hub state backends."""

    @abstractmethod
    def get_mode(self) -> str:
        """Get current enforcement mode (learn/enforce)."""
        pass

    @abstractmethod
    def set_mode(self, mode: str) -> None:
        """Set enforcement mode."""
        pass

    @abstractmethod
    def get_telemetry_logs(self, limit: int = 10000) -> List[Dict]:
        """Get recent telemetry events (newest first)."""
        pass

    @abstractmethod
    def append_telemetry(self, event: Dict) -> int:
        """Append event, return sequence number."""
        pass

    @abstractmethod
    def get_lineage_trees(self) -> Dict[int, Dict]:
        """Get all lineage trees."""
        pass

    @abstractmethod
    def update_lineage_tree(self, lineage_id: int, update_fn: Callable[[Dict], None]) -> None:
        """Update a lineage tree atomically."""
        pass

    @abstractmethod
    def get_blocked_lineages(self) -> Set[int]:
        """Get set of blocked lineage IDs."""
        pass

    @abstractmethod
    def add_blocked_lineage(self, lineage_id: int) -> None:
        """Add lineage to blocked set."""
        pass

    @abstractmethod
    def remove_blocked_lineage(self, lineage_id: int) -> None:
        """Remove lineage from blocked set."""
        pass

    @abstractmethod
    def get_trusted_lineages(self) -> Set[int]:
        """Get set of trusted lineage IDs."""
        pass

    @abstractmethod
    def add_trusted_lineage(self, lineage_id: int) -> None:
        """Add lineage to trusted set."""
        pass

    @abstractmethod
    def remove_trusted_lineage(self, lineage_id: int) -> None:
        """Remove lineage from trusted set."""
        pass

    @abstractmethod
    def get_connected_nodes(self) -> Dict[str, Dict]:
        """Get connected nodes map."""
        pass

    @abstractmethod
    def update_connected_node(self, node_id: str, data: Dict) -> None:
        """Update connected node info."""
        pass

    @abstractmethod
    def get_login_failures(self, ip: str) -> tuple:
        """Get (failures, until) for login rate limiting."""
        pass

    @abstractmethod
    def set_login_failures(self, ip: str, failures: int, until: float) -> None:
        """Set login failures for IP."""
        pass

    @abstractmethod
    def clear_login_failures(self, ip: str) -> None:
        """Clear login failures for IP."""
        pass

    @abstractmethod
    def get_stats(self) -> Dict:
        """Get aggregate statistics for /api/v1/stats."""
        pass

    @abstractmethod
    def health_check(self) -> Dict:
        """Health check for load balancers."""
        pass


class InMemoryState(StateBackend):
    """In-memory state backend (single-node, preserves current behavior)."""

    name = "inmemory"

    def __init__(self, max_telemetry: int = 10000):
        self._lock = threading.RLock()
        self._mode = "enforce"
        self._telemetry = deque(maxlen=max_telemetry)
        self._event_seq = 0
        self._lineage_trees = {}
        self._blocked_lineages = set()
        self._trusted_lineages = set()
        self._connected_nodes = {}
        self._login_failures = {}
        self._start_time = time.time()

    def get_mode(self) -> str:
        with self._lock:
            return self._mode

    def set_mode(self, mode: str) -> None:
        with self._lock:
            self._mode = mode

    def get_telemetry_logs(self, limit: int = 10000) -> List[Dict]:
        with self._lock:
            return list(self._telemetry)[:limit]

    def append_telemetry(self, event: Dict) -> int:
        with self._lock:
            self._event_seq += 1
            event["_seq"] = self._event_seq
            self._telemetry.appendleft(event)
            return self._event_seq

    def get_lineage_trees(self) -> Dict[int, Dict]:
        with self._lock:
            return dict(self._lineage_trees)

    def update_lineage_tree(self, lineage_id: int, update_fn: Callable[[Dict], None]) -> None:
        with self._lock:
            if lineage_id not in self._lineage_trees:
                self._lineage_trees[lineage_id] = {
                    "lineage_id": lineage_id,
                    "parent_lineage_id": None,
                    "root_pid": None,
                    "nodes": {},
                    "threat_count": 0,
                    "blocked": False,
                    "trusted": False,
                    "first_seen": time.time(),
                    "last_seen": time.time()
                }
            update_fn(self._lineage_trees[lineage_id])

    def get_blocked_lineages(self) -> Set[int]:
        with self._lock:
            return set(self._blocked_lineages)

    def add_blocked_lineage(self, lineage_id: int) -> None:
        with self._lock:
            self._blocked_lineages.add(lineage_id)

    def remove_blocked_lineage(self, lineage_id: int) -> None:
        with self._lock:
            self._blocked_lineages.discard(lineage_id)

    def get_trusted_lineages(self) -> Set[int]:
        with self._lock:
            return set(self._trusted_lineages)

    def add_trusted_lineage(self, lineage_id: int) -> None:
        with self._lock:
            self._trusted_lineages.add(lineage_id)

    def remove_trusted_lineage(self, lineage_id: int) -> None:
        with self._lock:
            self._trusted_lineages.discard(lineage_id)

    def get_connected_nodes(self) -> Dict[str, Dict]:
        with self._lock:
            return dict(self._connected_nodes)

    def update_connected_node(self, node_id: str, data: Dict) -> None:
        with self._lock:
            self._connected_nodes[node_id] = data

    def get_login_failures(self, ip: str) -> tuple:
        with self._lock:
            return self._login_failures.get(ip, (0, 0))

    def set_login_failures(self, ip: str, failures: int, until: float) -> None:
        with self._lock:
            self._login_failures[ip] = (failures, until)

    def clear_login_failures(self, ip: str) -> None:
        with self._lock:
            self._login_failures.pop(ip, None)

    def get_stats(self) -> Dict:
        with self._lock:
            now = time.time()
            active_nodes = sum(1 for n in self._connected_nodes.values() if now - n.get("last_seen", 0) < 30)
            total_trees = len(self._lineage_trees)
            blocked_trees = sum(1 for t in self._lineage_trees.values() if t.get("blocked"))
            trusted_trees = sum(1 for t in self._lineage_trees.values() if t.get("trusted"))
            total_nodes = sum(len(t.get("nodes", {})) for t in self._lineage_trees.values())
            total_threats = sum(t.get("threat_count", 0) for t in self._lineage_trees.values())
            total_exec = sum(1 for x in self._telemetry if x.get("type") == "EXEC_THREAT")
            total_geo = sum(1 for x in self._telemetry if x.get("type") == "GEO_BLOCK")
            total_file = sum(1 for x in self._telemetry if x.get("type") == "FILE_THREAT")
            total_net = sum(1 for x in self._telemetry if x.get("type") == "NETWORK_THREAT")
            total_killed = sum(1 for x in self._telemetry if x.get("killed"))
            critical_threats = sum(1 for x in self._telemetry if x.get("severity") == "CRITICAL")
            exfil_attempts = sum(1 for x in self._telemetry if x.get("type") in [
                "ICMP_COVERT_CHANNEL", "DATA_EXFILTRATION_VOLUME", "DNS_TUNNELING_RATE", "DNS_TUNNELING"])
            kernel_alerts = sum(1 for x in self._telemetry if x.get("type") in [
                "BPF_PROG_LOAD", "BPF_MAP_CREATE", "KERNEL_MODULE_LOAD", "MODULE_READ_FILE"])

            return {
                "active_nodes": max(active_nodes, 1),
                "total_events": len(self._telemetry),
                "exec_threats": total_exec,
                "geo_blocks": total_geo,
                "file_threats": total_file,
                "network_threats": total_net,
                "killed_processes": total_killed,
                "critical_threats": critical_threats,
                "exfil_attempts": exfil_attempts,
                "kernel_alerts": kernel_alerts,
                "uptime_seconds": int(now - self._start_time),
                "lineage": {
                    "total_lineages": total_trees,
                    "blocked_lineages": blocked_trees,
                    "trusted_lineages": trusted_trees,
                    "total_processes": total_nodes,
                    "total_threats": total_threats
                },
                "mode": self._mode
            }

    def health_check(self) -> Dict:
        return {
            "status": "healthy",
            "timestamp": time.time(),
            "uptime_seconds": int(time.time() - self._start_time),
            "checks": {
                "state_backend": {"status": "ok", "type": "inmemory"}
            }
        }


class RedisState(StateBackend):
    """Redis-backed state for multi-worker deployments."""

    name = "redis"

    def __init__(self, url: str = "redis://localhost:6379/0"):
        if not REDIS_AVAILABLE:
            raise RuntimeError("redis-py not installed. Install with: pip install redis")
        self._redis = redis.from_url(url, decode_responses=True)
        self._lock = threading.RLock()  # Local lock for compound operations
        self._pubsub = self._redis.pubsub()
        self._pubsub.subscribe("sentinel:commands")
        self._start_time = time.time()

    # Redis key prefixes
    MODE_KEY = "sentinel:mode"
    TELEMETRY_KEY = "sentinel:telemetry"
    EVENT_SEQ_KEY = "sentinel:event_seq"
    LINEAGE_PREFIX = "sentinel:lineage:"
    BLOCKED_KEY = "sentinel:blocked_lineages"
    TRUSTED_KEY = "sentinel:trusted_lineages"
    NODES_KEY = "sentinel:connected_nodes"
    LOGIN_FAIL_PREFIX = "sentinel:login_fail:"

    def get_mode(self) -> str:
        return self._redis.get(self.MODE_KEY) or "enforce"

    def set_mode(self, mode: str) -> None:
        self._redis.set(self.MODE_KEY, mode)

    def get_telemetry_logs(self, limit: int = 10000) -> List[Dict]:
        # Telemetry stored as list with newest at index 0
        data = self._redis.lrange(self.TELEMETRY_KEY, 0, limit - 1)
        return [json.loads(d) for d in data]

    def append_telemetry(self, event: Dict) -> int:
        # Use atomic increment for sequence
        seq = self._redis.incr(self.EVENT_SEQ_KEY)
        event["_seq"] = seq
        # Push to front of list, trim to maxlen
        pipe = self._redis.pipeline()
        pipe.lpush(self.TELEMETRY_KEY, json.dumps(event))
        pipe.ltrim(self.TELEMETRY_KEY, 0, 9999)
        pipe.execute()
        return seq

    def get_lineage_trees(self) -> Dict[int, Dict]:
        keys = self._redis.keys(f"{self.LINEAGE_PREFIX}*")
        trees = {}
        for key in keys:
            data = self._redis.get(key)
            if data:
                lineage_id = int(key.split(":")[-1], 16)
                trees[lineage_id] = json.loads(data)
        return trees

    def update_lineage_tree(self, lineage_id: int, update_fn: Callable[[Dict], None]) -> None:
        key = f"{self.LINEAGE_PREFIX}{lineage_id:016x}"
        with self._lock:
            data = self._redis.get(key)
            tree = json.loads(data) if data else {
                "lineage_id": lineage_id,
                "parent_lineage_id": None,
                "root_pid": None,
                "nodes": {},
                "threat_count": 0,
                "blocked": False,
                "trusted": False,
                "first_seen": time.time(),
                "last_seen": time.time()
            }
            update_fn(tree)
            self._redis.set(key, json.dumps(tree, default=str))

    def get_blocked_lineages(self) -> Set[int]:
        return {int(x, 16) for x in self._redis.smembers(self.BLOCKED_KEY)}

    def add_blocked_lineage(self, lineage_id: int) -> None:
        self._redis.sadd(self.BLOCKED_KEY, f"{lineage_id:016x}")

    def remove_blocked_lineage(self, lineage_id: int) -> None:
        self._redis.srem(self.BLOCKED_KEY, f"{lineage_id:016x}")

    def get_trusted_lineages(self) -> Set[int]:
        return {int(x, 16) for x in self._redis.smembers(self.TRUSTED_KEY)}

    def add_trusted_lineage(self, lineage_id: int) -> None:
        self._redis.sadd(self.TRUSTED_KEY, f"{lineage_id:016x}")

    def remove_trusted_lineage(self, lineage_id: int) -> None:
        self._redis.srem(self.TRUSTED_KEY, f"{lineage_id:016x}")

    def get_connected_nodes(self) -> Dict[str, Dict]:
        data = self._redis.get(self.NODES_KEY)
        return json.loads(data) if data else {}

    def update_connected_node(self, node_id: str, data: Dict) -> None:
        nodes = self.get_connected_nodes()
        nodes[node_id] = data
        self._redis.set(self.NODES_KEY, json.dumps(nodes, default=str))

    def get_login_failures(self, ip: str) -> tuple:
        key = f"{self.LOGIN_FAIL_PREFIX}{ip}"
        data = self._redis.get(key)
        if data:
            return tuple(map(int, data.split(":")))
        return (0, 0)

    def set_login_failures(self, ip: str, failures: int, until: float) -> None:
        key = f"{self.LOGIN_FAIL_PREFIX}{ip}"
        self._redis.setex(key, int(until - time.time()) + 1, f"{failures}:{int(until)}")

    def clear_login_failures(self, ip: str) -> None:
        self._redis.delete(f"{self.LOGIN_FAIL_PREFIX}{ip}")

    def get_stats(self) -> Dict:
        with self._lock:
            # For Redis, we need to compute from stored state
            telemetry = self.get_telemetry_logs(10000)
            nodes = self.get_connected_nodes()
            trees = self.get_lineage_trees()

            now = time.time()
            active_nodes = sum(1 for n in nodes.values() if now - n.get("last_seen", 0) < 30)
            total_trees = len(trees)
            blocked_trees = sum(1 for t in trees.values() if t.get("blocked"))
            trusted_trees = sum(1 for t in trees.values() if t.get("trusted"))
            total_nodes = sum(len(t.get("nodes", {})) for t in trees.values())
            total_threats = sum(t.get("threat_count", 0) for t in trees.values())
            total_exec = sum(1 for x in telemetry if x.get("type") == "EXEC_THREAT")
            total_geo = sum(1 for x in telemetry if x.get("type") == "GEO_BLOCK")
            total_file = sum(1 for x in telemetry if x.get("type") == "FILE_THREAT")
            total_net = sum(1 for x in telemetry if x.get("type") == "NETWORK_THREAT")
            total_killed = sum(1 for x in telemetry if x.get("killed"))
            critical_threats = sum(1 for x in telemetry if x.get("severity") == "CRITICAL")
            exfil_attempts = sum(1 for x in telemetry if x.get("type") in [
                "ICMP_COVERT_CHANNEL", "DATA_EXFILTRATION_VOLUME", "DNS_TUNNELING_RATE", "DNS_TUNNELING"])
            kernel_alerts = sum(1 for x in telemetry if x.get("type") in [
                "BPF_PROG_LOAD", "BPF_MAP_CREATE", "KERNEL_MODULE_LOAD", "MODULE_READ_FILE"])

            return {
                "active_nodes": max(active_nodes, 1),
                "total_events": len(telemetry),
                "exec_threats": total_exec,
                "geo_blocks": total_geo,
                "file_threats": total_file,
                "network_threats": total_net,
                "killed_processes": total_killed,
                "critical_threats": critical_threats,
                "exfil_attempts": exfil_attempts,
                "kernel_alerts": kernel_alerts,
                "uptime_seconds": int(now - self._start_time),
                "lineage": {
                    "total_lineages": total_trees,
                    "blocked_lineages": blocked_trees,
                    "trusted_lineages": trusted_trees,
                    "total_processes": total_nodes,
                    "total_threats": total_threats
                },
                "mode": self.get_mode()
            }

    def health_check(self) -> Dict:
        try:
            self._redis.ping()
            redis_status = "ok"
        except Exception as e:
            redis_status = f"failed: {e}"
        return {
            "status": "healthy" if redis_status == "ok" else "degraded",
            "timestamp": time.time(),
            "uptime_seconds": int(time.time() - self._start_time),
            "checks": {
                "redis": {"status": redis_status}
            }
        }


def create_state_backend() -> StateBackend:
    """Factory function to create the appropriate state backend."""
    redis_url = os.getenv("SENTINEL_REDIS_URL")
    if redis_url:
        return RedisState(redis_url)
    return InMemoryState()