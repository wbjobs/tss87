import asyncio
import websockets
import json
import random
import time
import threading
import math
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Deque, Tuple, Optional

SYSCALL_CATEGORIES = {
    "file_ops": ["open", "read", "write", "close", "creat", "unlink", "rename", "stat", "fstat", "lseek"],
    "network": ["socket", "connect", "accept", "send", "recv", "bind", "listen"],
    "process": ["fork", "execve", "exit", "wait", "kill", "getpid", "getppid"],
    "memory": ["mmap", "munmap", "brk", "sbrk", "mprotect"],
    "time": ["time", "gettimeofday", "clock_gettime", "nanosleep", "usleep"]
}

ALL_SYSCALLS = [s for cat in SYSCALL_CATEGORIES.values() for s in cat]

CATEGORY_MAP = {}
for cat, syscalls in SYSCALL_CATEGORIES.items():
    for s in syscalls:
        CATEGORY_MAP[s] = cat

CATEGORY_LIST = list(CATEGORY_MAP.items())

BASE_FREQUENCY = {
    "read": 0.25, "write": 0.20, "open": 0.10, "close": 0.10,
    "recv": 0.08, "send": 0.06, "mmap": 0.04, "stat": 0.03,
    "gettimeofday": 0.03, "clock_gettime": 0.03,
    "time": 0.02, "fstat": 0.02, "lseek": 0.02,
    "fork": 0.01, "execve": 0.01,
    "munmap": 0.01,
    "creat": 0.005, "unlink": 0.005, "rename": 0.005,
    "socket": 0.005, "connect": 0.005, "accept": 0.005,
    "exit": 0.003, "wait": 0.003, "kill": 0.003,
    "getpid": 0.002, "getppid": 0.002, "brk": 0.002,
    "sbrk": 0.001, "mprotect": 0.001,
    "bind": 0.001, "listen": 0.001,
    "nanosleep": 0.002, "usleep": 0.002
}

SYSCALL_LIST = list(BASE_FREQUENCY.keys())
SYSCALL_WEIGHTS = list(BASE_FREQUENCY.values())

LATENCY_RANGES = {
    "read": (0.1, 5.0),
    "write": (0.1, 8.0),
    "open": (1.0, 20.0),
    "close": (0.05, 2.0),
    "recv": (0.5, 15.0),
    "send": (0.5, 10.0),
    "mmap": (0.1, 3.0),
    "munmap": (0.05, 1.0),
}
DEFAULT_LATENCY_RANGE = (0.01, 2.0)
MIN_LATENCY = 0.001


class SyscallSimulator:
    def __init__(self):
        self.calls_per_second = 8000
        self.variation = 0.4
        self.load_phases = [1.0, 1.5, 0.7, 1.2, 0.9, 1.3]
        self.phase_index = 0
        self.phase_duration = 60
        self.phase_start = time.time()

    def _update_phase(self):
        now = time.time()
        if now - self.phase_start > self.phase_duration:
            self.phase_index = (self.phase_index + 1) % len(self.load_phases)
            self.phase_start = now

    def _safe_latency(self, syscall: str) -> float:
        lo, hi = LATENCY_RANGES.get(syscall, DEFAULT_LATENCY_RANGE)
        val = random.uniform(lo, hi)
        if random.random() < 0.001:
            val *= random.uniform(10, 100)
        return max(abs(val), MIN_LATENCY)

    def generate_aggregated(self) -> Tuple[int, float, Dict[str, Tuple[int, float]], Dict[str, Tuple[int, float]]]:
        self._update_phase()
        load_multiplier = self.load_phases[self.phase_index]
        base_calls = int(self.calls_per_second * load_multiplier)
        variation = random.uniform(1 - self.variation, 1 + self.variation)
        num_calls = max(1, int(base_calls * variation))

        per_syscall_count: Dict[str, int] = defaultdict(int)
        per_syscall_time: Dict[str, float] = defaultdict(float)
        per_category_count: Dict[str, int] = defaultdict(int)
        per_category_time: Dict[str, float] = defaultdict(float)

        total_count = 0
        total_time = 0.0

        chosen = random.choices(SYSCALL_LIST, weights=SYSCALL_WEIGHTS, k=num_calls)

        for syscall in chosen:
            latency = self._safe_latency(syscall)

            per_syscall_count[syscall] += 1
            per_syscall_time[syscall] += latency

            category = CATEGORY_MAP.get(syscall, "file_ops")
            per_category_count[category] += 1
            per_category_time[category] += latency

            total_count += 1
            total_time += latency

        per_syscall: Dict[str, Tuple[int, float]] = {
            s: (per_syscall_count[s], per_syscall_time[s])
            for s in per_syscall_count
        }
        per_category: Dict[str, Tuple[int, float]] = {
            c: (per_category_count[c], per_category_time[c])
            for c in per_category_count
        }

        return total_count, total_time, per_syscall, per_category


class DataAggregator:
    def __init__(self, retention_seconds=300):
        self.retention_seconds = retention_seconds
        self.history: Deque[dict] = deque()
        self.simulator = SyscallSimulator()

        self._lock = threading.Lock()
        self._pending: Optional[dict] = None
        self._thread = threading.Thread(target=self._producer_loop, daemon=True)
        self._thread.start()

    def _producer_loop(self):
        next_tick = time.time()
        while True:
            next_tick += 1.0
            try:
                data = self._collect_and_aggregate()
                with self._lock:
                    self._pending = data
            except Exception as e:
                print(f"[Aggregator] Producer error: {e}")

            sleep_time = next_tick - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)
            else:
                drift = -sleep_time
                if drift > 2.0:
                    print(f"[Aggregator] Drift detected: {drift:.2f}s, skipping {int(drift)} frames")
                    next_tick += int(drift)

    def _collect_and_aggregate(self) -> dict:
        total_count, total_time, per_syscall_raw, per_category_raw = self.simulator.generate_aggregated()

        per_syscall = {
            s: {"count": c, "total_time": round(t, 4)}
            for s, (c, t) in per_syscall_raw.items()
        }
        per_category = {
            cat: {"count": c, "total_time": round(t, 4)}
            for cat, (c, t) in per_category_raw.items()
        }

        current_data = {
            "timestamp": time.time(),
            "datetime": datetime.now().isoformat(timespec="seconds"),
            "total_count": total_count,
            "total_time": round(total_time, 4),
            "per_syscall": per_syscall,
            "per_category": per_category,
            "rate": total_count
        }

        self.history.append(current_data)
        self._clean_old_data()

        return current_data

    def _clean_old_data(self):
        cutoff = time.time() - self.retention_seconds
        while self.history and self.history[0]["timestamp"] < cutoff:
            self.history.popleft()

    async def collect_and_aggregate(self) -> Optional[dict]:
        for _ in range(50):
            with self._lock:
                data = self._pending
                self._pending = None
            if data is not None:
                return data
            await asyncio.sleep(0.02)
        return None

    def get_history_summary(self, compact: bool = True):
        if not self.history:
            return {"windows": [], "total_count": 0, "total_time": 0, "window_count": 0}

        total_count = sum(d["total_count"] for d in self.history)
        total_time = sum(d["total_time"] for d in self.history)

        if compact:
            windows = [
                {
                    "t": round(d["timestamp"]),
                    "c": d["total_count"],
                    "pc": d["per_category"]
                }
                for d in self.history
            ]
        else:
            windows = list(self.history)

        return {
            "windows": windows,
            "total_count": total_count,
            "total_time": round(total_time, 4),
            "window_count": len(self.history)
        }


class WebSocketServer:
    def __init__(self, host="localhost", port=8765, http_port=8000):
        self.host = host
        self.port = port
        self.http_port = http_port
        self.aggregator = DataAggregator(retention_seconds=300)
        self.clients: set = set()
        self.current_data = None
        self._last_message = None

    async def broadcast(self, websocket):
        self.clients.add(websocket)
        try:
            history = self.aggregator.get_history_summary(compact=True)
            try:
                await websocket.send(json.dumps({
                    "type": "history",
                    "data": history
                }))
            except Exception:
                pass

            if self.current_data:
                try:
                    await websocket.send(json.dumps({
                        "type": "update",
                        "data": self.current_data
                    }))
                except Exception:
                    pass

            async for _ in websocket:
                pass
        finally:
            self.clients.discard(websocket)

    async def _send_to_client(self, client, message):
        try:
            await client.send(message)
            return True
        except Exception:
            return False

    async def aggregate_loop(self):
        print("[AggregateLoop] Starting")
        while True:
            data = await self.aggregator.collect_and_aggregate()
            if data is None:
                await asyncio.sleep(0.1)
                continue

            self.current_data = data
            message = json.dumps({"type": "update", "data": data})
            self._last_message = message

            if self.clients:
                tasks = [self._send_to_client(c, message) for c in list(self.clients)]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                disconnected = set()
                for client, ok in zip(list(self.clients), results):
                    if ok is not True:
                        disconnected.add(client)
                if disconnected:
                    self.clients -= disconnected
                    if disconnected:
                        print(f"[Broadcast] Dropped {len(disconnected)} client(s)")

    async def http_server(self):
        from aiohttp import web

        async def handle_index(request):
            with open("index.html", "rb") as f:
                return web.Response(body=f.read(), content_type="text/html")

        app = web.Application()
        app.router.add_get("/", handle_index)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.http_port)
        await site.start()
        print(f"HTTP server running at http://{self.host}:{self.http_port}")

    async def start(self):
        await asyncio.gather(
            websockets.serve(self.broadcast, self.host, self.port),
            self.aggregate_loop(),
            self.http_server()
        )


async def main():
    server = WebSocketServer(host="0.0.0.0", port=8765, http_port=8000)
    print(f"WebSocket server starting on ws://0.0.0.0:8765")
    await server.start()
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
