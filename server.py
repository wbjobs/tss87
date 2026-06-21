import asyncio
import websockets
import json
import random
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Deque

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

    def generate_syscall(self):
        self._update_phase()
        load_multiplier = self.load_phases[self.phase_index]
        base_calls = int(self.calls_per_second * load_multiplier)
        variation = random.uniform(1 - self.variation, 1 + self.variation)
        num_calls = int(base_calls * variation)
        
        calls = []
        for _ in range(num_calls):
            syscall = random.choices(
                list(BASE_FREQUENCY.keys()),
                weights=list(BASE_FREQUENCY.values()),
                k=1
            )[0]
            
            base_latency = {
                "read": random.uniform(0.1, 5.0),
                "write": random.uniform(0.1, 8.0),
                "open": random.uniform(1.0, 20.0),
                "close": random.uniform(0.05, 2.0),
                "recv": random.uniform(0.5, 15.0),
                "send": random.uniform(0.5, 10.0),
                "mmap": random.uniform(0.1, 3.0),
                "munmap": random.uniform(0.05, 1.0),
            }.get(syscall, random.uniform(0.01, 2.0))
            
            if random.random() < 0.001:
                base_latency *= random.uniform(10, 100)
            
            calls.append((syscall, base_latency))
        
        return calls

class DataAggregator:
    def __init__(self, retention_seconds=300):
        self.retention_seconds = retention_seconds
        self.history: Deque[dict] = deque()
        self.simulator = SyscallSimulator()

    def _clean_old_data(self):
        cutoff = time.time() - self.retention_seconds
        while self.history and self.history[0]["timestamp"] < cutoff:
            self.history.popleft()

    async def collect_and_aggregate(self):
        calls = self.simulator.generate_syscall()
        
        per_syscall: Dict[str, Dict] = defaultdict(lambda: {"count": 0, "total_time": 0.0})
        per_category: Dict[str, Dict] = defaultdict(lambda: {"count": 0, "total_time": 0.0})
        
        total_count = 0
        total_time = 0.0
        
        for syscall, latency in calls:
            per_syscall[syscall]["count"] += 1
            per_syscall[syscall]["total_time"] += latency
            category = CATEGORY_MAP.get(syscall, "other")
            per_category[category]["count"] += 1
            per_category[category]["total_time"] += latency
            total_count += 1
            total_time += latency
        
        current_data = {
            "timestamp": time.time(),
            "datetime": datetime.now().isoformat(),
            "total_count": total_count,
            "total_time": total_time,
            "per_syscall": dict(per_syscall),
            "per_category": dict(per_category),
            "rate": total_count
        }
        
        self.history.append(current_data)
        self._clean_old_data()
        
        return current_data

    def get_history_summary(self):
        if not self.history:
            return {"windows": [], "total_count": 0, "total_time": 0}
        
        total_count = sum(d["total_count"] for d in self.history)
        total_time = sum(d["total_time"] for d in self.history)
        
        return {
            "windows": list(self.history),
            "total_count": total_count,
            "total_time": total_time,
            "window_count": len(self.history)
        }

class WebSocketServer:
    def __init__(self, host="localhost", port=8765, http_port=8000):
        self.host = host
        self.port = port
        self.http_port = http_port
        self.aggregator = DataAggregator(retention_seconds=300)
        self.clients = set()
        self.current_data = None

    async def broadcast(self, websocket):
        self.clients.add(websocket)
        try:
            history = self.aggregator.get_history_summary()
            await websocket.send(json.dumps({
                "type": "history",
                "data": history
            }))
            
            if self.current_data:
                await websocket.send(json.dumps({
                    "type": "update",
                    "data": self.current_data
                }))
            
            async for message in websocket:
                pass
        finally:
            self.clients.remove(websocket)

    async def aggregate_loop(self):
        while True:
            self.current_data = await self.aggregator.collect_and_aggregate()
            message = json.dumps({
                "type": "update",
                "data": self.current_data
            })
            
            if self.clients:
                disconnected = set()
                for client in self.clients:
                    try:
                        await client.send(message)
                    except Exception:
                        disconnected.add(client)
                
                self.clients -= disconnected
            
            await asyncio.sleep(1.0)

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
