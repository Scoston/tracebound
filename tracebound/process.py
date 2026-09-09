"""Bounded child processes; credentials only enter the process that needs them."""

import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

from .common import MAX_MESSAGE, canonical, decode


class Child:
    def __init__(self, module, config, variable):
        env = {k: v for k, v in os.environ.items() if k in (
            "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL")}
        env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
        env[variable] = canonical(config).decode()
        self.process = subprocess.Popen([sys.executable, "-u", "-m", module],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=env, bufsize=0)
        self.lines = queue.Queue(maxsize=20)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while True:
            raw = self.process.stdout.readline(MAX_MESSAGE + 1)
            try:
                self.lines.put(raw, timeout=1)
            except queue.Full:
                return
            if not raw or len(raw) > MAX_MESSAGE:
                return

    def receive(self):
        try:
            raw = self.lines.get(timeout=5)
        except queue.Empty as error:
            raise TimeoutError("local child response timed out") from error
        if not raw:
            raise RuntimeError("local child exited unexpectedly")
        return decode(raw)

    def send(self, message):
        raw = canonical(message) + b"\n"
        if len(raw) > MAX_MESSAGE:
            raise ValueError("protocol message exceeds limit")
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        for stream in (self.process.stdin, self.process.stdout):
            stream.close()
        self.reader.join(timeout=1)

