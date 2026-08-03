from __future__ import annotations

import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from capmesh.index import connect, init_db


class ServerShutdownTests(unittest.TestCase):
    def test_sigterm_exits_promptly_while_another_wal_reader_is_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mesh.db"
            con = connect(db)
            init_db(con, enable_vector=False)
            con.close()

            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]

            env = os.environ.copy()
            env.update(
                {
                    "CAPMESH_BUSY_TIMEOUT_MS": "5000",
                    "CAPMESH_REQUIRE_SAFE_SQLITE": "0",
                    "CAPMESH_ROOTS": tmp,
                }
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "capmesh",
                    "--db",
                    str(db),
                    "serve-http",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            blocker: sqlite3.Connection | None = None
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        self.fail(f"server exited during startup with {process.returncode}")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail("server did not become ready")
                        time.sleep(0.05)

                blocker = sqlite3.connect(db)
                blocker.execute("PRAGMA journal_mode=WAL")
                blocker.execute("BEGIN")
                blocker.execute("SELECT COUNT(*) FROM capabilities").fetchone()

                writer = sqlite3.connect(db)
                try:
                    writer.execute(
                        "INSERT INTO meta(key, value) VALUES('shutdown-test', '1') "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
                    )
                    writer.commit()
                finally:
                    writer.close()

                started = time.monotonic()
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=3)
                elapsed = time.monotonic() - started
                self.assertEqual(process.returncode, 0)
                self.assertLess(elapsed, 3.0)
            finally:
                if blocker is not None:
                    blocker.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
