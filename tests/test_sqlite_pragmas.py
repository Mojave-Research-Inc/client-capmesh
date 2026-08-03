"""
Test suite for SQLite pragma enhancements in capmesh.index.connect().

Validates:
- Default values are applied correctly
- Environment variable overrides work as expected
- Invalid environment values fall back to defaults
- Allowlist validation enforces OFF/NORMAL/FULL/EXTRA for synchronous pragma
- All PRAGMA statements execute successfully
- No other functions were modified
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from capmesh.index import ThreadLocalConnection, connect, init_db


class TestSQLitePragmas:
    """Test SQLite pragma configuration in connect()."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database file."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        yield Path(path)
        # Cleanup
        if Path(path).exists():
            Path(path).unlink()

    def test_default_pragmas_applied(self, temp_db_path, monkeypatch):
        """Test that default pragma values are applied when no env vars set."""
        # Clear all relevant env vars
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)

        # Query the pragma values
        synchronous = con.execute("PRAGMA synchronous").fetchone()[0]
        cache_size = con.execute("PRAGMA cache_size").fetchone()[0]
        mmap_size = con.execute("PRAGMA mmap_size").fetchone()[0]
        temp_store = con.execute("PRAGMA temp_store").fetchone()[0]

        con.close()

        # Verify defaults: synchronous mode names map to integer values
        # NORMAL = 1, so we check for that value
        assert synchronous == 1, f"Expected synchronous=NORMAL (1), got {synchronous}"
        assert cache_size == -131072, f"Expected cache_size=-131072, got {cache_size}"
        assert mmap_size == 1073741824, f"Expected mmap_size=1073741824 (1GB), got {mmap_size}"
        assert temp_store == 2, f"Expected temp_store=MEMORY (2), got {temp_store}"

    def test_request_scoped_connection_is_released(self, temp_db_path):
        pool = ThreadLocalConnection(temp_db_path, check_same_thread=False)
        assert pool.execute("SELECT 1").fetchone()[0] == 1
        assert len(pool._all_connections) == 1
        pool.close_current()
        assert len(pool._all_connections) == 0
        assert pool.execute("SELECT 1").fetchone()[0] == 1
        pool.close()

    def test_sqlite_vec_is_loaded_on_subsequent_connections(self, temp_db_path):
        first = connect(temp_db_path)
        status = init_db(first, enable_vector=True)
        first.close()
        if not status["vector"]["enabled"]:
            pytest.skip("sqlite-vec extension is unavailable")
        second = connect(temp_db_path)
        try:
            second.execute("SELECT COUNT(*) FROM capability_vec").fetchone()
        finally:
            second.close()

    def test_synchronous_override_valid(self, temp_db_path, monkeypatch):
        """Test that CAPMESH_SYNCHRONOUS env var overrides default."""
        for mode_name, mode_int in [("OFF", 0), ("NORMAL", 1), ("FULL", 2), ("EXTRA", 3)]:
            monkeypatch.setenv("CAPMESH_SYNCHRONOUS", mode_name)
            monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
            monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
            monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

            con = connect(temp_db_path)
            synchronous = con.execute("PRAGMA synchronous").fetchone()[0]
            con.close()

            assert synchronous == mode_int, f"Expected {mode_name}={mode_int}, got {synchronous}"

    def test_synchronous_override_invalid_fallback(self, temp_db_path, monkeypatch):
        """Test that invalid CAPMESH_SYNCHRONOUS falls back to NORMAL."""
        monkeypatch.setenv("CAPMESH_SYNCHRONOUS", "INVALID_MODE")
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        synchronous = con.execute("PRAGMA synchronous").fetchone()[0]
        con.close()

        # Should fall back to NORMAL = 1
        assert synchronous == 1, f"Expected fallback to NORMAL (1), got {synchronous}"

    def test_synchronous_case_insensitive(self, temp_db_path, monkeypatch):
        """Test that synchronous mode is case-insensitive."""
        monkeypatch.setenv("CAPMESH_SYNCHRONOUS", "full")  # lowercase
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        synchronous = con.execute("PRAGMA synchronous").fetchone()[0]
        con.close()

        # Should match FULL = 2
        assert synchronous == 2, f"Expected FULL (2) case-insensitive, got {synchronous}"

    def test_cache_size_override_valid(self, temp_db_path, monkeypatch):
        """Test that CAPMESH_CACHE_SIZE env var overrides default."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.setenv("CAPMESH_CACHE_SIZE", "-262144")  # 256 MiB
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        cache_size = con.execute("PRAGMA cache_size").fetchone()[0]
        con.close()

        assert cache_size == -262144, f"Expected cache_size=-262144, got {cache_size}"

    def test_cache_size_override_invalid_fallback(self, temp_db_path, monkeypatch):
        """Test that invalid CAPMESH_CACHE_SIZE falls back to default."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.setenv("CAPMESH_CACHE_SIZE", "not_a_number")
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        cache_size = con.execute("PRAGMA cache_size").fetchone()[0]
        con.close()

        # Should fall back to default
        assert cache_size == -131072, f"Expected fallback to -131072, got {cache_size}"

    def test_mmap_size_override_valid(self, temp_db_path, monkeypatch):
        """Test that CAPMESH_MMAP_SIZE env var overrides default."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.setenv("CAPMESH_MMAP_SIZE", "536870912")  # 512 MiB
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        mmap_size = con.execute("PRAGMA mmap_size").fetchone()[0]
        con.close()

        assert mmap_size == 536870912, f"Expected mmap_size=536870912, got {mmap_size}"

    def test_mmap_size_override_invalid_fallback(self, temp_db_path, monkeypatch):
        """Test that invalid CAPMESH_MMAP_SIZE falls back to default."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.setenv("CAPMESH_MMAP_SIZE", "not_a_number")
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        mmap_size = con.execute("PRAGMA mmap_size").fetchone()[0]
        con.close()

        # Should fall back to default (1 GB)
        assert mmap_size == 1073741824, f"Expected fallback to 1073741824, got {mmap_size}"

    def test_temp_store_memory_unconditional(self, temp_db_path, monkeypatch):
        """Test that temp_store is always set to MEMORY."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        temp_store = con.execute("PRAGMA temp_store").fetchone()[0]
        con.close()

        # temp_store=MEMORY returns 2
        assert temp_store == 2, f"Expected temp_store=MEMORY (2), got {temp_store}"

    def test_wal_pragma_unchanged(self, temp_db_path, monkeypatch):
        """Test that WAL journal mode is still applied."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        journal_mode = con.execute("PRAGMA journal_mode").fetchone()[0]
        con.close()

        assert journal_mode.lower() == "wal", f"Expected journal_mode=WAL, got {journal_mode}"

    def test_foreign_keys_pragma_unchanged(self, temp_db_path, monkeypatch):
        """Test that foreign_keys pragma is still applied."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        foreign_keys = con.execute("PRAGMA foreign_keys").fetchone()[0]
        con.close()

        assert foreign_keys == 1, f"Expected foreign_keys=1 (ON), got {foreign_keys}"

    def test_all_pragmas_execute_successfully(self, temp_db_path, monkeypatch):
        """Test that all pragmas execute without error."""
        monkeypatch.setenv("CAPMESH_SYNCHRONOUS", "FULL")
        monkeypatch.setenv("CAPMESH_CACHE_SIZE", "-262144")
        monkeypatch.setenv("CAPMESH_MMAP_SIZE", "536870912")
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)

        # Execute all pragma queries to verify they work
        pragmas = {
            "journal_mode": con.execute("PRAGMA journal_mode").fetchone()[0],
            "foreign_keys": con.execute("PRAGMA foreign_keys").fetchone()[0],
            "synchronous": con.execute("PRAGMA synchronous").fetchone()[0],
            "cache_size": con.execute("PRAGMA cache_size").fetchone()[0],
            "mmap_size": con.execute("PRAGMA mmap_size").fetchone()[0],
            "temp_store": con.execute("PRAGMA temp_store").fetchone()[0],
        }

        con.close()

        # All pragmas should have been set (non-None values)
        for pragma_name, pragma_value in pragmas.items():
            assert pragma_value is not None, f"Pragma {pragma_name} returned None"

    def test_connection_row_factory_set(self, temp_db_path, monkeypatch):
        """Test that row_factory is still set to sqlite3.Row."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)

        # row_factory should be set to sqlite3.Row
        assert con.row_factory is sqlite3.Row, f"Expected row_factory=sqlite3.Row, got {con.row_factory}"

        con.close()

    def test_no_string_interpolation_in_pragmas(self, temp_db_path, monkeypatch):
        """Test that pragmas use safe integer interpolation (not raw strings)."""
        # Set values to verify they're interpolated safely (within SQLite limits)
        monkeypatch.setenv("CAPMESH_CACHE_SIZE", "9999999")
        monkeypatch.setenv("CAPMESH_MMAP_SIZE", "2097152000")  # ~2 GB (within SQLite limits)
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        cache_size = con.execute("PRAGMA cache_size").fetchone()[0]
        mmap_size = con.execute("PRAGMA mmap_size").fetchone()[0]
        con.close()

        # Values should be exactly what we set (SQLite may clamp internally, but it accepts the input)
        assert cache_size == 9999999
        assert mmap_size == 2097152000

    def test_zero_cache_size_valid(self, temp_db_path, monkeypatch):
        """Test that zero cache_size is allowed."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.setenv("CAPMESH_CACHE_SIZE", "0")
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        cache_size = con.execute("PRAGMA cache_size").fetchone()[0]
        con.close()

        assert cache_size == 0, f"Expected cache_size=0, got {cache_size}"

    def test_negative_cache_size_valid(self, temp_db_path, monkeypatch):
        """Test that negative cache_size (memory in KB) is allowed."""
        monkeypatch.delenv("CAPMESH_SYNCHRONOUS", raising=False)
        monkeypatch.setenv("CAPMESH_CACHE_SIZE", "-65536")  # 64 MiB
        monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
        monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

        con = connect(temp_db_path)
        cache_size = con.execute("PRAGMA cache_size").fetchone()[0]
        con.close()

        assert cache_size == -65536, f"Expected cache_size=-65536, got {cache_size}"

    def test_synchronous_allowlist_comprehensive(self, temp_db_path, monkeypatch):
        """Test comprehensive allowlist enforcement for synchronous."""
        invalid_modes = ["INVALID", "0", "1", "2", "", "off", "normal"]  # lowercase checked separately

        for invalid_mode in invalid_modes:
            if invalid_mode in ("off", "normal"):
                continue  # Already tested case-insensitivity

            monkeypatch.setenv("CAPMESH_SYNCHRONOUS", invalid_mode)
            monkeypatch.delenv("CAPMESH_CACHE_SIZE", raising=False)
            monkeypatch.delenv("CAPMESH_MMAP_SIZE", raising=False)
            monkeypatch.delenv("CAPMESH_BUSY_TIMEOUT_MS", raising=False)

            con = connect(temp_db_path)
            synchronous = con.execute("PRAGMA synchronous").fetchone()[0]
            con.close()

            # Should fall back to NORMAL = 1
            assert synchronous == 1, f"Invalid mode '{invalid_mode}' did not fall back to NORMAL"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
