"""Integration tests against the real clamscan binary.

Run with: uv run pytest tests/test_integration.py -m integration
Skipped automatically when clamscan is not on PATH.
"""

import base64
import os
import shutil
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main

pytestmark = pytest.mark.integration

CLAMSCAN = shutil.which("clamscan")


@pytest.mark.skipif(CLAMSCAN is None, reason="clamscan not available")
class TestIntegration:
    def test_clean_file_scan(self):
        payload = b"hello world, this is a harmless test file\n"
        out = main.scan_file(base64.b64encode(payload).decode(), "test.txt")
        assert out["success"] is True
        assert "FOUND" not in out["result"]

    def test_temp_file_cleaned_up(self, monkeypatch):
        created = []
        original = main.tempfile.NamedTemporaryFile

        class TrackingTempFile:
            def __init__(self, *args, **kwargs):
                self._real = original(*args, **kwargs)

            def __enter__(self):
                self._real.__enter__()
                created.append(self._real.name)
                return self

            def __exit__(self, *a):
                self._real.__exit__(*a)
                return False

            def write(self, data):
                return self._real.write(data)

            @property
            def name(self):
                return self._real.name

        monkeypatch.setattr(main.tempfile, "NamedTemporaryFile", TrackingTempFile)
        out = main.scan_file(base64.b64encode(b"clean payload\n").decode(), "test.txt")
        assert out["success"] is True
        assert len(created) == 1
        assert not os.path.exists(created[0])

    def test_temp_file_permissions_0600(self, monkeypatch):
        modes = []
        original = main.tempfile.NamedTemporaryFile

        class PermTempFile:
            def __init__(self, *args, **kwargs):
                self._real = original(*args, **kwargs)

            def __enter__(self):
                self._real.__enter__()
                modes.append(stat.S_IMODE(os.stat(self._real.name).st_mode))
                return self

            def __exit__(self, *a):
                self._real.__exit__(*a)
                return False

            def write(self, data):
                return self._real.write(data)

            @property
            def name(self):
                return self._real.name

        monkeypatch.setattr(main.tempfile, "NamedTemporaryFile", PermTempFile)
        out = main.scan_file(base64.b64encode(b"clean payload\n").decode(), "test.txt")
        assert out["success"] is True
        assert len(modes) == 1
        assert modes[0] == 0o600
