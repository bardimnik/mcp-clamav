import base64
import os
import stat
import subprocess
import sys
import types
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main


GOOD_B64 = base64.b64encode(b"hello").decode()


def _ok_result(stdout="OK", stderr=""):
    return subprocess.CompletedProcess(args=["clamscan"], returncode=0, stdout=stdout, stderr=stderr)


class TestSanitizeFilename:
    def test_basename_with_slashes(self):
        assert main._sanitize_filename("a/b/c.txt") == "c.txt"

    def test_basename_with_backslashes(self):
        assert main._sanitize_filename("a\\b\\c.txt") == "c.txt"

    def test_dotdot_rejected(self):
        with pytest.raises(ValueError):
            main._sanitize_filename("..")

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            main._sanitize_filename("")

    def test_control_chars_rejected(self):
        for bad in ["a\nb", "a\rb", "a\x00b", "a\tb", "a\x7fb"]:
            with pytest.raises(ValueError):
                main._sanitize_filename(bad)

    def test_leading_dot_rejected(self):
        with pytest.raises(ValueError):
            main._sanitize_filename(".hidden")

    def test_long_name_truncated(self):
        long_name = "a" * 300 + ".txt"
        assert len(main._sanitize_filename(long_name)) == 255

    def test_non_string_rejected(self):
        with pytest.raises(ValueError):
            main._sanitize_filename(123)


class TestInputValidation:
    def test_oversized_input_rejected(self, monkeypatch):
        monkeypatch.setattr(main, "MAX_B64_LEN", 5)
        out = main.scan_file(GOOD_B64, "file.txt")
        assert out["success"] is False
        assert "large" in out["error"]

    def test_invalid_base64_rejected(self):
        out = main.scan_file("!!!not-base64!!!", "file.txt")
        assert out["success"] is False
        assert out["error"] == "invalid base64 input"

    def test_bad_filename_rejected_before_decode(self):
        for bad in ["..", ".", ".hidden", "a\nb", "a\x00b"]:
            out = main.scan_file(GOOD_B64, bad)
            assert out["success"] is False
            assert "invalid filename" in out["error"]

    def test_path_like_filename_is_basename_only(self, monkeypatch):
        # "../evil" is sanitized to a safe basename and scan proceeds
        monkeypatch.setattr(main.subprocess, "run", lambda *a, **kw: _ok_result(stdout="ok"))
        monkeypatch.setattr(main.os.path, "exists", lambda p: False)
        out = main.scan_file(GOOD_B64, "../evil")
        assert out["success"] is True
        assert "invalid filename" not in str(out.get("error", ""))

    def test_non_string_base64_rejected(self):
        out = main.scan_file(12345, "file.txt")
        assert out["success"] is False


class TestScanFlow:
    def test_success_path(self, monkeypatch, tmp_path):
        created = []

        class FakeTempFile:
            def __init__(self, path):
                self.path = path

            def __init__(self, path):
                self.path = path
                self.name = path

            def __enter__(self):
                created.append(self.path)
                return self

            def __exit__(self, *a):
                return False

            def write(self, data):
                with open(self.path, "wb") as f:
                    f.write(data)

        target = str(tmp_path / "_test_scan_file")
        monkeypatch.setattr(main.tempfile, "NamedTemporaryFile", lambda *a, **kw: FakeTempFile(target))
        monkeypatch.setattr(main.os.path, "exists", lambda p: True)
        monkeypatch.setattr(main.os, "unlink", lambda p: None)
        monkeypatch.setattr(main.subprocess, "run", lambda *a, **kw: _ok_result(stdout="scan ok"))

        out = main.scan_file(GOOD_B64, "file.txt")
        assert out["success"] is True
        assert out["result"] == "scan ok"

    def test_temp_file_permissions_0600(self, monkeypatch):
        captured = {}

        def fake_run(*a, **kw):
            path = a[0][1]
            captured["path"] = path
            captured["mode"] = stat.S_IMODE(os.stat(path).st_mode)
            return _ok_result(stdout="ok")

        monkeypatch.setattr(main.subprocess, "run", fake_run)
        out = main.scan_file(GOOD_B64, "file.txt")
        assert out["success"] is True
        assert captured["mode"] == 0o600

    def test_output_truncated(self, monkeypatch):
        monkeypatch.setattr(main, "MAX_OUTPUT_BYTES", 10)
        monkeypatch.setattr(main.subprocess, "run", lambda *a, **kw: _ok_result(stdout="x" * 100))
        monkeypatch.setattr(main.os.path, "exists", lambda p: False)
        out = main.scan_file(GOOD_B64, "file.txt")
        assert out["success"] is True
        assert "truncated" in out["result"]
        assert len(out["result"]) < 100

    def test_timeout(self, monkeypatch):
        def raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="clamscan", timeout=120)
        monkeypatch.setattr(main.subprocess, "run", raise_timeout)
        monkeypatch.setattr(main.os.path, "exists", lambda p: False)
        out = main.scan_file(GOOD_B64, "file.txt")
        assert out["success"] is False
        assert out["error"] == "scan timed out"

    def test_scanner_unavailable(self, monkeypatch):
        def raise_fnf(*a, **kw):
            raise FileNotFoundError("clamscan")
        monkeypatch.setattr(main.subprocess, "run", raise_fnf)
        monkeypatch.setattr(main.os.path, "exists", lambda p: False)
        out = main.scan_file(GOOD_B64, "file.txt")
        assert out["success"] is False
        assert out["error"] == "scanner unavailable"

    def test_cleanup_failure_does_not_mask(self, monkeypatch):
        monkeypatch.setattr(main.subprocess, "run", lambda *a, **kw: _ok_result(stdout="ok"))
        monkeypatch.setattr(main.os.path, "exists", lambda p: True)
        monkeypatch.setattr(main.os, "unlink", lambda p: (_ for _ in ()).throw(OSError("nope")))
        out = main.scan_file(GOOD_B64, "file.txt")
        assert out["success"] is True
        assert out["result"] == "ok"

    def test_error_does_not_leak_exception_details(self, monkeypatch):
        def raise_exc(*a, **kw):
            raise RuntimeError("internal secret details")
        monkeypatch.setattr(main.subprocess, "run", raise_exc)
        monkeypatch.setattr(main.os.path, "exists", lambda p: False)
        out = main.scan_file(GOOD_B64, "file.txt")
        assert out["success"] is False
        assert "secret" not in out["error"]
