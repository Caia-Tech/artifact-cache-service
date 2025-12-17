import importlib.util
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def _load_server_module(path: Path):
    spec = importlib.util.spec_from_file_location("artifact_cache_server", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["artifact_cache_server"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_local_paths_disabled_by_default(tmp_path, monkeypatch):
    server_path = Path(__file__).resolve().parents[1] / "server.py"
    onyx_cache = _load_server_module(server_path)

    onyx_cache.CACHE_DIR = tmp_path / "cache"
    onyx_cache.ALLOW_LOCAL_PATHS = False
    onyx_cache.ALLOWED_PATH_PREFIXES = str(tmp_path)

    p = tmp_path / "x.bin"
    p.write_bytes(b"abc")

    with TestClient(onyx_cache.app) as client:
        r = client.post("/resolve", json={"artifact_uri": str(p)})
        assert r.status_code == 400
        assert "Local paths are disabled" in r.text


def test_local_resolve_computes_sha_and_size(tmp_path, monkeypatch):
    server_path = Path(__file__).resolve().parents[1] / "server.py"
    onyx_cache = _load_server_module(server_path)

    onyx_cache.CACHE_DIR = tmp_path / "cache"
    onyx_cache.ALLOW_LOCAL_PATHS = True
    onyx_cache.ALLOWED_PATH_PREFIXES = str(tmp_path)

    p = tmp_path / "x.bin"
    p.write_bytes(b"abc")

    with TestClient(onyx_cache.app) as client:
        r = client.post("/resolve", json={"artifact_uri": str(p)})
        assert r.status_code == 200
        data = r.json()
        assert data["local_path"] == str(p)
        assert data["size_bytes"] == 3
        assert isinstance(data["sha256"], str) and len(data["sha256"]) == 64
        assert data["cached"] is True


def test_s3_requires_sha_and_size(tmp_path):
    server_path = Path(__file__).resolve().parents[1] / "server.py"
    onyx_cache = _load_server_module(server_path)
    onyx_cache.CACHE_DIR = tmp_path / "cache"

    with TestClient(onyx_cache.app) as client:
        r = client.post("/resolve", json={"artifact_uri": "s3://bucket/key"})
        assert r.status_code == 400
        assert "require sha256 and size_bytes" in r.text


def test_s3_returns_cached_without_downloading(tmp_path, monkeypatch):
    server_path = Path(__file__).resolve().parents[1] / "server.py"
    onyx_cache = _load_server_module(server_path)

    onyx_cache.CACHE_DIR = tmp_path / "cache"
    onyx_cache.S3_ENDPOINT_URL = "http://example.invalid"

    sha = "a" * 64
    data = b"hello"
    dest = (onyx_cache.CACHE_DIR / "sha256" / sha)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)

    def _boom():
        raise AssertionError("should not call s3 client when cached")

    monkeypatch.setattr(onyx_cache, "_s3_client", _boom)

    with TestClient(onyx_cache.app) as client:
        r = client.post("/resolve", json={"artifact_uri": "s3://bucket/key", "sha256": sha, "size_bytes": len(data)})
        assert r.status_code == 200
        out = r.json()
        assert out["cached"] is True
        assert out["local_path"] == str(dest)


def test_s3_downloads_and_verifies(tmp_path, monkeypatch):
    server_path = Path(__file__).resolve().parents[1] / "server.py"
    onyx_cache = _load_server_module(server_path)

    onyx_cache.CACHE_DIR = tmp_path / "cache"
    onyx_cache.S3_ENDPOINT_URL = "http://example.invalid"

    data = b"downloaded-bytes"
    import hashlib

    sha = hashlib.sha256(data).hexdigest()

    class Body:
        def __init__(self, b: bytes):
            self._b = b
            self._i = 0

        def read(self, n: int):
            if self._i >= len(self._b):
                return b""
            chunk = self._b[self._i : self._i + n]
            self._i += len(chunk)
            return chunk

    class S3:
        def get_object(self, Bucket, Key):  # noqa: N802
            _ = (Bucket, Key)
            return {"Body": Body(data)}

    monkeypatch.setattr(onyx_cache, "_s3_client", lambda: S3())

    with TestClient(onyx_cache.app) as client:
        r = client.post("/resolve", json={"artifact_uri": "s3://bucket/key", "sha256": sha, "size_bytes": len(data)})
        assert r.status_code == 200
        out = r.json()
        assert out["cached"] is False
        assert out["local_path"].endswith(sha)
        assert Path(out["local_path"]).read_bytes() == data

