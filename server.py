import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any, Dict, Tuple
from urllib.parse import urlparse

import boto3
from botocore.config import Config as BotoConfig
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ConfigDict


def _env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default) == "1"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


CACHE_DIR = Path(os.environ.get("ARTIFACT_CACHE_DIR", "./cache")).expanduser().resolve()
MAX_HASH_BYTES = _env_int("ARTIFACT_MAX_HASH_BYTES", 268_435_456)
ALLOW_LOCAL_PATHS = _env_bool("ARTIFACT_ALLOW_LOCAL_PATHS", "0")
ALLOWED_PATH_PREFIXES = os.environ.get("ARTIFACT_ALLOWED_PATH_PREFIXES", str(Path(__file__).parent.resolve()))

S3_ENDPOINT_URL = os.environ.get("ARTIFACT_S3_ENDPOINT_URL") or None
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def _allowed_prefixes() -> list[Path]:
    prefixes: list[Path] = []
    for raw in (ALLOWED_PATH_PREFIXES or "").split(","):
        raw = raw.strip()
        if raw:
            prefixes.append(Path(raw).expanduser().resolve())
    return prefixes or [Path(__file__).parent.resolve()]


def _is_allowed_local_path(p: Path) -> bool:
    rp = p.expanduser().resolve()
    for base in _allowed_prefixes():
        try:
            rp.relative_to(base)
            return True
        except Exception:
            continue
    return False


def _normalize_local_path(raw: str) -> Path:
    s = (raw or "").strip()
    if s.startswith("file://"):
        s = s[len("file://") :]
    if "://" in s:
        raise HTTPException(status_code=400, detail=f"Unsupported artifact_uri scheme: {raw}")
    return Path(s).expanduser().resolve()


def _sha256_file(path: Path, *, max_bytes: int) -> Tuple[Optional[str], int]:
    size = path.stat().st_size
    if size > max_bytes:
        return None, size
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest(), size


@dataclass(frozen=True)
class S3Uri:
    bucket: str
    key: str


def _parse_s3(uri: str) -> S3Uri:
    if not uri.startswith("s3://"):
        raise ValueError("not s3")
    rest = uri[len("s3://") :]
    parts = rest.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("invalid s3 uri")
    return S3Uri(bucket=parts[0], key=parts[1])


def _s3_client():
    cfg = BotoConfig(
        region_name=AWS_REGION,
        retries={"max_attempts": 3, "mode": "standard"},
        s3={"addressing_style": "path"},
    )
    return boto3.client("s3", endpoint_url=S3_ENDPOINT_URL, config=cfg)


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_uri: str = Field(..., description="file path or s3://bucket/key")
    sha256: Optional[str] = Field(default=None, description="Expected sha256 (64 hex)")
    size_bytes: Optional[int] = Field(default=None, ge=0, description="Expected size in bytes")


class ResolveResponse(BaseModel):
    artifact_uri: str
    local_path: str
    sha256: str
    size_bytes: int
    cached: bool


app = FastAPI(title="Caia Artifact Cache", version="0.1.0")


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "cache_dir": str(CACHE_DIR),
        "allow_local_paths": bool(ALLOW_LOCAL_PATHS),
        "s3_endpoint_url": S3_ENDPOINT_URL,
    }


def _validate_sha256(s: str) -> str:
    candidate = s.strip().lower()
    if candidate.startswith("sha256:"):
        candidate = candidate.split(":", 1)[1].strip()
    if len(candidate) != 64 or any(c not in "0123456789abcdef" for c in candidate):
        raise HTTPException(status_code=400, detail="Invalid sha256 (expected 64 hex characters)")
    return candidate


def _cache_path_for_sha(sha: str) -> Path:
    return (CACHE_DIR / "sha256" / sha).resolve()


def _ensure_cache_dir():
    (CACHE_DIR / "sha256").mkdir(parents=True, exist_ok=True)


def _resolve_local(req: ResolveRequest) -> ResolveResponse:
    if not ALLOW_LOCAL_PATHS:
        raise HTTPException(status_code=400, detail="Local paths are disabled (set ARTIFACT_ALLOW_LOCAL_PATHS=1)")

    p = _normalize_local_path(req.artifact_uri)
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {p}")
    if not _is_allowed_local_path(p):
        raise HTTPException(status_code=400, detail=f"Path not allowed: {p}")

    sha_expected = _validate_sha256(req.sha256) if req.sha256 else None
    sha_actual, size = _sha256_file(p, max_bytes=MAX_HASH_BYTES)

    if req.size_bytes is not None and int(req.size_bytes) != int(size):
        raise HTTPException(status_code=400, detail="Size mismatch for local file")

    if sha_expected is not None:
        if sha_actual is None:
            raise HTTPException(status_code=400, detail="Local file too large to hash; increase ARTIFACT_MAX_HASH_BYTES")
        if sha_actual != sha_expected:
            raise HTTPException(status_code=400, detail="SHA256 mismatch for local file")
        sha_final = sha_expected
    else:
        if sha_actual is None:
            raise HTTPException(status_code=400, detail="sha256 required for large local files")
        sha_final = sha_actual

    return ResolveResponse(
        artifact_uri=req.artifact_uri,
        local_path=str(p),
        sha256=sha_final,
        size_bytes=int(size),
        cached=True,
    )


def _resolve_s3(req: ResolveRequest) -> ResolveResponse:
    if req.sha256 is None or req.size_bytes is None:
        raise HTTPException(status_code=400, detail="Remote artifacts require sha256 and size_bytes")
    sha_expected = _validate_sha256(req.sha256)
    size_expected = int(req.size_bytes)

    _ensure_cache_dir()
    dest = _cache_path_for_sha(sha_expected)
    if dest.exists():
        if dest.stat().st_size == size_expected:
            return ResolveResponse(
                artifact_uri=req.artifact_uri,
                local_path=str(dest),
                sha256=sha_expected,
                size_bytes=size_expected,
                cached=True,
            )
        dest.unlink(missing_ok=True)

    s3 = _s3_client()
    parsed = _parse_s3(req.artifact_uri)
    tmp = dest.with_suffix(".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)

    obj = s3.get_object(Bucket=parsed.bucket, Key=parsed.key)
    body = obj["Body"]

    h = hashlib.sha256()
    n = 0
    with tmp.open("wb") as f:
        while True:
            chunk = body.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)
            h.update(chunk)
            n += len(chunk)

    sha_actual = h.hexdigest()
    if n != size_expected:
        tmp.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Downloaded size mismatch")
    if sha_actual != sha_expected:
        tmp.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Downloaded sha256 mismatch")

    os.replace(tmp, dest)
    return ResolveResponse(
        artifact_uri=req.artifact_uri,
        local_path=str(dest),
        sha256=sha_expected,
        size_bytes=size_expected,
        cached=False,
    )


@app.post("/resolve", response_model=ResolveResponse)
def resolve(req: ResolveRequest) -> ResolveResponse:
    uri = (req.artifact_uri or "").strip()
    if uri.startswith("s3://"):
        return _resolve_s3(req)
    if uri.startswith("file://") or "://" not in uri:
        return _resolve_local(req)
    parsed = urlparse(uri)
    raise HTTPException(status_code=400, detail=f"Unsupported scheme: {parsed.scheme}")

