# Caia Artifact Cache Service

Small FastAPI service that resolves an `artifact_uri` to a verified local file path.

Goals:
- Make model artifacts reproducible and safe to load (hash/size verification).
- Provide a single cache location for inference/training workers.
- Support S3-compatible object stores (MinIO in dev, AWS S3 in prod).

Non-goals (v1):
- No UI.
- No auth/ACL model beyond “run it behind your network” (you can add an API key later).
- No artifact uploads (use `aws s3 cp` / `mc cp` / CI pipelines).

## API

### `GET /health`

Returns basic status + configuration.

### `POST /resolve`

Request:

```json
{
  "artifact_uri": "s3://bucket/path/to/checkpoint.pt",
  "sha256": "…64 hex…",
  "size_bytes": 123456
}
```

Response:

```json
{
  "artifact_uri": "s3://bucket/path/to/checkpoint.pt",
  "local_path": "/cache/sha256/<sha256>",
  "sha256": "…",
  "size_bytes": 123456,
  "cached": true
}
```

Notes:
- Remote URIs require `sha256` and `size_bytes` (default). This keeps downloads verifiable and cache keys stable.
- Local filesystem resolution is disabled by default; enable only for dev.

## Environment Variables

- `ARTIFACT_CACHE_DIR` (default `./cache`): where cached artifacts are stored.
- `ARTIFACT_MAX_HASH_BYTES` (default `268435456`): max bytes to hash for *local* paths (remote downloads are hashed while streaming).
- `ARTIFACT_ALLOW_LOCAL_PATHS` (default `0`): allow resolving local filesystem paths.
- `ARTIFACT_ALLOWED_PATH_PREFIXES` (default current repo dir): comma-separated allowlist for local paths.
- `ARTIFACT_S3_ENDPOINT_URL` (optional): S3-compatible endpoint (e.g. `http://minio:9000`).
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` (default `us-east-1`).

## Dev (Docker + MinIO)

```bash
docker compose up --build
```

MinIO console: `http://127.0.0.1:9001` (user/pass: `minioadmin` / `minioadmin`)

The compose stack also creates a bucket named `artifacts`.

## Wiring With `model-registry` + `onyx-api`

- `model-registry` stores `artifact_uri` + `checkpoint_sha256` + `checkpoint_size_bytes`.
- `onyx-api` loads by `model_id`, resolves the registry `artifact_uri` through this service, then loads the local file.

Suggested env vars for `onyx-api`:
- `ONYX_REGISTRY_URL=http://127.0.0.1:8001`
- `ONYX_REGISTRY_API_KEY=...`
- `ONYX_ARTIFACT_CACHE_URL=http://127.0.0.1:8002`
- Optional safety gate: `ONYX_MIN_REGISTRY_STATUS=staging`

## Local tests (offline)

```bash
pytest
```
# artifact-cache-service
