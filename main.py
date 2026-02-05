import os
import json
from pathlib import Path
from typing import Optional, Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from supabase import Client, create_client

app = FastAPI(title="GSA API", version="1.0.0", docs_url="/gsa")


def load_env_file() -> None:
    env_path = Path(".env")
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value


load_env_file()


class ApiResponse(BaseModel):
    message: str
    received_text: Optional[str] = None
    received_raw: Optional[str] = None


def get_expected_secret() -> str:
    secret = os.getenv("SECRET_KEY")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail="Server configuration error: SECRET_KEY is not set in .env/environment.",
        )
    return secret


def get_supabase_client() -> Client:
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")

    if not supabase_url or not supabase_key:
        raise HTTPException(
            status_code=500,
            detail=(
                "Server configuration error: SUPABASE_URL and SUPABASE_KEY "
                "must be set in .env/environment."
            ),
        )

    return create_client(supabase_url, supabase_key)


def get_supabase_table() -> str:
    return os.getenv("SUPABASE_TABLE", "user_inputs")


def to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


@app.get("/")
def health() -> dict:
    return {"status": "ok", "docs": "/gsa"}


@app.post("/submit", response_model=ApiResponse)
async def submit_input(
    request: Request,
    x_api_key: str = Header(..., min_length=1, alias="x-api-key"),
) -> ApiResponse:
    expected_secret = get_expected_secret()
    if x_api_key != expected_secret:
        raise HTTPException(status_code=401, detail="Invalid secret key")

    raw_bytes = await request.body()
    raw_text = raw_bytes.decode("utf-8", errors="ignore") if raw_bytes else ""

    extracted: Any = None

    # 1) Try parsing JSON
    try:
        data = await request.json()

        if isinstance(data, dict):
            extracted = (
                data.get("text")
                or data.get("input")
                or data.get("message")
                or data.get("website")
                or data.get("url")
                or data.get("link")
                or data.get("content")
                or data.get("payload")
                or data
            )
        else:
            extracted = data

    except Exception:
        extracted = None

    # 2) Fallback to plain body text
    if extracted is None and raw_text.strip():
        extracted = raw_text.strip()

    # 3) Fallback to query params
    if extracted is None:
        qp = request.query_params
        extracted = (
            qp.get("text")
            or qp.get("input")
            or qp.get("message")
            or qp.get("website")
            or qp.get("url")
            or qp.get("link")
        )

    text = to_text(extracted)

    if not text:
        raise HTTPException(
            status_code=400,
            detail="No usable input found. Send JSON or plain text body.",
        )

    supabase = get_supabase_client()
    table_name = get_supabase_table()

    try:
        supabase.table(table_name).insert({"text": text}).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to store input in Supabase: {exc}",
        ) from exc

    return ApiResponse(
        message="Input accepted",
        received_text=text,
        received_raw=raw_text[:500] if raw_text else None,
    )
