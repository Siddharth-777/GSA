from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
import os
from pathlib import Path
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
        raise HTTPException(status_code=500, detail="SECRET_KEY is not set.")
    return secret

def get_supabase_client() -> Client:
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    if not supabase_url or not supabase_key:
        raise HTTPException(status_code=500, detail="SUPABASE_URL/SUPABASE_KEY not set.")
    return create_client(supabase_url, supabase_key)

def get_supabase_table() -> str:
    return os.getenv("SUPABASE_TABLE", "user_inputs")

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

    text = None

    # Try JSON first
    try:
        data = await request.json()
        if isinstance(data, dict):
            text = (
                data.get("text")
                or data.get("input")
                or data.get("message")
                or data.get("website")
                or data.get("url")
            )
        elif isinstance(data, str):
            text = data
    except Exception:
        pass

    # If not JSON, accept plain text body
    if not text and raw_text.strip():
        text = raw_text.strip()

    # Also allow query param fallback (some testers do this)
    if not text:
        qp = request.query_params
        text = qp.get("text") or qp.get("input") or qp.get("website") or qp.get("url")

    if not text:
        raise HTTPException(
            status_code=400,
            detail="No usable input found. Send JSON {'text': '...'} or a plain text body.",
        )

    supabase = get_supabase_client()
    table_name = get_supabase_table()

    try:
        supabase.table(table_name).insert({"text": text}).execute()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to store input in Supabase: {exc}") from exc

    return ApiResponse(message="Input accepted", received_text=text, received_raw=raw_text[:500])
