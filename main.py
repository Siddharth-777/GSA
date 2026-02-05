import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
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


class UserInput(BaseModel):
    text: str = Field(..., min_length=1, description="Input text from user")


class ApiResponse(BaseModel):
    message: str
    received_text: Optional[str] = None


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


@app.get("/")
def health() -> dict:
    return {"status": "ok", "docs": "/gsa"}


@app.post("/submit", response_model=ApiResponse)
def submit_input(
    payload: UserInput,
    x_api_key: str = Header(..., min_length=1, alias="x-api-key"),
) -> ApiResponse:
    expected_secret = get_expected_secret()

    if x_api_key != expected_secret:
        raise HTTPException(status_code=401, detail="Invalid secret key")

    supabase = get_supabase_client()
    table_name = get_supabase_table()

    try:
        supabase.table(table_name).insert({"text": payload.text}).execute()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to store input in Supabase: {exc}",
        ) from exc

    return ApiResponse(message="Input accepted", received_text=payload.text)
