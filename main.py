import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

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


@app.get("/")
def health() -> dict:
    return {"status": "ok", "docs": "/gsa"}


@app.post("/submit", response_model=ApiResponse)
def submit_input(
    payload: UserInput,
    x_secret_key: str = Header(..., min_length=1, alias="X-Secret-Key"),
) -> ApiResponse:
    expected_secret = get_expected_secret()

    if x_secret_key != expected_secret:
        raise HTTPException(status_code=401, detail="Invalid secret key")

    return ApiResponse(message="Input accepted", received_text=payload.text)
