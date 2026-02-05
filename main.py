import os
import re
import json
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib import error as url_error
from urllib import request as url_request

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="GSA API", version="2.0.0", docs_url="/gsa")

FINAL_RESULT_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
SCAM_THRESHOLD = 0.35
SUPABASE_CONVERSATION_FOLDER = "conversations"
SUPABASE_OUTPUT_FOLDER = "outputs"
SUPABASE_FIRST_HIT_TABLE = "honeypot_first_hits"


# -------------------------------
# Environment / configuration
# -------------------------------
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


# -------------------------------
# API models
# -------------------------------
class Message(BaseModel):
    sender: str = Field(..., description="scammer or user")
    text: str
    timestamp: int


class Metadata(BaseModel):
    channel: str | None = None
    language: str | None = None
    locale: str | None = None


class HoneyPotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: list[Message] = Field(default_factory=list)
    metadata: Metadata | None = None


class ExtractedIntelligence(BaseModel):
    bankAccounts: list[str] = Field(default_factory=list)
    upiIds: list[str] = Field(default_factory=list)
    phishingLinks: list[str] = Field(default_factory=list)
    phoneNumbers: list[str] = Field(default_factory=list)
    suspiciousKeywords: list[str] = Field(default_factory=list)


class HoneyPotResponse(BaseModel):
    status: str
    reply: str
    scamDetected: bool
    confidence: float
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str
    callbackSent: bool


# -------------------------------
# Stateful session store
# -------------------------------
@dataclass
class SessionState:
    scam_detected: bool = False
    confidence: float = 0.0
    total_messages: int = 0
    agent_notes: str = ""
    callback_sent: bool = False
    bank_accounts: set[str] = field(default_factory=set)
    upi_ids: set[str] = field(default_factory=set)
    phishing_links: set[str] = field(default_factory=set)
    phone_numbers: set[str] = field(default_factory=set)
    suspicious_keywords: set[str] = field(default_factory=set)
    first_hit_logged: bool = False
    prompt_attempts: dict[str, int] = field(default_factory=dict)


SESSION_STORE: dict[str, SessionState] = {}


# -------------------------------
# Detection + extraction helpers
# -------------------------------
SCAM_PATTERNS: dict[str, float] = {
    "verify": 0.08,
    "urgent": 0.1,
    "immediately": 0.08,
    "account blocked": 0.2,
    "account suspension": 0.2,
    "kyc": 0.15,
    "otp": 0.2,
    "cvv": 0.2,
    "upi": 0.1,
    "bank": 0.08,
    "click": 0.08,
    "link": 0.08,
    "refund": 0.08,
    "gift": 0.07,
    "lottery": 0.15,
    "pay now": 0.2,
    "share screen": 0.2,
    "remote app": 0.2,
    "suspend": 0.12,
    "security team": 0.12,
    "verification": 0.1,
    "wallet": 0.08,
    "transfer": 0.1,
    "beneficiary": 0.12,
}

UPI_REGEX = re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b")
URL_REGEX = re.compile(r"https?://[^\s]+", re.IGNORECASE)
PHONE_REGEX = re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b")
BANK_REGEX = re.compile(r"\b\d{9,18}\b")



def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def collect_messages(payload: HoneyPotRequest, sender: str | None = None) -> list[str]:
    messages: list[Message] = [*payload.conversationHistory, payload.message]
    if sender is None:
        return [msg.text for msg in messages]

    sender_normalized = sender.strip().lower()
    return [msg.text for msg in messages if msg.sender.strip().lower() == sender_normalized]



def detect_scam_intent(text: str) -> tuple[bool, float, list[str]]:
    normalized = normalize_text(text)
    score = 0.0
    hits: list[str] = []

    for key, weight in SCAM_PATTERNS.items():
        if key in normalized:
            score += weight
            hits.append(key)

    if re.search(r"\b(otp|pin|cvv|password|aadhar|pan)\b", normalized):
        score += 0.2
        hits.append("credential_harvest")

    if URL_REGEX.search(normalized):
        score += 0.1
        hits.append("url")

    if "do not" in normalized and "tell" in normalized:
        score += 0.06
        hits.append("isolation_tactic")

    return score >= SCAM_THRESHOLD, min(score, 1.0), hits



def update_intelligence(state: SessionState, text: str) -> None:
    lowered = normalize_text(text)
    for token in UPI_REGEX.findall(text):
        state.upi_ids.add(token)
    for token in URL_REGEX.findall(text):
        state.phishing_links.add(token)
    for token in PHONE_REGEX.findall(text):
        state.phone_numbers.add(token.strip())
    for token in BANK_REGEX.findall(text):
        state.bank_accounts.add(token)

    for keyword in SCAM_PATTERNS:
        if keyword in lowered:
            state.suspicious_keywords.add(keyword)



def extract_payload(state: SessionState) -> ExtractedIntelligence:
    return ExtractedIntelligence(
        bankAccounts=sorted(state.bank_accounts),
        upiIds=sorted(state.upi_ids),
        phishingLinks=sorted(state.phishing_links),
        phoneNumbers=sorted(state.phone_numbers),
        suspiciousKeywords=sorted(state.suspicious_keywords),
    )



def generate_reply(state: SessionState) -> str:
    if not state.scam_detected:
        return "Can you explain this in detail? I want to understand before I proceed."

    prompts = {
        "upi": [
            "I can do that. Which UPI ID should I use for verification?",
            "Please confirm the exact UPI handle so I send it to the right account.",
        ],
        "link": [
            "Okay, please share the exact link where I should complete this process.",
            "The page is not opening for me. Can you resend the full secure link?",
        ],
        "phone": [
            "In case this disconnects, which official support number should I call back?",
            "Please share your helpline number so I can confirm this request quickly.",
        ],
        "bank": [
            "Do you have an account reference number for this case?",
            "Share the beneficiary account number once so I can match it before proceeding.",
        ],
    }

    goals = [
        ("upi", not state.upi_ids),
        ("link", not state.phishing_links),
        ("phone", not state.phone_numbers),
        ("bank", not state.bank_accounts),
    ]

    for key, missing in goals:
        if not missing:
            continue
        attempt = state.prompt_attempts.get(key, 0)
        state.prompt_attempts[key] = attempt + 1
        variants = prompts[key]
        return variants[min(attempt, len(variants) - 1)]

    return "I am getting an error. Could you repeat the steps once more so I do it correctly?"



def should_send_callback(state: SessionState) -> bool:
    if not state.scam_detected or state.callback_sent:
        return False

    intel_signals = sum(
        [
            1 if state.upi_ids else 0,
            1 if state.phishing_links else 0,
            1 if state.phone_numbers else 0,
            1 if state.bank_accounts else 0,
        ]
    )
    return state.total_messages >= 6 or intel_signals >= 2



def send_final_callback(session_id: str, state: SessionState) -> bool:
    payload = {
        "sessionId": session_id,
        "scamDetected": state.scam_detected,
        "totalMessagesExchanged": state.total_messages,
        "extractedIntelligence": extract_payload(state).model_dump(),
        "agentNotes": state.agent_notes,
    }

    try:
        response = safe_post_json(
            FINAL_RESULT_ENDPOINT,
            payload,
            headers={"Content-Type": "application/json"},
            timeout=2.5,
        )
        return response < 300
    except OSError:
        return False


def get_supabase_settings() -> dict[str, str] | None:
    url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    bucket = os.getenv("SUPABASE_BUCKET", "").strip()

    if not url or not key or not bucket:
        return None

    return {"url": url, "key": key, "bucket": bucket}


def upload_json_to_supabase(path: str, payload: dict[str, Any]) -> bool:
    settings = get_supabase_settings()
    if not settings:
        return False

    endpoint = (
        f"{settings['url']}/storage/v1/object/{settings['bucket']}/{path.lstrip('/')}"
    )
    headers = {
        "apikey": settings["key"],
        "Authorization": f"Bearer {settings['key']}",
        "Content-Type": "application/json",
        "x-upsert": "true",
    }

    try:
        status = safe_post_json(endpoint, payload, headers=headers, timeout=2.5)
        return status < 300
    except OSError:
        return False


def register_first_hit(session_id: str, first_message: Message, history_count: int) -> bool:
    settings = get_supabase_settings()
    if not settings:
        return False

    table = os.getenv("SUPABASE_FIRST_HIT_TABLE", SUPABASE_FIRST_HIT_TABLE).strip()
    endpoint = f"{settings['url']}/rest/v1/{table}"
    headers = {
        "apikey": settings["key"],
        "Authorization": f"Bearer {settings['key']}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }

    record = {
        "session_id": session_id,
        "first_message_timestamp": first_message.timestamp,
        "first_message_received_at": datetime.now(timezone.utc).isoformat(),
        "first_message_sender": first_message.sender,
        "history_count_on_first_hit": history_count,
    }

    try:
        status = safe_post_json(endpoint, record, headers=headers, timeout=2.5)
        return status < 300
    except OSError:
        return False


def safe_post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    timeout: float = 2.5,
) -> int:
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)

    data = json.dumps(payload).encode("utf-8")
    req = url_request.Request(url, data=data, headers=request_headers, method="POST")
    try:
        with url_request.urlopen(req, timeout=timeout) as response:
            return response.getcode()
    except url_error.HTTPError as exc:
        return exc.code


def persist_session_artifacts(
    session_id: str,
    payload: HoneyPotRequest,
    response_payload: HoneyPotResponse,
) -> tuple[bool, bool]:
    event_timestamp = payload.message.timestamp

    conversation_blob = {
        "sessionId": session_id,
        "metadata": payload.metadata.model_dump() if payload.metadata else None,
        "conversationHistory": [msg.model_dump() for msg in payload.conversationHistory],
        "latestMessage": payload.message.model_dump(),
        "savedAt": datetime.now(timezone.utc).isoformat(),
    }
    conversation_path = (
        f"{SUPABASE_CONVERSATION_FOLDER}/{session_id}/{event_timestamp}.json"
    )

    output_blob = response_payload.model_dump()
    output_blob["sessionId"] = session_id
    output_blob["savedAt"] = datetime.now(timezone.utc).isoformat()
    output_path = f"{SUPABASE_OUTPUT_FOLDER}/{session_id}/{event_timestamp}.json"

    convo_saved = upload_json_to_supabase(conversation_path, conversation_blob)
    output_saved = upload_json_to_supabase(output_path, output_blob)
    return convo_saved, output_saved



def get_expected_secret() -> str:
    secret = os.getenv("SECRET_KEY")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail="Server configuration error: SECRET_KEY is not set.",
        )
    return secret


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok", "docs": "/gsa"}


@app.post("/honeypot", response_model=HoneyPotResponse)
def honeypot_handler(
    payload: HoneyPotRequest,
    x_api_key: str = Header(..., min_length=1, alias="x-api-key"),
) -> HoneyPotResponse:
    expected_secret = get_expected_secret()
    if x_api_key != expected_secret:
        raise HTTPException(status_code=401, detail="Invalid API key")

    state = SESSION_STORE.setdefault(payload.sessionId, SessionState())

    if not state.first_hit_logged:
        state.first_hit_logged = register_first_hit(
            payload.sessionId,
            payload.message,
            len(payload.conversationHistory),
        )

    scammer_messages = collect_messages(payload, sender="scammer")
    full_text = "\n".join(scammer_messages or collect_messages(payload))

    detected, confidence, hits = detect_scam_intent(full_text)
    state.scam_detected = state.scam_detected or detected
    state.confidence = max(state.confidence, confidence)

    for msg_text in scammer_messages:
        update_intelligence(state, msg_text)

    state.total_messages = len(payload.conversationHistory) + 1

    if hits:
        state.agent_notes = (
            f"Detected scam behavior with indicators: {', '.join(sorted(set(hits)))}"
        )
    elif state.scam_detected:
        state.agent_notes = "Conversation remains suspicious based on cumulative context."
    else:
        state.agent_notes = "No strong scam indicators in latest context."

    reply = generate_reply(state)

    callback_sent = False
    if should_send_callback(state):
        callback_sent = send_final_callback(payload.sessionId, state)
        state.callback_sent = callback_sent

    response = HoneyPotResponse(
        status="success",
        reply=reply,
        scamDetected=state.scam_detected,
        confidence=round(state.confidence, 3),
        totalMessagesExchanged=state.total_messages,
        extractedIntelligence=extract_payload(state),
        agentNotes=state.agent_notes,
        callbackSent=callback_sent,
    )

    persist_session_artifacts(payload.sessionId, payload, response)
    return response
