# GSA — Guarded Speech Assistant

AI-powered anti-scam defense with an **agentic honeypot API** for scam detection and intelligence extraction.

## Overview
This repository now includes a hackathon-ready REST API that:

- Detects likely scam intent from incoming conversation events
- Generates believable multi-turn honeypot replies
- Extracts scam intelligence (UPI IDs, links, phone numbers, account numbers, keywords)
- Sends the **mandatory final callback** to GUVI after sufficient engagement
- Secures access with `x-api-key`

## API

### Health
- `GET /`

### Honeypot Endpoint
- `POST /honeypot`
- Required header:
  - `x-api-key: <SECRET_KEY>`

### Request Body
```json
{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response Body
```json
{
  "status": "success",
  "reply": "I can do that. Which UPI ID should I use for verification?",
  "scamDetected": true,
  "confidence": 0.61,
  "totalMessagesExchanged": 2,
  "extractedIntelligence": {
    "bankAccounts": [],
    "upiIds": ["scammer@upi"],
    "phishingLinks": [],
    "phoneNumbers": [],
    "suspiciousKeywords": ["account blocked", "upi", "verify"]
  },
  "agentNotes": "Detected scam behavior with indicators: account blocked, credential_harvest, verify",
  "callbackSent": false
}
```

## Mandatory Final Result Callback
When scam intent is confirmed and enough engagement is complete, the service automatically posts to:

- `POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult`

Payload fields:
- `sessionId`
- `scamDetected`
- `totalMessagesExchanged`
- `extractedIntelligence`
- `agentNotes`

## Environment Variables
Create `.env` with:

```bash
SECRET_KEY=your_api_key_here
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
SUPABASE_BUCKET=your_bucket_name
# optional override (default: honeypot_first_hits)
SUPABASE_FIRST_HIT_TABLE=honeypot_first_hits
```

> Supabase integration is optional at runtime, but when configured the API stores:
> - full incoming conversation payload as JSON under `conversations/<sessionId>/...`
> - final API output as JSON under `outputs/<sessionId>/...`
> - first-hit registration row in `honeypot_first_hits` for first-message timing

## Run Locally
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Open docs at:
- `http://127.0.0.1:8000/gsa`
