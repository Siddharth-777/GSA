# GSA — Guarded Speech Assistant

AI-powered anti-scam calling defense built for India’s fraud crisis.

## Problem Context
India is facing a large-scale telecom fraud wave:

- **5,00,000+ scam calls/day**
- **₹60+ crore lost/day**
- **3+ spam calls per citizen per day**

This project targets the hackathon challenges by building a practical, real-time defense layer for phone users.

## Our Hackathon Goal
We are building an AI system that can:

1. **Detect scam/spam calls in real time** during live conversations.
2. **Warn and protect users instantly** with clear risk signals.
3. **Hand off suspicious calls to an AI honeypot agent** that can safely engage scammers and gather intelligence.

## Challenge Mapping

### Challenge 1: AI-Powered Audio Call Analyzer
Core capabilities:

- Real-time speech-to-text from call audio
- Fraud keyword and intent detection (OTP, KYC update, bank block, urgent transfer, etc.)
- Behavioral analysis (pressure tactics, urgency framing, impersonation patterns)
- Live risk scoring and escalation thresholds
- On-device/app alerts: **"Likely Scam"**, **"High Risk"**, **"Disconnect Recommended"**

### Challenge 2: Agentic AI Honeypot System
Once risk crosses threshold:

- User can transfer the call to an AI persona
- AI agent continues a believable conversation to keep scammer engaged
- System extracts and logs indicators such as:
  - UPI IDs
  - Bank/account references
  - Phone numbers
  - Shortened/unknown links
  - Social engineering scripts
- Structured evidence package can be shared with law enforcement or cyber cells

## Proposed System Architecture

1. **Audio Ingestion Layer**
   - Captures incoming call stream (where platform permissions allow)
   - Segments and denoises speech for low-latency analysis

2. **Realtime Intelligence Layer**
   - ASR (speech-to-text)
   - NLP classifier for fraud intent
   - Conversation-level risk engine

3. **Decision & Response Layer**
   - Alert engine for end-user warnings
   - Optional auto-handoff trigger to honeypot mode

4. **Agentic Honeypot Layer**
   - Persona-driven conversational agent
   - Tooling for entity extraction and IOC (indicator of compromise) capture

5. **Evidence & Reporting Layer**
   - Time-stamped transcripts
   - Extracted scam artifacts
   - Export-ready report for enforcement workflows

## MVP Scope
For the hackathon timeline, we will focus on:

- Binary scam/spam detection + confidence score
- Fast user alerting UX
- Controlled honeypot conversation loop
- Basic intelligence extraction (UPI IDs, phone numbers, links)
- Demo-ready dashboard/report output

## Success Metrics

- **Detection precision/recall** on scam call samples
- **Average alert latency** from suspicious utterance to user warning
- **Honeypot engagement duration** (how long scammer remains engaged)
- **Actionable IOC extraction rate** per suspicious call

## Why This Matters
This is not just a classifier—it is a proactive defense system.

By combining **real-time detection** and an **agentic response**, we aim to:

- Reduce financial loss for citizens
- Increase friction and cost for scam operations
- Generate useful intelligence for cybercrime enforcement

## Team Direction
Immediate next milestones:

1. Curate multilingual scam-call dataset (Hindi + English + Hinglish)
2. Build low-latency inference pipeline
3. Design alert + handoff experience
4. Implement honeypot persona and extraction tools
5. Integrate reporting pipeline for demo day

---

If you are collaborating on this repository, please keep contributions aligned to the two challenge tracks above.

## FastAPI Demo Endpoint
A simple FastAPI app is available in `main.py` with Swagger UI support.

### Endpoint
- `POST /submit`
- Request body fields:
  - `text` (string)
- Required header:
  - `x-api-key` (string)

The endpoint validates `x-api-key` against `SECRET_KEY` from `.env` and stores the submitted `text` in Supabase.

Required environment variables:
- `SECRET_KEY`
- `SUPABASE_URL`
- `SUPABASE_KEY`
- `SUPABASE_TABLE` (optional, defaults to `user_inputs`)

### Run locally
```bash
uvicorn main:app --reload
```

Then open:
- Swagger UI: `http://127.0.0.1:8000/gsa`
