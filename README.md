# AI-Driven SIEM Pipeline

A modern, AI-powered Security Information and Event Management (SIEM) webhook receiver. This project ingests security alerts from Elastalert, enriches them by querying Elasticsearch for surrounding log context, and uses Google's Gemini AI to analyze the threat. Based on the AI's verdict, it enforces automated or human-in-the-loop mitigations using the macOS firewall (`pfctl`) and user policies (`pwpolicy`).

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Alert Handlers Built-In](#alert-handlers-built-in)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Setup and Installation](#setup-and-installation)
- [Running the Server](#running-the-server)
- [Simulating an Alert](#simulating-an-alert)
- [Safe Mode](#safe-mode)

---

## Features

- **Webhook Ingestion**: Fast and lightweight FastAPI server to receive alerts from Elastalert (or any SIEM).
- **Context Enrichment**: Dynamically queries local Elasticsearch clusters to fetch surrounding logs (e.g., prior HTTP requests, past SSH attempts) to give the AI the full picture.
- **AI Threat Analysis**: Uses `gemini-3.5-flash` with strictly formatted system prompts to generate structured JSON verdicts (`normal`, `block_temporarily`, or `block_permanently`) and a detailed reasoning report.
- **Automated Mitigations**: 
  - Temporarily blocks IPs via `pfctl`.
  - Temporarily locks compromised or brute-forced user accounts via macOS `pwpolicy`.
- **Human-in-the-Loop Approvals**: For severe actions (permanent blocks or locking multiple users), the system sends an interactive HTML email (via Resend) to SOC analysts with "Yes/No" approval buttons.
- **Audit Logging**: Uses Prisma and SQLite to keep a persistent record of all incoming raw payloads, the AI's reasoning, and the final verdicts.
- **Fail-Safes**: Implements a Whitelist system to prevent automated locking of VIPs, gateway IPs, or executive accounts.

## Architecture

An alert arrives with almost no context — an IP, a rule name, a count. The pipeline's job
is to turn that into a decision that can be defended, so every stage adds evidence before
anything is enforced.

```
┌────────────┐
│ Elastalert │  rule fires
└─────┬──────┘
      │ POST /webhook
      ▼
┌─────────────────────────────────────────────────────────────┐
│  main.py (FastAPI)                                          │
│    1. persist the raw payload immediately  ──► SecurityAlert│
│    2. attach _db_alert_id                                   │
│    3. hand off to process_alert()                           │
└─────┬───────────────────────────────────────────────────────┘
      ▼
┌─────────────────────────────────────────────────────────────┐
│  services/alert_handlers.py        routes by rule_name       │
│     HTTP 4xx spike · privilege escalation                    │
│     console login  · SSH brute force                         │
└─────┬───────────────────────────────────────────────────────┘
      ▼
┌──────────────────┐   surrounding logs   ┌──────────────────┐
│ services/        │ ◄─────────────────── │  Elasticsearch   │
│ es_client.py     │                      └──────────────────┘
└─────┬────────────┘
      ▼
┌──────────────────┐   structured verdict ┌──────────────────┐
│ gemini_client.py │ ◄─────────────────── │  Gemini          │
│ + prompts.py     │                      └──────────────────┘
└─────┬────────────┘
      ▼
┌─────────────────────────────────────────────────────────────┐
│  whitelist.py   ── VIPs, gateways and executives exempted    │
└─────┬───────────────────────────────────────────────────────┘
      ▼
   normal          block_temporarily          block_permanently
      │                    │                          │
   log only        firewall.py (pfctl /         email_service.py
                   pwpolicy) + auto-undo        → analyst approves
                                                → /action/* endpoint
```

### Why enrichment comes before the model

A raw alert cannot distinguish a broken link from a vulnerability scan — both look like
HTTP 403s. `es_client.py` queries Elasticsearch for the logs *surrounding* the alert, so
the model sees the request sequence rather than a single data point. The quality of the
verdict is mostly a function of this step, not of the prompt.

### Two tiers of enforcement

Severity determines who decides:

| Verdict | Decided by | Action |
| :--- | :--- | :--- |
| `normal` | Automatic | Logged, nothing enforced |
| `block_temporarily` | Automatic | `pfctl` IP block or `pwpolicy` account lock, auto-reverted on a timer |
| `block_permanently` | **A human** | Analyst receives an interactive email; the block only happens when they click |

Reversible actions are automated; irreversible ones are not. The approval endpoints in
`main.py` (`/action/block-permanently`, `/action/ip-decision`, `/action/users-decision`)
exist so the analyst's click *is* the execution path.

### Fail-safes

`whitelist.py` is checked before any enforcement, so gateway IPs and executive accounts
cannot be locked out by an automated verdict — the failure mode of an over-eager SIEM is
locking the people who would fix it. `PROTECTED_USERNAMES` applies the same guard to the
multi-user lock path.

### Audit trail

The raw payload is written to the database *before* analysis, so an alert is recoverable
even if enrichment or the model call fails. The record is then updated with the model's
reasoning and the final verdict, giving a complete chain from trigger to action.

## Alert Handlers Built-In

1. **HTTP Error Spikes (4xx)**: Analyzes web server logs to distinguish between broken links, vulnerability scanning (dirb/nikto), and login brute-forcing.
2. **Privilege Escalation**: Detects repeated `sudo` failures and assesses if it is a targeted attack or an absent-minded user.
3. **Physical Console Logins**: Monitors `/bin/login` failures to protect local workstations.
4. **SSH Failed Logins**: Analyzes inbound SSH brute force attempts.

## Tech Stack

- **Backend**: Python 3.9, FastAPI, Uvicorn
- **AI/LLM**: Google GenAI SDK (`gemini-3.5-flash`)
- **Database (Logs)**: Elasticsearch (Async Client)
- **Database (Audit)**: Prisma ORM (SQLite)
- **Email Service**: Resend API
- **System Level**: macOS `pf` (Packet Filter) and `pwpolicy`

## Prerequisites

- Python 3.9+
- Local or remote Elasticsearch instance
- A Google Gemini API Key
- A Resend API Key

## Setup and Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/TrinayanMahato/SIEM.git
   cd SIEM
   ```

2. **Create a virtual environment and install dependencies:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Initialize the Prisma Database:**
   ```bash
   prisma generate
   prisma db push
   ```

4. **Environment Variables:**
   Create a `.env` file in the root directory and add your keys:
   ```env
   GEMINI_API_KEY=your_gemini_key_here
   RESEND_API_KEY=your_resend_key_here
   ELASTICSEARCH_HOST=http://localhost:9200
   ```

5. **Configure macOS Firewall (Optional for active mitigations):**
   To allow the system to drop packets, ensure `pf` is enabled and configured to read the `siem_blocked` table.

## Running the Server

Start the FastAPI server using Uvicorn:

```bash
uvicorn main:app --reload
```
The server will run on `http://127.0.0.1:8000`.

## Simulating an Alert

The project includes a `simulate_alert.py` script to test the pipeline without waiting for a real attack. 
This script connects to Elasticsearch, injects mock HTTP 403 logs, and then fires a webhook at the FastAPI server.

In a separate terminal, run:
```bash
python3 simulate_alert.py
```
You will see the AI's real-time reasoning and verdict printed in the FastAPI terminal!

## Safe Mode

The pipeline ships in **dry-run** by default. The full chain runs — enrichment, model
analysis, whitelist checks, verdict — and the decision is logged rather than enforced:

```
[DRY-RUN] LLM Action: block_permanently
```

This is the right default for a system that can lock accounts and drop packets: it lets
you validate the model's judgement against real traffic before giving it the authority to
act. Enable enforcement by uncommenting the action blocks in
`services/alert_handlers.py` once the verdicts look right.
