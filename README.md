# AI-Driven SIEM Pipeline

A modern, AI-powered Security Information and Event Management (SIEM) webhook receiver. This project ingests security alerts from Elastalert, enriches them by querying Elasticsearch for surrounding log context, and uses Google's Gemini AI to analyze the threat. Based on the AI's verdict, it enforces automated or human-in-the-loop mitigations using the macOS firewall (`pfctl`) and user policies (`pwpolicy`).

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

## Project State: Dry-Run Mode

Currently, the project is configured in a safe **"Dry-Run"** mode. The AI analyzes logs and prints its verdict (e.g., `[DRY-RUN] LLM Action: block_permanently`), but actual firewall commands and emails are commented out in `services/alert_handlers.py`. To take the SIEM live, simply uncomment the enforcement blocks.
