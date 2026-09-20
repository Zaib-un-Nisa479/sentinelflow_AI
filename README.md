# SentinelFlow AI

**An autonomous SOC (Security Operations Center) triage platform.** It ingests a suspicious indicator (IP, domain, hash, or URL), enriches it against real threat-intelligence sources, reasons about severity using an LLM grounded in MITRE ATT&CK, takes safe actions autonomously, and routes anything risky to a human for approval — with a full audit trail.

▶ **[Live dashboard](https://claude.ai/artifact/We1LjTFbxB37xGDdeg2atF)** — real-time metrics and case activity, pulled directly from the deployed API.

---

## Why this exists

Security analysts get thousands of alerts a day and can't manually triage them all — this is the well-documented "alert fatigue" problem. SentinelFlow AI demonstrates an architecture for solving it: automate the read-only reasoning and enrichment work, but keep a human explicitly in the loop for anything with real-world consequence (blocking traffic, isolating a host).

## Architecture

```
                    ┌─────────────────┐
   Webhook  ───────▶│                 │
   (manual report)  │   n8n           │      ┌──────────────┐
                     │   orchestration │─────▶│  FastAPI     │
   Schedule Trigger  │   + AI Agent    │◀─────│  (enrich/    │
   (URLhaus feed) ──▶│                 │      │   action)    │
                     └────────┬────────┘      └──────┬───────┘
                              │                       │
                     ┌────────▼────────┐      ┌───────▼───────┐
                     │  Human approval │      │   Postgres    │
                     │  (email/wait)   │      │  (audit trail)│
                     └─────────────────┘      └───────────────┘
                              │
                     ┌────────▼────────┐
                     │  Supabase       │
                     │  (ATT&CK vector │
                     │   store)        │
                     └─────────────────┘
```

**n8n** orchestrates the flow and runs the AI Agent (Groq-hosted `openai/gpt-oss-120b`), which reasons about each indicator using two tools: a custom enrichment endpoint and a MITRE ATT&CK vector search (Supabase + Google Gemini embeddings). **FastAPI** is a standalone microservice holding the actual engineering logic — the composite risk-scoring algorithm, the action-execution interface, and API-key auth. **Postgres** stores four append-only-by-design tables (`cases`, `enrichment_log`, `actions_taken`, `approvals`) forming a tamper-evident audit trail, modeled loosely on SOC2-style compliance logging.

## What's actually "mine" vs. off-the-shelf

- The composite risk-scoring function (`compute_composite_score` in `api/enrichment.py`) — VirusTotal and AbuseIPDB give raw vendor data, not a 0-100 score; the weighting (`malicious_count * 8 + suspicious_count * 3`, capped at 100, combined with AbuseIPDB via `MAX` rather than average) is a deliberate design choice favoring sensitivity over precision in a security context.
- The escalation policy and system prompt design (`AI Agent` node's system message) — the actual behavioral control surface for the agent.
- The Postgres schema and audit-trail design.
- API-key auth, deduplication logic (skips re-investigating an IOC already under active review within the last hour), structured logging, and a parse-error safety branch that forces unparseable agent output into manual review rather than silently defaulting to "benign."
- The overall orchestration flow connecting all of the above.

n8n, Groq, VirusTotal, AbuseIPDB, and Supabase are tools; the scoring logic, schema, prompt design, and safety branches are the actual engineering content here.

## Live deployment

| Component | URL |
|---|---|
| n8n orchestration | `https://n8n-production-62882.up.railway.app` |
| FastAPI service | `https://sentinelflowai-production.up.railway.app` |
| Dashboard | [Live link](https://claude.ai/artifact/We1LjTFbxB37xGDdeg2atF) |

## Local setup

```bash
git clone https://github.com/Zaib-un-Nisa479/sentinelflow_AI.git
cd sentinelflow_AI
cp .env.example .env   # fill in your own API keys and secrets
docker compose up -d
```

Run the schema once against Postgres (via a Postgres node in n8n, or `psql`) using the `CREATE TABLE` statements in `docs/schema.sql`.

n8n: `http://localhost:5678` · API: `http://localhost:8000/docs`

### Required API keys
- VirusTotal (`VT_API_KEY`)
- AbuseIPDB (`ABUSEIPDB_API_KEY`)
- Groq (for the AI Agent's chat model)
- Google Gemini (for ATT&CK embeddings)
- Supabase (for the ATT&CK vector store)
- SMTP credentials (for the approval email — see limitation below)

## Known limitations

Being upfront about these because understanding *why* something doesn't work in a given environment is more useful than pretending it doesn't exist:

- **Human approval via email doesn't work on Railway's free/hobby tier.** Railway blocks all outbound SMTP (ports 25, 465, 587) below their Pro plan — confirmed directly with their support team. This isn't a bug in the workflow; it's a hard platform-level network restriction. The full approval flow (email → click Approve/Decline → audit log) is verified working end-to-end in local Docker deployment. A production fix would swap SMTP for a transactional email HTTPS API (Resend, SendGrid) or a Telegram bot, both of which route over HTTPS rather than raw SMTP.
- **Groq's free tier has tight rate limits** (8,000 tokens/minute on `openai/gpt-oss-120b` at time of writing) — rapid manual testing can trip a 429 faster than actual token usage would suggest, since the limit is a rolling per-minute window shared across all calls.
- **Supabase's free-tier project auto-pauses** after a period of inactivity, which manifests as a generic `fetch failed` error in the ATT&CK vector search tool rather than a clear "paused" message. Resuming it from the Supabase dashboard fixes this immediately.
- **The dashboard's API key is visible in client-side JavaScript.** Acceptable for a read-only portfolio demo; a real production dashboard would proxy these calls through a backend that holds the key server-side.
- **`/action`'s block/isolate execution is simulated**, not wired to a real firewall/EDR — deliberately, since untested automation with real network blast radius is a genuinely bad idea to ship casually. The interface (`api/actions.py`) is production-shaped: swapping the internals for a real firewall API call wouldn't require changing anything upstream (the agent, the approval flow, or the audit log).

## What I'd improve next

- Multi-source enrichment (cross-validate VT/AbuseIPDB against a third source)
- A real firewall/EDR integration behind the existing `/action` interface
- Queue-mode n8n scaling for high alert volume
- Swap SMTP for Resend/Telegram so the full approval loop works in the Railway deployment too, not just locally

## Recruiter-defense cheat sheet

**"Walk me through the architecture."**
n8n orchestrates an AI agent that reasons about security threats. The agent calls a FastAPI microservice I built for enrichment (VirusTotal + AbuseIPDB, combined via my own weighted risk score) and for taking actions. Everything's logged to Postgres across four tables forming an audit trail. High-risk actions require human approval before executing — enforced structurally via n8n's wait-for-approval mechanism, not just a suggestion in a prompt.

**"What's actually yours vs. off-the-shelf?"**
See the section above — the scoring algorithm, escalation policy, schema design, and safety branches (like the parse-error handling that prevents a malformed LLM response from silently defaulting to "benign") are the real engineering content.

**"Why not just call VirusTotal directly from n8n?"**
The value-add — scoring logic, action-simulation layer, audit logging — needed to live somewhere I fully control, not inside a no-code tool's node configuration. It's also portable: I could swap n8n for a different orchestrator without rewriting the scoring engine.

**"Is this production-ready?"**
The interfaces are production-shaped. What's missing for real production: real firewall/EDR credentials, a secrets manager instead of `.env`, an email provider that works over HTTPS instead of SMTP, and likely queue-mode n8n scaling for volume.

**"What would you improve next?"**
See "What I'd improve next" above.

## Repo structure

```
├── docker-compose.yml
├── .env.example
├── api/                    # FastAPI microservice
│   ├── main.py
│   ├── enrichment.py       # composite risk scoring
│   ├── actions.py          # simulated action execution
│   ├── models.py
│   ├── database.py
│   ├── metrics.py
│   ├── reports.py
│   └── tests/              # pytest suite
├── dashboard/
│   └── index.html          # live metrics dashboard
├── workflows/
│   └── SentinelFlow - Main Triage.json
└── n8n-custom/             # custom n8n image (Railway volume-permission fix)
```
