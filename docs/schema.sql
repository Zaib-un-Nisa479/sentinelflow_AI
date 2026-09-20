CREATE TABLE IF NOT EXISTS cases (
    id SERIAL PRIMARY KEY,
    ioc TEXT NOT NULL,
    ioc_type TEXT,                     -- 'ip', 'domain', 'hash', 'url'
    risk_score INTEGER,
    verdict TEXT,                      -- 'benign', 'suspicious', 'malicious'
    status TEXT DEFAULT 'open',        -- 'open', 'auto_resolved', 'escalated', 'closed'
    attck_techniques TEXT,             -- comma-separated technique IDs matched
    source TEXT,                       -- 'manual_report', 'siem_alert', 'urlhaus_feed'
    created_at TIMESTAMP DEFAULT NOW(),
    resolved_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS enrichment_log (
    id SERIAL PRIMARY KEY,
    case_id INTEGER REFERENCES cases(id),
    source TEXT,                       -- 'virustotal', 'abuseipdb'
    raw_response JSONB,
    contributed_score INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS actions_taken (
    id SERIAL PRIMARY KEY,
    case_id INTEGER REFERENCES cases(id),
    action_type TEXT,                  -- 'block_ip', 'isolate_host', 'log_only'
    executed_by TEXT,                  -- 'agent_auto', 'human_approved'
    result TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approvals (
    id SERIAL PRIMARY KEY,
    case_id INTEGER REFERENCES cases(id),
    requested_action TEXT,
    approver TEXT,
    decision TEXT,                     -- 'approved', 'declined', 'pending'
    decided_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);