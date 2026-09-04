-- CyberAcademy SIEM Database Schema
-- PostgreSQL with TimescaleDB support (optional)

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "timescaledb" CASCADE;

-- ============================================================================
-- 1. LOGS TABLE (Ana Log Veri)
-- ============================================================================

CREATE TABLE IF NOT EXISTS logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Log Type Tanımlaması
    log_type VARCHAR(50) NOT NULL CHECK (log_type IN ('FIREWALL', 'DC', 'DNS', 'IIS', 'VPN', 'WINDOWS_EVENT')),
    
    -- Network Bilgileri
    source_ip INET NOT NULL,
    dest_ip INET NOT NULL,
    source_port INTEGER,
    dest_port INTEGER,
    protocol VARCHAR(20),
    
    -- Aksiyon ve Sonuç
    action VARCHAR(20), -- allow, deny, block, success, failed, etc.
    result VARCHAR(20), -- success, failed, etc.
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    
    -- User & Session Info
    user_name VARCHAR(255),
    user_domain VARCHAR(255),
    
    -- Severity ve Metadata
    severity INTEGER DEFAULT 1, -- 1-10 scale
    event_id VARCHAR(50), -- Windows Event ID, etc.
    category VARCHAR(100),
    
    -- Raw & Flexible Data
    raw_data JSONB,
    message TEXT,
    
    -- Administrative
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    lab_id UUID, -- Which lab this log belongs to (NULL = real logs)
    case_id UUID -- Which case/scenario
);

-- Indexes for fast queries
CREATE INDEX idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX idx_logs_source_ip ON logs(source_ip);
CREATE INDEX idx_logs_dest_ip ON logs(dest_ip);
CREATE INDEX idx_logs_user_name ON logs(user_name);
CREATE INDEX idx_logs_log_type ON logs(log_type);
CREATE INDEX idx_logs_lab_id ON logs(lab_id);
CREATE INDEX idx_logs_timestamp_logtype ON logs(timestamp DESC, log_type);

-- If using TimescaleDB, convert to hypertable
-- SELECT create_hypertable('logs', 'timestamp', if_not_exists => TRUE);

-- ============================================================================
-- 2. ALERT_RULES TABLE (Deteksiyon Kuralları)
-- ============================================================================

CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    
    -- Which log type does this rule apply to
    log_type VARCHAR(50) NOT NULL CHECK (log_type IN ('FIREWALL', 'DC', 'DNS', 'IIS', 'VPN', 'WINDOWS_EVENT')),
    
    -- Rule condition in JSON format
    -- Example: {
    --   "event_id": 4625,
    --   "threshold": 10,
    --   "time_window": 600,
    --   "group_by": "source_ip"
    -- }
    condition JSONB NOT NULL,
    
    -- Severity levels
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    
    -- Status
    enabled BOOLEAN DEFAULT TRUE,
    enabled_labs_only BOOLEAN DEFAULT FALSE, -- Is this rule only for labs?
    
    -- Rule categories
    category VARCHAR(100), -- 'brute_force', 'lateral_movement', 'data_exfil', etc.
    
    -- Metadata
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alert_rules_enabled ON alert_rules(enabled);
CREATE INDEX idx_alert_rules_log_type ON alert_rules(log_type);
CREATE INDEX idx_alert_rules_category ON alert_rules(category);

-- ============================================================================
-- 3. ALERTS TABLE (Tetiklenen Alertler)
-- ============================================================================

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    rule_id UUID NOT NULL REFERENCES alert_rules(id),
    
    -- When triggered
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Alert Details
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    message TEXT NOT NULL,
    
    -- Matched Information
    matched_logs_count INTEGER DEFAULT 0,
    matched_logs JSONB, -- Store summary or IDs
    
    -- Affected Entities
    source_ip INET,
    dest_ip INET,
    user_name VARCHAR(255),
    domain VARCHAR(255),
    
    -- Status & Investigation
    status VARCHAR(50) DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'false_positive', 'confirmed', 'resolved')),
    assigned_to VARCHAR(255),
    notes TEXT,
    
    -- Context
    lab_id UUID, -- Which lab this alert is part of
    case_id UUID, -- Which incident case
    
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_triggered_at ON alerts(triggered_at DESC);
CREATE INDEX idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX idx_alerts_lab_id ON alerts(lab_id);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);

-- ============================================================================
-- 4. LABS TABLE (Eğitim Laboratuvarları)
-- ============================================================================

CREATE TABLE IF NOT EXISTS labs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    title VARCHAR(255) NOT NULL,
    description TEXT,
    
    -- Difficulty Level
    difficulty VARCHAR(20) NOT NULL CHECK (difficulty IN ('easy', 'medium', 'hard')),
    
    -- Content Structure
    objectives TEXT[] NOT NULL, -- Array of objectives
    hint_logs JSONB, -- Hints about key logs to find
    hints TEXT[] DEFAULT '{}',
    
    -- Expected Results
    expected_alerts_count INTEGER,
    expected_alert_rule_ids UUID[], -- Which rules should trigger
    expected_findings JSONB, -- What students should discover
    
    -- Solution
    solution TEXT,
    solution_video_url VARCHAR(500),
    
    -- Lab Data
    scenario_description TEXT,
    scenario_timeframe VARCHAR(100), -- "15 minutes", "Jan 15 2024 14:00-15:00"
    
    -- Scoring
    max_score INTEGER DEFAULT 100,
    passing_score INTEGER DEFAULT 70,
    
    -- Metadata
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Publish Status
    published BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_labs_difficulty ON labs(difficulty);
CREATE INDEX idx_labs_published ON labs(published);

-- ============================================================================
-- 5. LAB_INSTANCES TABLE (Öğrenci'nin Lab Çalışması)
-- ============================================================================

CREATE TABLE IF NOT EXISTS lab_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    lab_id UUID NOT NULL REFERENCES labs(id),
    user_id VARCHAR(255) NOT NULL,
    
    -- Progress
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    status VARCHAR(50) DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'completed', 'abandoned')),
    
    -- Score & Performance
    score INTEGER,
    time_taken_minutes INTEGER,
    attempts INTEGER DEFAULT 1,
    
    -- Answers & Findings
    student_findings JSONB, -- Student's discoveries
    student_alerts_triggered JSONB, -- Alerts they triggered
    
    -- Metadata
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_lab_instances_user_id ON lab_instances(user_id);
CREATE INDEX idx_lab_instances_lab_id ON lab_instances(lab_id);
CREATE INDEX idx_lab_instances_status ON lab_instances(status);

-- ============================================================================
-- 6. CASES TABLE (Olay İnceleme Senaryoları)
-- ============================================================================

CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    title VARCHAR(255) NOT NULL,
    description TEXT,
    
    difficulty VARCHAR(20) NOT NULL CHECK (difficulty IN ('easy', 'medium', 'hard')),
    
    -- Scenario Details
    scenario_type VARCHAR(100), -- 'breach', 'exfiltration', 'lateral_movement', etc.
    scenario_description TEXT,
    victim_organization VARCHAR(255),
    incident_date DATE,
    
    -- Expected Indicators
    expected_findings JSONB,
    expected_duration_hours INTEGER,
    
    -- Solution
    solution TEXT,
    solution_video_url VARCHAR(500),
    
    -- Case Data & Logs
    case_logs JSONB, -- Reference to log scenarios
    
    -- Scoring
    max_score INTEGER DEFAULT 200,
    passing_score INTEGER DEFAULT 140,
    
    -- Metadata
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    published BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_cases_difficulty ON cases(difficulty);
CREATE INDEX idx_cases_scenario_type ON cases(scenario_type);

-- ============================================================================
-- 7. CASE_INSTANCES TABLE (Öğrenci'nin Case Çalışması)
-- ============================================================================

CREATE TABLE IF NOT EXISTS case_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    case_id UUID NOT NULL REFERENCES cases(id),
    user_id VARCHAR(255) NOT NULL,
    
    -- Progress
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'in_progress' CHECK (status IN ('in_progress', 'completed', 'abandoned')),
    
    -- Score & Performance
    score INTEGER,
    time_taken_hours INTEGER,
    attempts INTEGER DEFAULT 1,
    
    -- Findings
    student_findings JSONB,
    student_conclusions TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 8. AUDIT_LOG TABLE (Platform Activity Auditing)
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    user_id VARCHAR(255),
    action VARCHAR(100), -- 'view_lab', 'submit_answer', 'trigger_alert', etc.
    resource_type VARCHAR(100), -- 'lab', 'case', 'log', 'alert'
    resource_id UUID,
    
    details JSONB,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- ============================================================================
-- Seed Data: Basic Alert Rules
-- ============================================================================

INSERT INTO alert_rules (name, log_type, condition, severity, category, description, created_by) VALUES
('RDP Brute Force - Windows Events', 'WINDOWS_EVENT', '{"event_id": 4625, "threshold": 10, "time_window": 600, "group_by": "source_ip"}', 'high', 'brute_force', 'Detects 10+ failed RDP login attempts within 10 minutes', 'system'),
('SSH Brute Force - Firewall Logs', 'FIREWALL', '{"protocol": "SSH", "action": "DENY", "threshold": 15, "time_window": 300, "group_by": "source_ip"}', 'high', 'brute_force', 'Detects 15+ SSH connection denials in 5 minutes', 'system'),
('VPN Authentication Failures', 'VPN', '{"result": "failed", "threshold": 5, "time_window": 300, "group_by": "source_ip"}', 'medium', 'brute_force', 'Multiple failed VPN auth attempts', 'system'),
('Lateral Movement - Unusual Ports', 'FIREWALL', '{"action": "ALLOW", "dest_port": [3389, 445, 139, 135], "source_ip_internal": true, "dest_ip_internal": true, "threshold": 3, "time_window": 600}', 'high', 'lateral_movement', 'Internal IPs connecting to risky internal ports', 'system'),
('Data Exfiltration - Large Transfers', 'FIREWALL', '{"action": "ALLOW", "direction": "outbound", "bytes_sent_threshold": 1073741824, "time_window": 300}', 'critical', 'data_exfil', 'Unusual outbound traffic volume detected (>1GB in 5min)', 'system'),
('DNS Tunneling Detection', 'DNS', '{"query_length": 200, "subdomain_depth": 5, "threshold": 20, "time_window": 600}', 'high', 'command_control', 'Suspicious DNS query patterns detected', 'system'),
('Port Scanning Activity', 'FIREWALL', '{"action": "DENY", "dest_port": {"is_sequential": true, "threshold": 20}, "time_window": 60, "group_by": "source_ip"}', 'medium', 'reconnaissance', 'Sequential port scan detected', 'system'),
('SQL Injection Attempts', 'IIS', '{"url_pattern": ["UNION", "SELECT", "DROP", "INSERT"], "threshold": 5, "time_window": 300}', 'high', 'exploitation', 'SQL injection patterns in HTTP requests', 'system'),
('Privilege Escalation Attempts', 'WINDOWS_EVENT', '{"event_id": 4672, "failure_count": 5, "time_window": 600}', 'high', 'privilege_escalation', 'Multiple failed admin access attempts', 'system'),
('C2 Communication - Known Bad Domains', 'DNS', '{"domain_reputation": "malicious", "threshold": 1, "time_window": 0}', 'critical', 'command_control', 'DNS query to known malicious domain', 'system'),
('Account Lockout Cascade', 'DC', '{"event_id": 4740, "threshold": 3, "time_window": 600, "group_by": "subnet"}', 'medium', 'attack', 'Multiple account lockouts from same subnet', 'system'),
('Blacklisted IP Detection', 'FIREWALL', '{"source_ip_reputation": "malicious", "threshold": 1, "time_window": 0}', 'critical', 'threat_intel', 'Connection attempt from known malicious IP', 'system');

-- ============================================================================
-- Seed Data: First Lab - Brute Force Detection
-- ============================================================================

INSERT INTO labs (title, difficulty, description, objectives, expected_alerts_count, expected_alert_rule_ids, max_score, created_by, published) 
VALUES (
    'Brute Force Attack Detection',
    'easy',
    'A suspicious number of failed RDP login attempts are detected on your server. Investigate the attack, identify the attacker''s IP, and understand the attack pattern.',
    ARRAY[
        'Identify the attacker IP address',
        'Count total failed login attempts',
        'Identify targeted user accounts',
        'Determine attack duration',
        'Calculate time between attempts',
        'Recommend mitigation strategy'
    ],
    1,
    ARRAY[(SELECT id FROM alert_rules WHERE name = 'RDP Brute Force - Windows Events')],
    100,
    'system',
    TRUE
);

COMMIT;
