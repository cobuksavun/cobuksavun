/**
 * CyberAcademy SIEM Backend API
 * Node.js/Express Server
 * 
 * Installation:
 * npm init -y
 * npm install express cors dotenv pg jsonwebtoken
 */

const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================================
// DATABASE CONNECTION
// ============================================================================

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'cyber_academy',
    password: process.env.DB_PASSWORD || 'password',
    port: process.env.DB_PORT || 5432,
});

// Test connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('Database connection error:', err.stack);
    } else {
        console.log('✅ Connected to PostgreSQL');
        release();
    }
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

app.use(cors());
app.use(express.json());

// Request logging
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Execute alert rule logic on logs
 * Check if rule condition matches any logs
 */
async function evaluateAlertRule(rule) {
    try {
        const condition = rule.condition;
        let query = 'SELECT * FROM logs WHERE TRUE';
        let params = [];

        // Build WHERE clause based on rule condition
        if (condition.log_type) {
            query += ' AND log_type = $' + (params.length + 1);
            params.push(condition.log_type);
        }

        if (condition.event_id) {
            query += ' AND event_id = $' + (params.length + 1);
            params.push(condition.event_id.toString());
        }

        if (condition.result) {
            query += ' AND result = $' + (params.length + 1);
            params.push(condition.result);
        }

        // Time window
        const timeWindow = condition.time_window || 3600;
        const sinceTime = new Date(Date.now() - timeWindow * 1000);
        query += ' AND timestamp > $' + (params.length + 1);
        params.push(sinceTime);

        query += ' ORDER BY timestamp DESC LIMIT 1000';

        const result = await pool.query(query, params);
        const logs = result.rows;

        // Check if threshold is met
        if (logs.length >= (condition.threshold || 1)) {
            // Alert triggered!
            return {
                triggered: true,
                matched_count: logs.length,
                matched_logs: logs.slice(0, 10) // Store top 10 matched logs
            };
        }

        return { triggered: false, matched_count: logs.length };
    } catch (err) {
        console.error('Error evaluating rule:', err);
        return { triggered: false, error: err.message };
    }
}

// ============================================================================
// API ENDPOINTS: LOGS
// ============================================================================

/**
 * GET /api/logs
 * Retrieve logs with filtering and pagination
 * 
 * Query params:
 * - from: start timestamp (ISO 8601)
 * - to: end timestamp (ISO 8601)
 * - log_type: FIREWALL, DC, DNS, IIS, VPN, WINDOWS_EVENT
 * - source_ip: filter by source IP
 * - severity: 1-10
 * - limit: number of logs (default 100)
 * - offset: pagination offset (default 0)
 */
app.get('/api/logs', async (req, res) => {
    try {
        const { from, to, log_type, source_ip, severity, limit = 100, offset = 0 } = req.query;
        
        let query = 'SELECT * FROM logs WHERE 1=1';
        let params = [];

        // Filters
        if (from) {
            query += ' AND timestamp >= $' + (params.length + 1);
            params.push(new Date(from));
        }

        if (to) {
            query += ' AND timestamp <= $' + (params.length + 1);
            params.push(new Date(to));
        }

        if (log_type) {
            query += ' AND log_type = $' + (params.length + 1);
            params.push(log_type.toUpperCase());
        }

        if (source_ip) {
            query += ' AND source_ip::text = $' + (params.length + 1);
            params.push(source_ip);
        }

        if (severity) {
            query += ' AND severity >= $' + (params.length + 1);
            params.push(parseInt(severity));
        }

        // Pagination
        query += ' ORDER BY timestamp DESC';
        query += ' LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
        params.push(parseInt(limit), parseInt(offset));

        const result = await pool.query(query, params);
        
        res.json({
            success: true,
            count: result.rows.length,
            logs: result.rows
        });
    } catch (err) {
        console.error('Error fetching logs:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * POST /api/logs
 * Ingest new log entry
 */
app.post('/api/logs', async (req, res) => {
    try {
        const {
            timestamp,
            log_type,
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            protocol,
            action,
            result,
            user_name,
            severity,
            raw_data,
            message
        } = req.body;

        const query = `
            INSERT INTO logs (
                timestamp, log_type, source_ip, dest_ip, source_port, dest_port,
                protocol, action, result, user_name, severity, raw_data, message
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
        `;

        const result_data = await pool.query(query, [
            new Date(timestamp),
            log_type.toUpperCase(),
            source_ip,
            dest_ip,
            source_port || null,
            dest_port || null,
            protocol || null,
            action || null,
            result || null,
            user_name || null,
            severity || 1,
            raw_data || null,
            message || null
        ]);

        // Check alert rules
        // (In production, use a background job/queue for this)
        const rules = await pool.query('SELECT * FROM alert_rules WHERE enabled = true');
        for (const rule of rules.rows) {
            const evaluation = await evaluateAlertRule(rule);
            if (evaluation.triggered) {
                // Create alert
                await pool.query(`
                    INSERT INTO alerts (rule_id, severity, message, matched_logs_count, status)
                    VALUES ($1, $2, $3, $4, $5)
                `, [rule.id, rule.severity, `Rule '${rule.name}' triggered`, evaluation.matched_count, 'new']);
            }
        }

        res.status(201).json({
            success: true,
            log: result_data.rows[0]
        });
    } catch (err) {
        console.error('Error inserting log:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// API ENDPOINTS: ALERTS
// ============================================================================

/**
 * GET /api/alerts
 * Retrieve active alerts with filtering
 * 
 * Query params:
 * - severity: critical, high, medium, low
 * - status: new, investigating, false_positive, confirmed, resolved
 * - rule_id: filter by specific rule
 */
app.get('/api/alerts', async (req, res) => {
    try {
        const { severity, status, rule_id, limit = 50, offset = 0 } = req.query;

        let query = 'SELECT * FROM alerts WHERE 1=1';
        let params = [];

        if (severity) {
            query += ' AND severity = $' + (params.length + 1);
            params.push(severity.toLowerCase());
        }

        if (status) {
            query += ' AND status = $' + (params.length + 1);
            params.push(status.toLowerCase());
        }

        if (rule_id) {
            query += ' AND rule_id = $' + (params.length + 1);
            params.push(rule_id);
        }

        query += ' ORDER BY triggered_at DESC';
        query += ' LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
        params.push(parseInt(limit), parseInt(offset));

        const result = await pool.query(query, params);

        res.json({
            success: true,
            count: result.rows.length,
            alerts: result.rows
        });
    } catch (err) {
        console.error('Error fetching alerts:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/alerts/summary
 * Get alert count summary by severity
 */
app.get('/api/alerts/summary', async (req, res) => {
    try {
        const query = `
            SELECT 
                severity,
                COUNT(*) as count
            FROM alerts
            WHERE status != 'resolved'
            GROUP BY severity
        `;

        const result = await pool.query(query);

        const summary = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        result.rows.forEach(row => {
            summary[row.severity] = parseInt(row.count);
        });

        res.json({
            success: true,
            summary
        });
    } catch (err) {
        console.error('Error fetching alert summary:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * PATCH /api/alerts/:id
 * Update alert status
 */
app.patch('/api/alerts/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { status, assigned_to, notes } = req.body;

        let query = 'UPDATE alerts SET ';
        let params = [];
        let setCount = 1;

        if (status) {
            query += `status = $${setCount++}`;
            params.push(status);
        }

        if (assigned_to) {
            if (params.length > 0) query += ', ';
            query += `assigned_to = $${setCount++}`;
            params.push(assigned_to);
        }

        if (notes) {
            if (params.length > 0) query += ', ';
            query += `notes = $${setCount++}`;
            params.push(notes);
        }

        if (status === 'resolved') {
            if (params.length > 0) query += ', ';
            query += `resolved_at = $${setCount++}`;
            params.push(new Date());
        }

        query += ` WHERE id = $${setCount} RETURNING *`;
        params.push(id);

        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Alert not found' });
        }

        res.json({
            success: true,
            alert: result.rows[0]
        });
    } catch (err) {
        console.error('Error updating alert:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// API ENDPOINTS: ALERT RULES
// ============================================================================

/**
 * GET /api/rules
 * Get all alert rules
 */
app.get('/api/rules', async (req, res) => {
    try {
        const { enabled, category } = req.query;

        let query = 'SELECT * FROM alert_rules WHERE 1=1';
        let params = [];

        if (enabled !== undefined) {
            query += ' AND enabled = $' + (params.length + 1);
            params.push(enabled === 'true');
        }

        if (category) {
            query += ' AND category = $' + (params.length + 1);
            params.push(category);
        }

        query += ' ORDER BY severity DESC, name ASC';

        const result = await pool.query(query, params);

        res.json({
            success: true,
            count: result.rows.length,
            rules: result.rows
        });
    } catch (err) {
        console.error('Error fetching rules:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * POST /api/rules
 * Create new alert rule
 */
app.post('/api/rules', async (req, res) => {
    try {
        const { name, description, log_type, condition, severity, category, created_by } = req.body;

        if (!name || !log_type || !condition || !severity) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required fields: name, log_type, condition, severity' 
            });
        }

        const query = `
            INSERT INTO alert_rules (name, description, log_type, condition, severity, category, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
        `;

        const result = await pool.query(query, [
            name,
            description || null,
            log_type.toUpperCase(),
            condition,
            severity.toLowerCase(),
            category || null,
            created_by || 'api'
        ]);

        res.status(201).json({
            success: true,
            rule: result.rows[0]
        });
    } catch (err) {
        console.error('Error creating rule:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// API ENDPOINTS: LABS
// ============================================================================

/**
 * GET /api/labs
 * Get available labs
 */
app.get('/api/labs', async (req, res) => {
    try {
        const { difficulty, published } = req.query;

        let query = 'SELECT id, title, description, difficulty, max_score, created_at FROM labs WHERE 1=1';
        let params = [];

        if (difficulty) {
            query += ' AND difficulty = $' + (params.length + 1);
            params.push(difficulty);
        }

        if (published !== undefined) {
            query += ' AND published = $' + (params.length + 1);
            params.push(published === 'true');
        }

        query += ' ORDER BY created_at DESC';

        const result = await pool.query(query, params);

        res.json({
            success: true,
            count: result.rows.length,
            labs: result.rows
        });
    } catch (err) {
        console.error('Error fetching labs:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * GET /api/labs/:id
 * Get detailed lab information
 */
app.get('/api/labs/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const query = 'SELECT * FROM labs WHERE id = $1';
        const result = await pool.query(query, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Lab not found' });
        }

        res.json({
            success: true,
            lab: result.rows[0]
        });
    } catch (err) {
        console.error('Error fetching lab:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

/**
 * POST /api/labs/:id/start
 * Start a lab instance
 */
app.post('/api/labs/:id/start', async (req, res) => {
    try {
        const { id } = req.params;
        const { user_id } = req.body;

        if (!user_id) {
            return res.status(400).json({ success: false, error: 'user_id required' });
        }

        const query = `
            INSERT INTO lab_instances (lab_id, user_id)
            VALUES ($1, $2)
            RETURNING *
        `;

        const result = await pool.query(query, [id, user_id]);

        res.status(201).json({
            success: true,
            instance: result.rows[0]
        });
    } catch (err) {
        console.error('Error starting lab:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
    console.log(`
    ╔════════════════════════════════════╗
    ║  CyberAcademy SIEM API Server      ║
    ║  Listening on http://localhost:${PORT}  ║
    ╚════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down gracefully...');
    pool.end();
    process.exit(0);
});
