/**
 * CyberAcademy SIEM Backend API
 * Node.js/Express Server with Supabase
 */

const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// SUPABASE CLIENT
// ============================================================================

const supabaseUrl = process.env.SUPABASE_URL || 'https://nxfjyntjcckrsldewhtc.supabase.co';
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseKey) {
    console.error('❌ Missing SUPABASE_ANON_KEY environment variable');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

console.log(`✅ Connected to Supabase: ${supabaseUrl}`);

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
// API ENDPOINTS: LOGS
// ============================================================================

/**
 * GET /api/logs
 * Retrieve logs with filtering and pagination
 */
app.get('/api/logs', async (req, res) => {
    try {
        const { from, to, log_type, source_ip, severity, limit = 100, offset = 0 } = req.query;

        let query = supabase.from('logs').select('*');

        // Filters
        if (log_type) {
            query = query.eq('log_type', log_type.toUpperCase());
        }

        if (source_ip) {
            query = query.eq('source_ip', source_ip);
        }

        if (severity) {
            query = query.gte('severity', parseInt(severity));
        }

        if (from) {
            query = query.gte('timestamp', new Date(from).toISOString());
        }

        if (to) {
            query = query.lte('timestamp', new Date(to).toISOString());
        }

        // Pagination & Sorting
        query = query.order('timestamp', { ascending: false })
            .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

        const { data, error, count } = await query;

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.json({
            success: true,
            count: data ? data.length : 0,
            total: count,
            logs: data || []
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

        // Validate required fields
        if (!log_type || !source_ip || !dest_ip) {
            return res.status(400).json({
                success: false,
                error: 'Missing required fields: log_type, source_ip, dest_ip'
            });
        }

        const logData = {
            timestamp: timestamp ? new Date(timestamp).toISOString() : new Date().toISOString(),
            log_type: log_type.toUpperCase(),
            source_ip,
            dest_ip,
            source_port: source_port || null,
            dest_port: dest_port || null,
            protocol: protocol || null,
            action: action || null,
            result: result || null,
            user_name: user_name || null,
            severity: severity || 1,
            raw_data: raw_data || null,
            message: message || null
        };

        const { data, error } = await supabase
            .from('logs')
            .insert([logData])
            .select();

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.status(201).json({
            success: true,
            log: data[0]
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
 */
app.get('/api/alerts', async (req, res) => {
    try {
        const { severity, status, rule_id, limit = 50, offset = 0 } = req.query;

        let query = supabase.from('alerts').select('*');

        if (severity) {
            query = query.eq('severity', severity.toLowerCase());
        }

        if (status) {
            query = query.eq('status', status.toLowerCase());
        }

        if (rule_id) {
            query = query.eq('rule_id', rule_id);
        }

        query = query.order('triggered_at', { ascending: false })
            .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

        const { data, error, count } = await query;

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.json({
            success: true,
            count: data ? data.length : 0,
            total: count,
            alerts: data || []
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
        const { data, error } = await supabase
            .from('alerts')
            .select('severity', { count: 'exact' })
            .neq('status', 'resolved');

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        const summary = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        data?.forEach(alert => {
            if (alert.severity in summary) {
                summary[alert.severity]++;
            }
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

        const updateData = {};
        if (status) updateData.status = status;
        if (assigned_to) updateData.assigned_to = assigned_to;
        if (notes) updateData.notes = notes;
        if (status === 'resolved') updateData.resolved_at = new Date().toISOString();

        const { data, error } = await supabase
            .from('alerts')
            .update(updateData)
            .eq('id', id)
            .select();

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({ success: false, error: 'Alert not found' });
        }

        res.json({
            success: true,
            alert: data[0]
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

        let query = supabase.from('alert_rules').select('*');

        if (enabled !== undefined) {
            query = query.eq('enabled', enabled === 'true');
        }

        if (category) {
            query = query.eq('category', category);
        }

        query = query.order('severity', { ascending: false })
            .order('name', { ascending: true });

        const { data, error } = await query;

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.json({
            success: true,
            count: data ? data.length : 0,
            rules: data || []
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

        const { data, error } = await supabase
            .from('alert_rules')
            .insert([{
                name,
                description: description || null,
                log_type: log_type.toUpperCase(),
                condition,
                severity: severity.toLowerCase(),
                category: category || null,
                created_by: created_by || 'api'
            }])
            .select();

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.status(201).json({
            success: true,
            rule: data[0]
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

        let query = supabase
            .from('labs')
            .select('id, title, description, difficulty, max_score, created_at');

        if (difficulty) {
            query = query.eq('difficulty', difficulty);
        }

        if (published !== undefined) {
            query = query.eq('published', published === 'true');
        }

        query = query.order('created_at', { ascending: false });

        const { data, error } = await query;

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.json({
            success: true,
            count: data ? data.length : 0,
            labs: data || []
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

        const { data, error } = await supabase
            .from('labs')
            .select('*')
            .eq('id', id)
            .single();

        if (error || !data) {
            return res.status(404).json({ success: false, error: 'Lab not found' });
        }

        res.json({
            success: true,
            lab: data
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

        const { data, error } = await supabase
            .from('lab_instances')
            .insert([{
                lab_id: id,
                user_id
            }])
            .select();

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.status(201).json({
            success: true,
            instance: data[0]
        });
    } catch (err) {
        console.error('Error starting lab:', err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// DASHBOARD & STATIC FILES
// ============================================================================

const path = require('path');

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        supabase: supabaseUrl
    });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
    console.log(`
    ╔════════════════════════════════════╗
    ║  CyberAcademy SIEM API Server      ║
    ║  Listening on http://localhost:${PORT}  ║
    ║  Database: Supabase                ║
    ╚════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down gracefully...');
    process.exit(0);
});
