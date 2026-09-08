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

let supabase = null;

if (supabaseKey) {
    try {
        supabase = createClient(supabaseUrl, supabaseKey);
        console.log(`✅ Connected to Supabase: ${supabaseUrl}`);
    } catch (err) {
        console.warn(`⚠️ Supabase connection warning: ${err.message}`);
    }
} else {
    console.warn('⚠️ SUPABASE_ANON_KEY not set - API endpoints will fail');
}

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
// DASHBOARD
// ============================================================================

app.get('/', (req, res) => {
    const html = '<html><head><meta charset="UTF-8"><title>CyberAcademy</title><style>body{margin:0;padding:0;font-family:Segoe UI,sans-serif;background:#0f1419;color:#e0e6ed;}h1{padding:20px;}.container{display:flex;height:100vh;}.sidebar{width:220px;background:#1a1f2e;padding:20px;border-right:1px solid #2a3142;}.logo{font-size:16px;font-weight:600;color:#00d4ff;margin-bottom:30px;}.main{flex:1;display:flex;flex-direction:column;}.topbar{background:#1a1f2e;border-bottom:1px solid #2a3142;padding:15px 25px;display:flex;justify-content:space-between;}.content{flex:1;overflow-y:auto;padding:25px;}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:30px;}.card{background:#1a1f2e;border:1px solid #2a3142;border-left:4px solid #00d4ff;padding:16px;border-radius:8px;text-align:center;}.card.critical{border-left-color:#e24b4a;}.num{font-size:32px;font-weight:600;color:#e0e6ed;margin:10px 0;}.label{font-size:11px;text-transform:uppercase;color:#5a6b7d;}.table-section{background:#1a1f2e;border:1px solid #2a3142;border-radius:8px;padding:20px;}table{width:100%;font-size:12px;border-collapse:collapse;}th{background:#0f1419;color:#5a6b7d;padding:12px;text-align:left;border-bottom:1px solid #2a3142;}td{padding:12px;border-bottom:1px solid #2a3142;}.ip{color:#00d4ff;}.status{color:#90ee90;}</style></head><body><div class="container"><div class="sidebar"><div class="logo">🛡 CyberAcademy</div><div style="color:#00d4ff;padding:10px;">Dashboard</div></div><div class="main"><div class="topbar"><div>Live SIEM Dashboard</div><div class="status">● Connected</div></div><div class="content"><h1>Real-time Monitoring</h1><div class="cards"><div class="card critical"><div class="label">Critical</div><div class="num" id="c">Loading...</div></div><div class="card"><div class="label">High</div><div class="num" id="h">Loading...</div></div><div class="card"><div class="label">Medium</div><div class="num" id="m">Loading...</div></div><div class="card"><div class="label">Low</div><div class="num" id="l">Loading...</div></div></div><div class="table-section"><h2>Recent Events (Brute Force Attack)</h2><table><thead><tr><th>Timestamp</th><th>Source IP</th><th>User</th><th>Action</th><th>Status</th></tr></thead><tbody id="logs"><tr><td colspan="5" style="text-align:center;">Loading logs...</td></tr></tbody></table></div></div></div></div><script>const API="https://cobuksavun-production.up.railway.app";function load(){fetch(API+"/api/logs?log_type=WINDOWS_EVENT&limit=20").then(r=>r.json()).then(d=>{const logs=d.logs||[];const tb=document.getElementById("logs");if(logs.length===0){tb.innerHTML="<tr><td colspan=\"5\" style=\"text-align:center;\">No logs found</td></tr>";return;}tb.innerHTML=logs.map(l=>"<tr><td>"+new Date(l.timestamp).toLocaleString()+"</td><td><span class=\"ip\">"+l.source_ip+"</span></td><td>"+(l.user_name||"-")+"</td><td>"+l.action+"</td><td>"+(l.result==="failed"?"❌ Failed":"✓ Success")+"</td></tr>").join("")}).catch(e=>{document.getElementById("logs").innerHTML="<tr><td colspan=\"5\" style=\"color:#e24b4a;\">Error: "+e.message+"</td></tr>"});fetch(API+"/api/alerts/summary").then(r=>r.json()).then(d=>{const a=d.summary||{};document.getElementById("c").textContent=a.critical||0;document.getElementById("h").textContent=a.high||0;document.getElementById("m").textContent=a.medium||0;document.getElementById("l").textContent=a.low||0}).catch(e=>console.error("Alert error:",e))}load();setInterval(load,10000);</script></body></html>';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
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
        if (!supabase) {
            return res.status(503).json({ success: false, error: 'Database not available' });
        }

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
    ║  Dashboard: GET /                  ║
    ╚════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down gracefully...');
    process.exit(0);
});
