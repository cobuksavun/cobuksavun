const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Supabase
const supabaseUrl = process.env.SUPABASE_URL || 'https://nxfjyntjcckrsldewhtc.supabase.co';
const supabaseKey = process.env.SUPABASE_ANON_KEY;
let supabase = null;

if (supabaseKey) {
    try {
        supabase = createClient(supabaseUrl, supabaseKey);
        console.log('✅ Supabase connected');
    } catch (err) {
        console.warn('⚠️ Supabase error:', err.message);
    }
}

// ============================================================================
// DASHBOARD ROUTE
// ============================================================================

app.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>CyberAcademy</title><style>body{margin:0;padding:0;font-family:Segoe UI,sans-serif;background:#0f1419;color:#e0e6ed;height:100vh;}h1{color:#00d4ff;text-align:center;padding-top:50px;}.container{display:flex;height:100vh;}.sidebar{width:220px;background:#1a1f2e;padding:20px;border-right:1px solid #2a3142;}.logo{font-size:16px;font-weight:600;color:#00d4ff;margin-bottom:30px;}.main{flex:1;display:flex;flex-direction:column;}.topbar{background:#1a1f2e;border-bottom:1px solid #2a3142;padding:15px 25px;}.content{flex:1;overflow-y:auto;padding:25px;}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:30px;}.card{background:#1a1f2e;border:1px solid #2a3142;border-left:4px solid #00d4ff;padding:16px;border-radius:8px;text-align:center;}.card.critical{border-left-color:#e24b4a;}.num{font-size:32px;font-weight:600;margin:10px 0;}.label{font-size:11px;color:#5a6b7d;text-transform:uppercase;}.table-section{background:#1a1f2e;border:1px solid #2a3142;border-radius:8px;padding:20px;}table{width:100%;font-size:12px;border-collapse:collapse;margin-top:15px;}th{background:#0f1419;color:#5a6b7d;padding:12px;text-align:left;border-bottom:1px solid #2a3142;}td{padding:12px;border-bottom:1px solid #2a3142;}tr:hover{background:#252d3d;}.ip{color:#00d4ff;}.status{color:#90ee90;}</style></head><body><div class="container"><div class="sidebar"><div class="logo">🛡 CyberAcademy</div><div style="color:#00d4ff;padding:10px;font-size:13px;">Dashboard</div></div><div class="main"><div class="topbar"><div>Live SIEM Dashboard</div><div class="status">● Connected</div></div><div class="content"><h1>Real-time Monitoring</h1><div class="cards"><div class="card critical"><div class="label">Critical</div><div class="num" id="c">0</div></div><div class="card"><div class="label">High</div><div class="num" id="h">0</div></div><div class="card"><div class="label">Medium</div><div class="num" id="m">0</div></div><div class="card"><div class="label">Low</div><div class="num" id="l">0</div></div></div><div class="table-section"><h2>Recent Events (Brute Force Attack)</h2><table><thead><tr><th>Timestamp</th><th>Source IP</th><th>User</th><th>Action</th></tr></thead><tbody id="logs"><tr><td colspan="4" style="text-align:center;">Loading...</td></tr></tbody></table></div></div></div></div><script>const API="https://cobuksavun-production.up.railway.app";function load(){fetch(API+"/api/logs?log_type=WINDOWS_EVENT&limit=20").then(r=>r.json()).then(d=>{const logs=d.logs||[];const tb=document.getElementById("logs");if(logs.length===0){tb.innerHTML="<tr><td colspan=4 style=text-align:center;>No logs</td></tr>";return}tb.innerHTML=logs.map(l=>"<tr><td>"+new Date(l.timestamp).toLocaleString()+"</td><td><span class=ip>"+l.source_ip+"</span></td><td>"+(l.user_name||"-")+"</td><td>"+l.action+"</td></tr>").join("")}).catch(e=>{document.getElementById("logs").innerHTML="<tr><td colspan=4 style=color:#e24b4a;>Error: "+e.message+"</td></tr>"});fetch(API+"/api/alerts/summary").then(r=>r.json()).then(d=>{const a=d.summary||{};document.getElementById("c").textContent=a.critical||0;document.getElementById("h").textContent=a.high||0;document.getElementById("m").textContent=a.medium||0;document.getElementById("l").textContent=a.low||0}).catch(e=>console.error(e))}load();setInterval(load,10000);</script></body></html>`);
});

// ============================================================================
// API: LOGS
// ============================================================================

app.get('/api/logs', async (req, res) => {
    if (!supabase) {
        return res.status(503).json({ success: false, error: 'Database unavailable' });
    }

    try {
        const { log_type, limit = 100, offset = 0 } = req.query;
        let query = supabase.from('logs').select('*');
        
        if (log_type) {
            query = query.eq('log_type', log_type.toUpperCase());
        }

        query = query.order('timestamp', { ascending: false })
            .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

        const { data, error } = await query;

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.json({ success: true, logs: data || [], count: data ? data.length : 0 });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/logs', async (req, res) => {
    if (!supabase) {
        return res.status(503).json({ success: false, error: 'Database unavailable' });
    }

    try {
        const { timestamp, log_type, source_ip, dest_ip, source_port, dest_port, protocol, action, result, user_name, severity, message } = req.body;

        if (!log_type || !source_ip || !dest_ip) {
            return res.status(400).json({ success: false, error: 'Missing required fields' });
        }

        const { data, error } = await supabase
            .from('logs')
            .insert([{
                timestamp: timestamp || new Date().toISOString(),
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
                message: message || null
            }])
            .select();

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.status(201).json({ success: true, log: data[0] });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// API: ALERTS
// ============================================================================

app.get('/api/alerts/summary', async (req, res) => {
    if (!supabase) {
        return res.json({ success: true, summary: { critical: 0, high: 0, medium: 0, low: 0 } });
    }

    try {
        const { data, error } = await supabase
            .from('alerts')
            .select('severity')
            .neq('status', 'resolved');

        if (error) {
            return res.json({ success: true, summary: { critical: 0, high: 0, medium: 0, low: 0 } });
        }

        const summary = { critical: 0, high: 0, medium: 0, low: 0 };
        data?.forEach(alert => {
            if (alert.severity in summary) {
                summary[alert.severity]++;
            }
        });

        res.json({ success: true, summary });
    } catch (err) {
        res.json({ success: true, summary: { critical: 0, high: 0, medium: 0, low: 0 } });
    }
});

app.get('/api/alerts', async (req, res) => {
    if (!supabase) {
        return res.status(503).json({ success: false, error: 'Database unavailable' });
    }

    try {
        const { limit = 50, offset = 0 } = req.query;
        const { data, error } = await supabase
            .from('alerts')
            .select('*')
            .order('triggered_at', { ascending: false })
            .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

        if (error) {
            return res.status(500).json({ success: false, error: error.message });
        }

        res.json({ success: true, alerts: data || [] });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// API: LABS
// ============================================================================

app.get('/api/labs', async (req, res) => {
    if (!supabase) {
        return res.status(503).json({ success: false, error: 'Database unavailable' });
    }

    try {
        const { difficulty, published } = req.query;
        let query = supabase.from('labs').select('id, title, description, difficulty, max_score, created_at');

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

        res.json({ success: true, labs: data || [] });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/labs/:id', async (req, res) => {
    if (!supabase) {
        return res.status(503).json({ success: false, error: 'Database unavailable' });
    }

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

        res.json({ success: true, lab: data });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

// ============================================================================
// HEALTH
// ============================================================================

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================================
// ERROR HANDLER
// ============================================================================

app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Not found' });
});

// ============================================================================
// START
// ============================================================================

app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════╗
║  CyberAcademy SIEM API Server      ║
║  Listening on port ${PORT}              ║
║  Dashboard: GET /                  ║
║  Health: GET /health               ║
╚════════════════════════════════════╝
    `);
});

process.on('SIGINT', () => {
    console.log('\nShutdown...');
    process.exit(0);
});
