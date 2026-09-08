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
    const html = '<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>CyberAcademy SIEM</title><style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0f1419;color:#e0e6ed;font-family:Segoe UI,sans-serif;height:100vh}#app{display:flex;height:100vh}.sidebar{width:220px;background:#1a1f2e;padding:20px;border-right:1px solid #2a3142;overflow-y:auto}.logo{font-size:16px;font-weight:600;color:#00d4ff;margin-bottom:30px}.nav-item{padding:10px 12px;margin:8px 0;border-radius:6px;cursor:pointer;color:#a0aec0;font-size:13px;transition:all 0.2s}.nav-item:hover{background:#2a3142;color:#e0e6ed}.nav-item.active{background:#00d4ff;color:#0f1419;font-weight:600}.main{flex:1;display:flex;flex-direction:column}.topbar{background:#1a1f2e;border-bottom:1px solid #2a3142;padding:15px 25px;display:flex;justify-content:space-between;align-items:center}.status-dot{width:8px;height:8px;background:#90ee90;border-radius:50%;animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}.content{flex:1;overflow-y:auto;padding:25px}.header h1{font-size:28px;margin-bottom:10px;color:#e0e6ed}.header p{color:#5a6b7d;font-size:13px;margin-bottom:25px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:30px}.card{background:#1a1f2e;border:1px solid #2a3142;border-left:4px solid #00d4ff;border-radius:8px;padding:16px;text-align:center}.card.critical{border-left-color:#e24b4a}.card.high{border-left-color:#ba7517}.card.medium{border-left-color:#ef9f27}.card.low{border-left-color:#378add}.card-num{font-size:32px;font-weight:600;margin:10px 0;color:#e0e6ed}.card-label{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#5a6b7d;margin-bottom:8px}.card-desc{font-size:12px;color:#a0aec0}.logs-section{background:#1a1f2e;border:1px solid #2a3142;border-radius:8px;padding:20px}.logs-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}.logs-header h2{font-size:16px;color:#e0e6ed}.status-text{font-size:12px;color:#5a6b7d}table{width:100%;font-size:12px;font-family:Courier New,monospace;border-collapse:collapse}th{background:#0f1419;color:#5a6b7d;padding:12px 8px;text-align:left;font-weight:600;border-bottom:1px solid #2a3142;text-transform:uppercase;letter-spacing:0.5px}td{padding:12px 8px;border-bottom:1px solid #2a3142;color:#a0aec0}tr:hover{background:#252d3d}.ip{color:#00d4ff;font-weight:500}.status-badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:10px;font-weight:600;text-transform:uppercase}.badge-failed{background:rgba(226,75,74,0.15);color:#e24b4a}.badge-success{background:rgba(144,238,144,0.15);color:#90ee90}</style></head><body><div id="app"><div class="sidebar"><div class="logo">🛡 CyberAcademy</div><div class="nav-item active">Dashboard</div><div class="nav-item">Logs</div><div class="nav-item">Alerts</div><div class="nav-item">Rules</div><div class="nav-item">Labs</div><div class="nav-item">Cases</div></div><div class="main"><div class="topbar"><div style="font-weight:500">Live SIEM Dashboard</div><div style="display:flex;align-items:center;gap:8px;font-size:12px"><div class="status-dot"></div><span>Live</span></div></div><div class="content"><div class="header"><h1>Dashboard</h1><p>Real-time security monitoring</p></div><div class="cards"><div class="card critical"><div class="card-label">Critical</div><div class="card-num" id="c">0</div><div class="card-desc">Active threats</div></div><div class="card high"><div class="card-label">High</div><div class="card-num" id="h">0</div><div class="card-desc">High priority</div></div><div class="card medium"><div class="card-label">Medium</div><div class="card-num" id="m">0</div><div class="card-desc">Investigate soon</div></div><div class="card low"><div class="card-label">Low</div><div class="card-num" id="l">0</div><div class="card-desc">Info monitoring</div></div></div><div class="logs-section"><div class="logs-header"><h2>Recent Events</h2><div class="status-text" id="status">Loading...</div></div><table><thead><tr><th>Timestamp</th><th>Source IP</th><th>User</th><th>Action</th><th>Status</th></tr></thead><tbody id="logs"><tr><td colspan="5" style="text-align:center">Loading logs...</td></tr></tbody></table></div></div></div></div></div><script>const API="https://cobuksavun-production.up.railway.app";function load(){fetch(API+"/api/logs?log_type=WINDOWS_EVENT&limit=20").then(r=>r.json()).then(d=>{const logs=d.logs||[];const tbody=document.getElementById("logs");if(logs.length===0){tbody.innerHTML="<tr><td colspan=5 style=text-align:center>No logs found</td></tr>";return}tbody.innerHTML=logs.map(l=>"<tr><td>"+new Date(l.timestamp).toLocaleString()+"</td><td><span class=ip>"+l.source_ip+"</span></td><td>"+(l.user_name||"-")+"</td><td>"+l.action+"</td><td><span class=status-badge"+(l.result==="failed"?" style=background:rgba(226,75,74,0.15);color:#e24b4a>❌ Failed":"  style=background:rgba(144,238,144,0.15);color:#90ee90>✓ Success")+"</span></td></tr>").join("")}).catch(e=>{document.getElementById("logs").innerHTML="<tr><td colspan=5 style=color:#e24b4a>Error: "+e.message+"</td></tr>";document.getElementById("status").textContent="Error: "+e.message});fetch(API+"/api/alerts/summary").then(r=>r.json()).then(d=>{const a=d.summary||{};document.getElementById("c").textContent=a.critical||0;document.getElementById("h").textContent=a.high||0;document.getElementById("m").textContent=a.medium||0;document.getElementById("l").textContent=a.low||0;document.getElementById("status").textContent="Connected"}).catch(e=>{document.getElementById("status").textContent="Error connecting to API"})}load();setInterval(load,10000)</script></body></html>';
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
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
// ERROR HANDLER (must be last)
// ============================================================================

app.use((err, req, res, next) => {
    console.error('❌ Global error handler:', err);
    res.status(500).json({ error: 'Internal server error', message: err.message });
});

app.use((req, res) => {
    console.log('❌ 404 Not Found:', req.path);
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
