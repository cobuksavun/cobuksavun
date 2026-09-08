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
    try {
        console.log('✅ GET / handler called');
        res.setHeader('Content-Type', 'text/plain');
        res.status(200).send('OK - CyberAcademy SIEM Dashboard');
    } catch (err) {
        console.error('❌ Error in GET /:', err);
        res.status(500).send('Error');
    }
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
