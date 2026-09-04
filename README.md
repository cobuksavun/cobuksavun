# 🛡️ CyberAcademy - SIEM-Based Cybersecurity Training Platform

Siber güvenlik profesyonelleri için **interaktif eğitim platformu**. Let's Defend tarzı laboratuvarlar + gerçekçi SIEM araçları simülasyonu.

## 🎯 Özellikler

- **SIEM Dashboard**: Splunk/ArcSight tarzı profesyonel arayüz
- **Realistic Logs**: Firewall, DNS, Windows Event, IIS, VPN, DC logs
- **Alert Rules**: 12+ önceden tanımlanmış detection kuralı
- **Interactive Labs**: Brute force, lateral movement, data exfiltration
- **Real-time Alerts**: Otomatik alert generation ve scoring
- **Case Studies**: Gerçekçi incident investigation senaryoları

## 🏗️ Mimarisi

```
┌─────────────────────────────────────┐
│   Frontend (React)                  │
│   - SIEM Dashboard                  │
│   - Log Viewer & Filter             │
│   - Lab Interface                   │
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│   Backend (Node.js/Express)         │
│   - REST API                        │
│   - Alert Rule Engine               │
│   - Lab Scoring                     │
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│   Database (PostgreSQL)             │
│   - Logs (millions of records)      │
│   - Alerts, Rules, Labs             │
│   - User Progress Tracking          │
└─────────────────────────────────────┘
```

## 📦 Tech Stack

- **Frontend**: React + TailwindCSS
- **Backend**: Node.js + Express
- **Database**: PostgreSQL (TimescaleDB optional)
- **Hosting**: Railway (Backend+DB) + Vercel (Frontend)

## 🚀 Quick Start

### Prerequisites
- Node.js 16+
- PostgreSQL 12+

### Installation

1. **Clone & Install**
```bash
git clone https://github.com/cobuksavun/cobuksavun.git
cd cobuksavun/backend
npm install
```

2. **Database Setup**
```bash
createdb cyber_academy
psql -U postgres -d cyber_academy -f schema.sql
```

3. **Environment Variables**
```bash
cp .env.example .env
# Edit .env with your database credentials
```

4. **Start Backend**
```bash
npm start
# Server runs on http://localhost:5000
```

5. **Test API**
```bash
curl http://localhost:5000/health
```

## 📚 API Endpoints

### Logs
- `GET /api/logs` - Retrieve logs (with filters)
- `POST /api/logs` - Ingest new log

### Alerts
- `GET /api/alerts` - Get active alerts
- `GET /api/alerts/summary` - Alert count by severity
- `PATCH /api/alerts/:id` - Update alert status

### Rules
- `GET /api/rules` - List detection rules
- `POST /api/rules` - Create custom rule

### Labs
- `GET /api/labs` - List available labs
- `GET /api/labs/:id` - Get lab details
- `POST /api/labs/:id/start` - Start lab instance

## 🎓 First Lab: Brute Force Attack Detection

**Scenario:**
```
Jan 15, 2024 - 14:00-15:00
RDP server is under attack with 40+ failed login attempts from 203.0.113.45
```

**Objectives:**
1. Identify attacker's IP address
2. Count total failed attempts
3. List targeted user accounts
4. Calculate attack duration
5. Recommend mitigation

**Expected Results:**
- Attacker IP: 203.0.113.45
- Failed Attempts: 40+
- Target Users: admin, root, backup
- Duration: ~5 minutes

## 📊 Database Schema

### Core Tables
| Table | Purpose |
|-------|---------|
| `logs` | Security events (firewall, DNS, Windows, etc) |
| `alert_rules` | Detection rules (12 seed rules) |
| `alerts` | Triggered alerts |
| `labs` | Training scenarios |
| `lab_instances` | Student lab sessions |
| `cases` | Incident investigation cases |
| `audit_logs` | Platform activity logging |

## 🔑 Alert Rules (Pre-built)

1. **RDP Brute Force** - 10+ failed RDP attempts in 10 min
2. **SSH Brute Force** - 15+ SSH denials in 5 min
3. **VPN Auth Failures** - 5+ failed VPN attempts
4. **Lateral Movement** - Internal IPs to risky ports
5. **Data Exfiltration** - >1GB outbound in 5 min
6. **DNS Tunneling** - Suspicious DNS patterns
7. **Port Scanning** - Sequential port connections
8. **SQL Injection** - SQLi patterns in HTTP requests
9. **Privilege Escalation** - Failed admin access
10. **C2 Communication** - Known malicious domains
11. **Account Lockout Cascade** - Multiple lockouts from subnet
12. **Blacklisted IP** - Connection from malicious IP

## 🛠️ Development

### Watch mode (auto-reload)
```bash
npm run dev
```

### Database commands
```bash
# Connect
psql -U postgres -d cyber_academy

# Show tables
\dt

# Count logs
SELECT COUNT(*) FROM logs;

# View alert rules
SELECT name, severity FROM alert_rules;
```

## 📝 Documentation

- [Setup Guide](./docs/SETUP.md) - Detailed installation
- [API Docs](./docs/API.md) - API reference
- [Database Schema](./backend/schema.sql) - Database design

## 🚢 Deployment

### Railway.app (Backend + Database)
1. Sign up: https://railway.app
2. Connect GitHub repo
3. Set environment variables
4. Deploy (automatic)

### Vercel (Frontend)
1. Sign up: https://vercel.com
2. Import project
3. Deploy (automatic)

## 📈 Roadmap

- [ ] Frontend React component development
- [ ] Lab submission & auto-grading
- [ ] User authentication & progress tracking
- [ ] More lab scenarios (SQL injection, lateral movement, C2)
- [ ] Real-time log streaming (WebSocket)
- [ ] Advanced alert rules engine
- [ ] Case studies with step-by-step solutions
- [ ] Mobile app (React Native)

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

MIT License - see LICENSE file

## 👨‍💻 Author

**cobuksavun** - SIEM & Threat Intelligence Specialist

## 📞 Support

- Issues: [GitHub Issues](https://github.com/cobuksavun/cobuksavun/issues)
- Email: (add contact)
- Discord: (add link)

---

**Built with ❤️ for cybersecurity professionals & students**
