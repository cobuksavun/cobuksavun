# CyberAcademy SIEM Platform - Setup Guide

## 📋 Project Overview

Bu bir **siber güvenlik eğitim platformu** (Let's Defend tarzı) ile **gerçek SIEM araçlarını simüle eden** arayüz.

**Mimarisi:**
- **Frontend:** React (artifact'ta - browser'da çalışıyor)
- **Backend:** Node.js/Express REST API
- **Database:** PostgreSQL (TimescaleDB isteğe bağlı)

---

## 🚀 HIZLI START (Localhost'ta)

### Adım 1: Prerequisites Kur

```bash
# PostgreSQL yüklü mü kontrol et
psql --version

# Node.js yüklü mü kontrol et
node --version
npm --version
```

Yoksa:
- **PostgreSQL:** https://www.postgresql.org/download/
- **Node.js:** https://nodejs.org/

---

### Adım 2: Database Oluştur

```bash
# PostgreSQL'e bağlan (Linux/Mac)
sudo -u postgres psql

# veya (Windows)
psql -U postgres

# Database oluştur
CREATE DATABASE cyber_academy;
\q
```

---

### Adım 3: Schema'yı Yükle

```bash
# Linux/Mac
psql -U postgres -d cyber_academy -f schema.sql

# Windows
psql -U postgres -d cyber_academy -f schema.sql
```

**Kontrol et:**
```bash
psql -U postgres -d cyber_academy -c "SELECT COUNT(*) FROM alert_rules;"
# Output: 12 kuralı görmeli
```

---

### Adım 4: Backend'i Kur ve Çalıştır

```bash
# 1. Dependencies yükle
npm install

# 2. .env dosyasını oluştur
cp .env.example .env

# .env dosyasını aç ve PostgreSQL şifreni gir
# (veya defaults'ı kullan)

# 3. Backend başlat
npm start

# Output:
# ╔════════════════════════════════════╗
# ║  CyberAcademy SIEM API Server      ║
# ║  Listening on http://localhost:5000  ║
# ╚════════════════════════════════════╝
```

---

### Adım 5: Frontend'i Çalıştır

Frontend zaten artifact'ta canlı. Şimdi API'ye bağla:

1. Browser'da konuşma çıkışı sabit (artifact'ta görmüşsün)
2. Artifact'taki `search-box` ve `nav-item` öğeleri çalışıyor
3. **Backend'i bağlamak için React component'ini güncelle:**

Artifact'ın `<script>` bölümüne şunu ekle:

```javascript
// API client
const API_URL = 'http://localhost:5000';

async function fetchLogs() {
    try {
        const response = await fetch(`${API_URL}/api/logs?limit=50`);
        const data = await response.json();
        if (data.success) {
            renderLogs(data.logs); // Artifact'ın renderLogs fonksiyonunu kullan
        }
    } catch (err) {
        console.error('API error:', err);
    }
}

// Page yüklenince çalıştır
document.addEventListener('DOMContentLoaded', fetchLogs);
```

---

## 🧪 API Test Et

### Terminal'de cURL kullan:

```bash
# Health check
curl http://localhost:5000/health

# Alert summary'yi al
curl http://localhost:5000/api/alerts/summary

# Tüm kuralları listele
curl http://localhost:5000/api/rules

# Lab'ları listele
curl http://localhost:5000/api/labs

# Logs'ı getir (brute force'tan)
curl "http://localhost:5000/api/logs?log_type=WINDOWS_EVENT&limit=10"
```

### Postman/Insomnia ile:

1. `http://localhost:5000`'ı API endpoint olarak ekle
2. **GET** `/api/logs` - Logs al
3. **POST** `/api/logs` - Yeni log ekle (test)

**POST test payload:**
```json
{
  "timestamp": "2024-01-15T14:23:45Z",
  "log_type": "WINDOWS_EVENT",
  "source_ip": "203.0.113.45",
  "dest_ip": "192.168.1.50",
  "protocol": "RDP",
  "action": "FAILED",
  "result": "failed",
  "user_name": "admin",
  "severity": 8,
  "message": "Failed RDP login attempt"
}
```

---

## 📊 Database Şeması

### Ana Tablolar:

| Tablo | Amaç |
|-------|------|
| `logs` | Tüm security events (firewall, DNS, Windows, vb) |
| `alert_rules` | Detection kuralları (12 adet seed) |
| `alerts` | Tetiklenen alertler |
| `labs` | Training senaryoları |
| `lab_instances` | Öğrencilerin lab çalışmaları |
| `cases` | Incident investigation case'leri |
| `audit_logs` | Platform activity logging |

**Verileri kontrol et:**
```bash
psql -U postgres -d cyber_academy

\dt                    # Tüm tabloları göster
SELECT COUNT(*) FROM logs;              # Kaç log?
SELECT COUNT(*) FROM alert_rules;       # Kaç kural?
SELECT * FROM alert_rules LIMIT 3;      # İlk 3 kuralı göster
```

---

## 🔌 API Endpoints (v1)

### Logs
- `GET /api/logs` - Logs al (filter support)
- `POST /api/logs` - Yeni log ekle

### Alerts
- `GET /api/alerts` - Active alerts
- `GET /api/alerts/summary` - Alert count by severity
- `PATCH /api/alerts/:id` - Update alert status

### Alert Rules
- `GET /api/rules` - Get all rules
- `POST /api/rules` - Create new rule

### Labs
- `GET /api/labs` - List labs
- `GET /api/labs/:id` - Get lab details
- `POST /api/labs/:id/start` - Start lab instance

---

## 🎓 İlk Lab: Brute Force Detection

### Senaryo:
```
Tarih: 15 Ocak 2024, 14:00-15:00
Firmaya brute force saldırısı yapılıyor (RDP).
```

### Lab Data (Database'de):
```sql
SELECT * FROM logs 
WHERE source_ip = '203.0.113.45' 
  AND log_type = 'WINDOWS_EVENT' 
  AND result = 'failed'
ORDER BY timestamp DESC;
```

### Öğrenci Yapacakları:
1. Attacker IP'sini bulma: **203.0.113.45**
2. Failure count'u sayma: **40+ attempts**
3. Hedef user'ları tanımlama: **admin, root, backup**
4. Attack duration'u hesaplama: **~5 dakika**
5. Mitigasyon önerisi: **Fail2ban, WAF kuralı, IP block**

---

## 🛠️ Development Mode

**Auto-reload dengan nodemon:**

```bash
npm install --save-dev nodemon
npm run dev  # Kod değişince otomatik restart
```

---

## 📝 Next Steps

**Şu aşamada yapacaklar:**

- [ ] Backend'i localhost'ta çalıştırma
- [ ] Artifact'taki React dashboard'ı API'ye bağlama
- [ ] Brute Force lab senaryosunun log verilerini seed etme
- [ ] Lab submission sistem oluşturma (öğrenci cevapları)
- [ ] Frontend component'ler geliştirme (logs table, alerts panel, rule builder)
- [ ] Production deploy (AWS/Heroku/DigitalOcean)

---

## 🤝 Soru?

Backend ve frontend arasında veri akışı:

```
Frontend (React/Artifact)
    ↓
    ├─→ Search/Filter user input
    ├─→ Fetch /api/logs?log_type=WINDOWS_EVENT
    │
Backend (Express/Node.js)
    ↓
    ├─→ PostgreSQL Query
    ├─→ Return JSON
    │
Frontend (React/Artifact)
    ↓
    └─→ renderLogs(data.logs)
```

---

## 📚 Useful PostgreSQL Commands

```bash
# Connect to database
psql -U postgres -d cyber_academy

# List tables
\dt

# Describe table
\d logs

# Count logs
SELECT COUNT(*) FROM logs;

# Show all failed RDP attempts
SELECT COUNT(*), source_ip FROM logs 
WHERE log_type = 'WINDOWS_EVENT' AND result = 'failed'
GROUP BY source_ip
ORDER BY COUNT(*) DESC;

# Export logs to CSV
\copy (SELECT * FROM logs LIMIT 100) TO 'export.csv' WITH CSV HEADER;

# Delete all logs (CAREFUL!)
DELETE FROM logs;
```

---

**Hazırsan başlayalım! 🚀**
