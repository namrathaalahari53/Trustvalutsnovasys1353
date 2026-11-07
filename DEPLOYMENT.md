# TrustVault Deployment Guide

## 1. Local Development Run

### Prerequisites
- Python 3.10+ (or 3.11/3.12)
- Node.js & npm (for AI Studio development environment)

### Startup Commands
```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Start TrustVault
python3 run.py --port 3000 --host 0.0.0.0
# Or via npm
npm run dev
```

The application will be accessible at `http://localhost:3000`.

### Default Bootstrap Accounts (created on first run)
- **Administrator**: `admin@trustvault.local` / `TrustVault2026!Admin#`
- **Demo User A (Alice)**: `alice@trustvault.local` / `TrustVault2026!Alice#`
- **Demo User B (Bob)**: `bob@trustvault.local` / `TrustVault2026!Bob#`

---

## 2. Production Deployment (Render / Cloud Run / VPS)

### Environment Variables
Configure the following in your hosting provider's dashboard:

```env
ENVIRONMENT=production
SECRET_KEY=generate_high_entropy_random_secret_here_min_64_chars
DATABASE_URL=postgresql://trustvault_user:db_password@host:5432/trustvault_prod
STORAGE_DIR=/var/data/trustvault_storage
SECURE_COOKIES=true
SESSION_EXPIRE_SECONDS=86400
RESET_TOKEN_EXPIRE_SECONDS=900
```

### Production Start Command
```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 3000 --workers 4
```

### Health Check Endpoint
- Route: `GET /api/health`
- Response: `{"status": "healthy", "service": "TrustVault", "version": "1.0.0"}`

---

## 3. Persistent Storage & Object Storage Configuration
- In development, files are saved locally to `./private_storage/`.
- For multi-instance production environments (e.g., Kubernetes, Render persistent disks, AWS ECS), mount a persistent volume at `STORAGE_DIR` or configure an S3-compatible backend.
