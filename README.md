# TrustVault — Secure Document Sharing with a Real Audit Trail

TrustVault is an enterprise-grade document security and collaboration application engineered in Python with FastAPI, SQLAlchemy 2, and Argon2id. It guarantees private-by-default access, strict server-side resource authorization, immediate permission revocation, and an independently verifiable SHA-256 tamper-evident hash-chained audit trail.

---

## Key Features

1. **Enterprise Identity & Authentication**:
   - Argon2id password hashing (RFC 9106: 64MB memory cost, 2 iterations, hybrid type).
   - Server-side session management using 48-byte URL-safe cryptographic tokens stored as SHA-256 digests.
   - HttpOnly, SameSite=Lax session cookies.
   - Sliding-window rate limiting on login and password reset endpoints.
   - Single-use, expiring password reset tokens.

2. **Centralized Default-Deny Authorization Engine**:
   - Zero trust in frontend state; permissions evaluated on every request against authoritative database records.
   - Resource-level role segregation: Administrator, Document Owner, Viewer (READ / EDIT).
   - Insecure Direct Object Reference (IDOR) immunity across all document and permission routes.

3. **Mandatory Immediate Revocation**:
   - Document owners can grant, modify (`READ` <-> `EDIT`), and instantly revoke collaborator access.
   - Permission deletions take effect in real time; subsequent requests from revoked users are denied immediately.

4. **Private Storage & File Security**:
   - Files stored in `./private_storage/` with server-generated UUID identifiers.
   - Magic bytes file signature verification (PDF, PNG, JPG, DOCX, XLSX, CSV, JSON, TXT).
   - Path traversal mitigation and filename sanitization.

5. **Tamper-Evident SHA-256 Audit Trail**:
   - Every security-sensitive action records a canonical JSON payload hashed into a SHA-256 chain linked to the preceding block.
   - Verification endpoint `/api/audit/verify` recalculates every historical event digest from genesis to latest record, detecting any altered payloads, broken sequence gaps, or deletions.

6. **Comprehensive 14-View Responsive Interface**:
   - Built with Bootstrap 5, modern dark luxury theme, responsive sidebar navigation, interactive modals, live password strength meter, drag-and-drop file upload zone, and cryptographic verification modal.

---

## Technology Stack

- **Backend**: Python 3.10+ / 3.12+, FastAPI, Pydantic V2, SQLAlchemy 2.0
- **Database**: SQLite (Local development & test suite), PostgreSQL (Production ready)
- **Security**: Argon2id (`argon2-cffi`), SHA-256 Hash Chain, Double-Submit Signed CSRF Tokens
- **Testing**: Pytest, HTTPX, Starlette TestClient (24/24 passing tests)
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5, Bootstrap Icons

---

## Getting Started

### 1. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Run the Application
```bash
python3 run.py --port 3000 --host 0.0.0.0
# Or:
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### 3. Run Automated Tests
```bash
pytest tests/ -v
# Or:
npm test
```

### 4. Default Seeded Accounts
- **Administrator**: `admin@trustvault.local` / `TrustVault2026!Admin#`
- **User A (Alice)**: `alice@trustvault.local` / `TrustVault2026!Alice#`
- **User B (Bob)**: `bob@trustvault.local` / `TrustVault2026!Bob#`

---

## Documentation Links
- [THREATS.md](THREATS.md) — Comprehensive threat model, boundaries, and residual risks
- [SECURITY.md](SECURITY.md) — Cryptographic and authorization architecture details
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) — REST API schema and endpoint reference
- [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) — Relational schema and indexing specification
- [DEPLOYMENT.md](DEPLOYMENT.md) — Production setup instructions for Render / Cloud Run
- [DEMO_SCRIPT.md](DEMO_SCRIPT.md) — Step-by-step evaluator walkthrough
- [PROMPTS.md](PROMPTS.md) — Genuine dated development log entries
