# Deploying TrustVault to Render (render.com)

TrustVault is fully pre-configured for seamless, zero-issue deployment on Render as a Web Service.

---

## 🚀 1-Click / Blueprint Deployment

1. Push this repository to GitHub or GitLab.
2. Log in to [Render Dashboard](https://dashboard.render.com).
3. Click **New +** -> **Blueprint**.
4. Connect your TrustVault repository.
5. Render will automatically read `render.yaml` and configure:
   - **Environment**: Node.js
   - **Build Command**: `npm install`
   - **Start Command**: `npm start` (runs `tsx server.ts`)
   - **Health Check Path**: `/api/health`
   - **Port**: Dynamically bound via `process.env.PORT`
6. Click **Apply**. Render will build and launch your instance with an active SSL certificate (`https://your-app.onrender.com`).

---

## ⚙️ Manual Web Service Deployment (Alternative)

If creating a Web Service manually without Blueprints:

| Setting | Value |
| :--- | :--- |
| **Name** | `trustvault` |
| **Language** | `Node` |
| **Branch** | `main` |
| **Build Command** | `npm install` |
| **Start Command** | `npm start` |
| **Health Check Path** | `/api/health` |
| **Instance Type** | Free or Starter |

### Recommended Environment Variables:
- `NODE_ENV`: `production`
- `PORT`: (Auto-set by Render)

---

## 🛡️ Pre-Configured Render Safeguards

1. **Dynamic Port Binding**:
   The server binds to `0.0.0.0` and listens on `process.env.PORT || 3000`.
2. **Built-in Health Checks**:
   Render pings `GET /api/health` on startup, which responds with `HTTP 200 OK` (`{"status":"healthy","service":"TrustVault"}`). Zero false-positive deployment timeouts.
3. **No Native Compilation Gotchas**:
   TrustVault uses Node 22's native `node:sqlite` and `node:crypto`. No python-gyp compilation failures or missing Linux shared libraries on Render's container workers.
4. **Self-Healing Storage**:
   `private_storage/` and SQLite tables automatically initialize on boot if absent.
5. **Multi-Channel Authentication**:
   Supports `Authorization: Bearer` and `X-Session-Token` headers alongside SameSite=None cookies, preventing third-party cookie blocking across subdomains or iframes.

---

## 🔍 Post-Deploy Verification

Once deployed, visit your Render URL:
- `https://your-app.onrender.com/` (TrustVault Application Dashboard)
- `https://your-app.onrender.com/api/health` (Health Endpoint)
- Run the **Live Security Audit** tab to verify all 10 security measures in production!
