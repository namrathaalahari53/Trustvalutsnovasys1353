# TrustVault REST API Documentation

Base URL: `http://localhost:3000/api` (or environment `APP_URL`)

All state-changing endpoints (`POST`, `PATCH`, `DELETE`) require the `X-CSRF-Token` header matching the active session's CSRF token.

---

## 1. Authentication Endpoints

### POST `/api/auth/register`
Creates a new user account.
- **Request Body**:
  ```json
  {
    "email": "user@trustvault.local",
    "username": "johndoe",
    "password": "Password#2026Secure!"
  }
  ```
- **Response** (`201 Created`):
  ```json
  {
    "user": {
      "id": "c1f7a8b9-...",
      "email": "user@trustvault.local",
      "username": "johndoe",
      "role": "user",
      "is_active": true,
      "created_at": "2026-11-05T12:00:00Z"
    },
    "csrf_token": "token.signature",
    "message": "Registration successful."
  }
  ```
- **Cookies Set**: `tv_session` (HttpOnly), `tv_csrf`.

### POST `/api/auth/login`
Authenticates user and initiates server-side session.
- **Request Body**:
  ```json
  {
    "email": "user@trustvault.local",
    "password": "Password#2026Secure!"
  }
  ```
- **Response** (`200 OK`):
  ```json
  {
    "user": { ... },
    "csrf_token": "...",
    "message": "Login successful."
  }
  ```

### POST `/api/auth/logout`
Terminates current session in database and clears session cookies.
- **Headers**: `X-CSRF-Token: <token>`
- **Response** (`200 OK`): `{"message": "Logged out successfully."}`

### GET `/api/auth/me`
Fetches authenticated user identity and active CSRF token.
- **Response** (`200 OK`):
  ```json
  {
    "user": { ... },
    "csrf_token": "..."
  }
  ```

### POST `/api/auth/forgot-password`
Generates expiring, single-use password reset token.
- **Request Body**: `{"email": "user@trustvault.local"}`
- **Response** (`200 OK`):
  ```json
  {
    "message": "If that email is registered, a password reset token has been generated.",
    "reset_token": "secure_urlsafe_token"
  }
  ```

### POST `/api/auth/reset-password`
Consumes reset token, updates password with Argon2id, and invalidates all active sessions.
- **Request Body**:
  ```json
  {
    "token": "secure_urlsafe_token",
    "new_password": "NewStrongPassword#2026!"
  }
  ```
- **Response** (`200 OK`): `{"message": "Password has been successfully reset."}`

---

## 2. Document Management Endpoints

### POST `/api/documents`
Uploads confidential document with magic bytes validation.
- **Form Data**:
  - `file`: Multipart file upload
  - `title`: String
  - `description`: Optional text
- **Headers**: `X-CSRF-Token: <token>`
- **Response** (`201 Created`):
  ```json
  {
    "id": "doc-uuid",
    "owner_id": "user-uuid",
    "owner_username": "johndoe",
    "title": "Financial Report",
    "original_filename": "report.pdf",
    "file_size": 1048576,
    "mime_type": "application/pdf",
    "file_hash_sha256": "3a8b...",
    "is_owner": true,
    "current_user_permission": "OWNER",
    "created_at": "2026-11-05T12:00:00Z"
  }
  ```

### GET `/api/documents`
Lists documents authorized for the current user.
- **Query Parameters**:
  - `scope`: `all` | `owned` | `shared` | `admin`
  - `search`: Filter by title/filename
  - `filter_type`: Filter by extension (e.g. `pdf`, `docx`, `xlsx`)
- **Response** (`200 OK`): `{"total": 5, "items": [...]}`

### GET `/api/documents/{document_id}`
Retrieves document metadata. Requires ownership or active `READ`/`EDIT` permission.
- **Response** (`200 OK`): DocumentResponse object

### PATCH `/api/documents/{document_id}`
Updates document title or description. Requires ownership or active `EDIT` permission.
- **Request Body**: `{"title": "Updated Title", "description": "New notes"}`
- **Headers**: `X-CSRF-Token: <token>`
- **Response** (`200 OK`): Updated DocumentResponse

### DELETE `/api/documents/{document_id}`
Deletes document and removes physical storage file. Strictly owner-only.
- **Headers**: `X-CSRF-Token: <token>`
- **Response** (`200 OK`): `{"message": "Document deleted successfully."}`

### GET `/api/documents/{document_id}/download`
Streams physical file content with real-time permission check.
- **Response** (`200 OK`): Binary stream with `Content-Disposition: attachment; filename="report.pdf"`

---

## 3. Permissions & Sharing Endpoints

### POST `/api/documents/{document_id}/permissions`
Grants or updates sharing permission for a registered collaborator. Owner-only.
- **Request Body**: `{"user_email": "alice@trustvault.local", "permission": "READ"}`
- **Headers**: `X-CSRF-Token: <token>`
- **Response** (`201 Created`): PermissionResponse

### GET `/api/documents/{document_id}/permissions`
Lists all collaborators and permission levels on a document. Owner-only.
- **Response** (`200 OK`): `{"total": 2, "items": [...]}`

### PATCH `/api/permissions/{permission_id}`
Modifies collaborator permission level (`READ` <-> `EDIT`). Owner-only.
- **Request Body**: `{"permission": "EDIT"}`
- **Headers**: `X-CSRF-Token: <token>`
- **Response** (`200 OK`): Updated PermissionResponse

### DELETE `/api/permissions/{permission_id}`
**Immediate Revocation Endpoint**: Purges permission row from database. Subsequent access attempts by target collaborator fail immediately. Owner-only.
- **Headers**: `X-CSRF-Token: <token>`
- **Response** (`200 OK`): `{"message": "Permission successfully revoked."}`

---

## 4. Tamper-Evident Audit Endpoints

### GET `/api/audit`
Lists audit events.
- **Query Parameters**: `action`, `resource_type`, `limit`, `offset`
- **Response** (`200 OK`):
  ```json
  {
    "total": 42,
    "items": [
      {
        "id": "event-uuid",
        "sequence_number": 12,
        "actor_email": "alice@trustvault.local",
        "action": "DOCUMENT_DOWNLOAD",
        "resource_type": "DOCUMENT",
        "outcome": "SUCCESS",
        "timestamp_utc": "2026-11-05T12:30:00Z",
        "previous_hash": "4a8e...",
        "current_hash": "9b1c...",
        "metadata": { ... }
      }
    ]
  }
  ```

### GET `/api/audit/documents/{document_id}`
Retrieves audit history for a specific document. Requires document `READ` permission.

### POST `/api/audit/verify`
Traverses and re-hashes entire SHA-256 chain from genesis to latest record.
- **Headers**: `X-CSRF-Token: <token>`
- **Response** (`200 OK`):
  ```json
  {
    "is_valid": true,
    "total_events_verified": 42,
    "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "latest_hash": "9b1c...",
    "broken_at_sequence": null,
    "error_detail": null,
    "verified_at": "2026-11-05T12:45:00Z"
  }
  ```

---

## 5. Administration Endpoints

### GET `/api/admin/users`
Lists all registered users, roles, active session counts, and document counts. Admin-only.

### PATCH `/api/admin/users/{user_id}/status`
Activates or deactivates user account. Deactivation terminates all active sessions. Admin-only.
- **Request Body**: `{"is_active": false}`
- **Headers**: `X-CSRF-Token: <token>`

### GET `/api/admin/activity`
Streams all security-relevant anomaly events (`ACCESS_DENIED`, `LOGIN_FAILURE`, `LOGIN_RATE_LIMITED`). Admin-only.

### GET `/api/admin/stats`
Returns system metrics and audit chain integrity status. Admin-only.
