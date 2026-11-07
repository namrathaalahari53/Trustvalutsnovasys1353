# TrustVault Security Architecture & Specifications

## 1. Authentication Architecture
- **Password Hashing**: Implemented via `argon2-cffi` adhering to RFC 9106.
  - Type: Argon2id (hybrid data-dependent and data-independent memory access)
  - Time Cost: 2 iterations
  - Memory Cost: 65,536 KiB (64 MiB)
  - Parallelism: 1 lane
  - Salt: Cryptographically secure 16-byte random salt generated per hash
- **Password Complexity Policy**:
  - Minimum length: 8 characters (maximum 128 characters)
  - Character set diversity: At least one uppercase letter, one lowercase letter, one numeric digit, and one special symbol (`[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]`)
- **Brute-Force & Credential Stuffing Defense**:
  - In-memory sliding window rate limiter (`RateLimiter`)
  - Maximum 5 failed attempts per 60 seconds per IP / account identifier
  - Excess attempts blocked with HTTP `429 Too Many Requests`
  - Successful logins clear failed attempt history
- **Password Reset Mechanism**:
  - Single-use, expiring URL-safe random reset tokens (15-minute TTL)
  - Tokens stored as SHA-256 digests in database (`PasswordResetToken`)
  - Password reset automatically invalidates all active user sessions across all devices

---

## 2. Server-Side Session Management
- **Token Security**: 48-byte URL-safe cryptographic entropy generated via `secrets.token_urlsafe(48)`.
- **Database Storage**: Raw tokens are never stored in plaintext; stored as deterministic SHA-256 hashes (`session_token_hash`).
- **Cookie Attributes**:
  - `HttpOnly`: Prevents JavaScript DOM access and XSS theft
  - `SameSite=Lax`: Mitigates Cross-Site Request Forgery
  - `Secure`: Enforced in HTTPS production environments
  - `Path=/`: Scoped to application root
- **Session Revocation**:
  - User logout immediately sets `is_active = False` in database
  - Account deactivation by administrators immediately terminates all active sessions for the target user

---

## 3. Centralized Authorization Engine
- **Default-Deny Access Policy**: If an explicit permission grant is not verified in the authoritative database state, access is unconditionally denied.
- **Resource Ownership Verification**: Document ownership is enforced at the server layer using `current_user.id == document.owner_id`.
- **Authoritative Real-Time Checks**: Access is never granted based on JWT claims, cached authorization state, or frontend flags. The `document_permissions` table is queried in real-time during every read, update, preview, and download request.
- **Role Hierarchy**:
  - **Administrator**: Global tenant visibility, user account status management, system-wide security anomaly auditing.
  - **Document Owner**: Exclusive right to update metadata, delete files, and grant, modify, or revoke collaborator permissions.
  - **Viewer (READ)**: Authorized to read metadata and download the file. Cannot modify metadata, cannot delete, cannot re-share.
  - **Viewer (EDIT)**: Authorized to update title and description. Cannot delete and cannot share.
- **Immediate Revocation**: Deletion of a permission record takes effect immediately; subsequent requests from the revoked user trigger HTTP 403 / 404 and record an `ACCESS_DENIED` audit event.

---

## 4. Secure File Storage & Validation
- **Private Filesystem Storage**: Files reside in `./private_storage/` outside of any static or public web root.
- **Randomized Storage Identifiers**: Storage filenames follow the strict pattern `f_{uuid4().hex}.bin` to prevent identifier predictability.
- **Magic Bytes Validation**: Binary contents are inspected against accepted file signatures:
  - PDF: `%PDF-` (`0x25 0x50 0x44 0x46 0x2D`)
  - PNG: `\x89PNG\r\n\x1a\n` (`0x89 0x50 0x4E 0x47 0x0D 0x0A 0x1A 0x0A`)
  - JPEG: `\xFF\xD8\xFF`
  - DOCX / XLSX: ZIP container signature `PK\x03\x04`
  - Text / CSV / JSON: Clean UTF-8 decodability, rejection of embedded null bytes (`\x00`), and strict JSON grammar parsing
- **Path Traversal Mitigation**: File paths are validated with `os.path.abspath` to guarantee target paths are strictly within the designated storage root.

---

## 5. Tamper-Evident SHA-256 Audit Trail
- **Deterministic Serialization**: Event payloads are normalized into canonical JSON with sorted keys and compact separators (`separators=(",", ":")`).
- **Cryptographic Hash Chaining**:
  $$H_0 = \text{"0"} \times 64$$
  $$H_i = \text{SHA256}(\text{CanonicalJSON}(\text{Sequence}_i, \text{ID}_i, \text{Actor}_i, \text{Action}_i, \text{Outcome}_i, \text{Time}_i, \text{Meta}_i, H_{i-1}))$$
- **Verification Routine**: Recomputes all event digests and checks strict sequence continuity from genesis to the latest event. Detects tampered event fields, missing/deleted records, and reordered blocks.
- **Exclusion of Sensitive Data**: Passwords, raw session tokens, reset tokens, and cookie values are programmatically stripped from audit metadata.
