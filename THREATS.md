# TrustVault Threat Model & Risk Analysis

## 1. Protected Assets
- **Confidential Document Data**: Stored in `./private_storage/` with randomized UUID filenames outside web root.
- **Authoritative Permissions Mapping**: Mappings of `(document_id, user_id, permission)` governing READ and EDIT access.
- **Tamper-Evident Audit Trail**: Cryptographically linked sequence of SHA-256 event digests.
- **User Authentication Credentials**: Argon2id password hashes with 64MB memory cost and 2 iterations.
- **Active Server Sessions**: SHA-256 hashed session identifiers in server database.
- **Password Reset Tokens**: Single-use, expiring SHA-256 hashed tokens.

---

## 2. Trust Boundaries
1. **Client Browser vs. TrustVault Web Application**: All browser inputs (filenames, parameters, user IDs, headers) are untrusted.
2. **Web Layer vs. Authoritative Database**: Authorization decisions are executed exclusively at the database layer; cached browser state is disregarded.
3. **Application Layer vs. Private Storage Subsystem**: Direct filesystem access is isolated to the `StorageService` using canonical path validation and random identifiers.
4. **Tenant Isolation Boundary**: Documents belonging to User A are strictly isolated from User B unless explicit row-level permissions exist.

---

## 3. Attackers & Capabilities

| Threat Actor | Capabilities | Target |
| :--- | :--- | :--- |
| **Anonymous Web Attacker** | External network access, fuzzing, brute force, token guessing | Public auth endpoints, URL enumeration, session hijacking |
| **Malicious Authenticated User (Viewer)** | Legitimate account, READ access to shared document | Privilege escalation to EDIT, unauthorized re-sharing, IDOR download of private documents |
| **Revoked Collaborator** | Formerly possessed valid READ or EDIT access | Retaining access after revocation via cached tokens or stale links |
| **Malicious Insider / Storage Observer** | Read access to host filesystem | Direct file reading without passing through authorization engine |
| **Compromised Database Operator** | Read/write access to relational tables | Modifying audit events, forging historical access records |

---

## 4. Threat Scenarios & Mitigations

### 4.1 Insecure Direct Object References (IDOR)
- **Threat**: An attacker guesses or enumerates document UUIDs to access private files.
- **Mitigation**: `AuthorizationEngine.check_document_access()` is invoked on every resource access (`/api/documents/{id}`, `/api/documents/{id}/download`, etc.). The check queries the authoritative database state. If the user is neither the owner nor granted an active permission record, the request is rejected with 403 or 404, and an `ACCESS_DENIED` audit event is logged.

### 4.2 Privilege Escalation (Horizontal & Vertical)
- **Threat**: A Viewer with `READ` attempts to send a `PATCH` request to alter document contents or title, or attempts to grant permissions to a third party.
- **Mitigation**: Resource operations explicitly check required action capabilities:
  - `READ`: Requires `permission in ('READ', 'EDIT')` or ownership.
  - `EDIT`: Requires `permission == 'EDIT'` or ownership.
  - `DELETE` & `SHARE`: Strictly reserved for document owners. Viewers cannot escalate privileges.

### 4.3 Revocation Bypass (Stale Access)
- **Threat**: User A revokes User B's access. User B attempts to access cached download URLs or reuse old requests.
- **Mitigation**: Zero JWT/cached permission tokens are used. The application queries the `DocumentPermission` table in real-time on every incoming request. Deletion of the permission record takes effect immediately (within the same database transaction).

### 4.4 File Upload & Path Traversal Attacks
- **Threat**: Uploading executable payloads (`.exe`, `.sh`), script injection, or directory traversal via filenames like `../../etc/passwd`.
- **Mitigation**:
  1. Filename sanitization normalizes slashes and strips directory components using `os.path.basename`.
  2. Storage files are saved under server-generated UUID names (e.g., `f_c92b...bin`) in a private directory.
  3. Strict file signature (magic bytes) validation matches actual byte headers (e.g. `%PDF-`, PNG header, JPEG header) against declared extensions.
  4. File size limits (25 MB) prevent denial-of-service storage exhaustion.

### 4.5 CSRF & Session Attacks
- **Threat**: Cross-Site Request Forgery executing unauthorized state-changing operations via cookie credentials.
- **Mitigation**: Double-submit signed CSRF token validation on all mutating methods (`POST`, `PATCH`, `DELETE`). Cookies are configured with `SameSite=Lax` and `HttpOnly`.

### 4.6 Tampering with Audit History
- **Threat**: An attacker modifies or deletes an audit event to conceal unauthorized access.
- **Mitigation**: Every event is cryptographically bound into a SHA-256 hash chain:
  $$H_i = \text{SHA256}(\text{CanonicalJSON}(\text{Event}_i) \parallel H_{i-1})$$
  The verification endpoint `/api/audit/verify` recalculates the canonical digest for all events from genesis ($H_0 = 0^{64}$) to the latest record. Any altered field, deleted sequence number, or reordered event causes an immediate verification failure.

---

## 5. Residual Risks & Security Considerations
1. **Host-Level Compromise**: An attacker with full root shell access can read private storage files or drop the database. Host-level OS hardening and filesystem encryption at rest (LUKS/eCryptfs) are recommended for production.
2. **Complete Chain Rewrite by DB Superuser**: While a hash chain detects unilateral edits or deletions, a database superuser who recalculates the entire chain from the tampered record forward could produce a syntactically valid chain if they control all records. To counter this, production deployments should periodically export signed cryptographic checkpoints to external append-only storage (e.g., AWS S3 Object Lock with WORM enabled).
