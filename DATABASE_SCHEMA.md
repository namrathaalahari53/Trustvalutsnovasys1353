# TrustVault Database Schema & Architecture

Engine: SQLAlchemy 2.0 ORM  
Driver Support: SQLite (Local development & automated testing) and PostgreSQL (Production)

---

## 1. Relational Entity Relationship Diagram

```text
       +-------------------+
       |       users       |
       +-------------------+
       | id (PK)           |<-----+
       | email (UQ)        |      |
       | username (UQ)     |      |
       | hashed_password   |      |
       | role              |      |
       | is_active         |      |
       | created_at        |      |
       +-------------------+      |
         |         |              |
         | 1:N     | 1:N          |
         v         v              |
+--------------+  +---------------+  |
|   sessions   |  |   documents   |  |
+--------------+  +---------------+  |
| id (PK)      |  | id (PK)       |  |
| token_hash   |  | owner_id (FK) |  |
| user_id (FK) |  | title         |  |
| is_active    |  | storage_fn    |  |
| expires_at   |  | file_size     |  |
+--------------+  | sha256        |  |
                  +---------------+  |
                         |           |
                         | 1:N       |
                         v           |
              +----------------------+
              | document_permissions |
              +----------------------+
              | id (PK)              |
              | document_id (FK)     |
              | user_id (FK) --------+
              | permission (READ/EDIT)|
              | granted_by (FK)      |
              +----------------------+

+-----------------------------------------+
|              audit_events               |
+-----------------------------------------+
| id (PK)                                 |
| sequence_number (UQ, Indexed, Sequential)|
| actor_id (FK/Nullable)                  |
| action                                  |
| resource_type                           |
| resource_id                             |
| outcome (SUCCESS/FAILURE/DENIED)        |
| metadata_json (Canonical Dict)          |
| timestamp_utc                           |
| previous_hash (SHA-256 of Seq - 1)      |
| current_hash (SHA-256 of Current + Prev) |
+-----------------------------------------+
```

---

## 2. Table Definitions

### 2.1 Table: `users`
Stores authenticated enterprise identities and access credentials.
- `id`: `VARCHAR(36)` Primary Key (UUID v4)
- `email`: `VARCHAR(255)` Unique, Indexed, Not Null
- `username`: `VARCHAR(64)` Unique, Indexed, Not Null
- `hashed_password`: `VARCHAR(255)` Not Null (Argon2id digest)
- `role`: `VARCHAR(32)` Default `'user'` (`'admin'` or `'user'`)
- `is_active`: `BOOLEAN` Default `TRUE`
- `created_at`: `DATETIME` UTC
- `updated_at`: `DATETIME` UTC

### 2.2 Table: `sessions`
Server-side active user sessions.
- `id`: `VARCHAR(36)` Primary Key (UUID v4)
- `session_token_hash`: `VARCHAR(64)` Unique, Indexed (SHA-256 digest of 48-byte token)
- `user_id`: `VARCHAR(36)` Foreign Key -> `users.id` (ON DELETE CASCADE)
- `is_active`: `BOOLEAN` Default `TRUE`
- `expires_at`: `DATETIME` Indexed (TTL 24 hours)
- `ip_address`: `VARCHAR(64)` Nullable
- `user_agent`: `VARCHAR(255)` Nullable
- **Indexes**: `idx_sessions_user_active (user_id, is_active)`

### 2.3 Table: `documents`
Encrypted/protected document catalog.
- `id`: `VARCHAR(36)` Primary Key (UUID v4)
- `owner_id`: `VARCHAR(36)` Foreign Key -> `users.id` (ON DELETE CASCADE)
- `title`: `VARCHAR(255)` Indexed, Not Null
- `description`: `TEXT` Nullable
- `original_filename`: `VARCHAR(255)` Sanitized
- `storage_filename`: `VARCHAR(255)` Unique (`f_{uuid}.bin`)
- `file_size`: `INTEGER` Bytes
- `mime_type`: `VARCHAR(128)` Verified MIME
- `file_hash_sha256`: `VARCHAR(64)` File checksum
- `is_deleted`: `BOOLEAN` Default `FALSE`
- `created_at`: `DATETIME` UTC
- `updated_at`: `DATETIME` UTC
- **Indexes**: `idx_docs_owner_deleted (owner_id, is_deleted)`

### 2.4 Table: `document_permissions`
Authoritative permission grants.
- `id`: `VARCHAR(36)` Primary Key (UUID v4)
- `document_id`: `VARCHAR(36)` Foreign Key -> `documents.id` (ON DELETE CASCADE)
- `user_id`: `VARCHAR(36)` Foreign Key -> `users.id` (ON DELETE CASCADE)
- `permission`: `VARCHAR(16)` (`'READ'` or `'EDIT'`)
- `granted_by`: `VARCHAR(36)` Foreign Key -> `users.id`
- `created_at`: `DATETIME` UTC
- `updated_at`: `DATETIME` UTC
- **Constraints**: `UNIQUE (document_id, user_id)`
- **Indexes**: `idx_doc_user_perm (document_id, user_id, permission)`

### 2.5 Table: `audit_events`
Cryptographically chained SHA-256 tamper-evident log.
- `id`: `VARCHAR(36)` Primary Key (UUID v4)
- `sequence_number`: `INTEGER` Unique, Contiguous, Indexed
- `actor_id`: `VARCHAR(36)` Nullable, Indexed
- `actor_email`: `VARCHAR(255)` Nullable
- `action`: `VARCHAR(64)` Indexed (e.g., `DOCUMENT_DOWNLOAD`, `ACCESS_DENIED`)
- `resource_type`: `VARCHAR(32)` (`DOCUMENT`, `USER`, `PERMISSION`, `SYSTEM`)
- `resource_id`: `VARCHAR(36)` Nullable, Indexed
- `outcome`: `VARCHAR(16)` (`SUCCESS`, `FAILURE`, `DENIED`)
- `ip_address`: `VARCHAR(64)` Nullable
- `user_agent`: `VARCHAR(255)` Nullable
- `metadata_json`: `TEXT` Canonical stringified JSON
- `timestamp_utc`: `VARCHAR(32)` ISO-8601 UTC string
- `previous_hash`: `VARCHAR(64)` SHA-256 of sequence - 1
- `current_hash`: `VARCHAR(64)` Unique, Indexed
- **Indexes**:
  - `idx_audit_actor_action (actor_id, action)`
  - `idx_audit_resource (resource_type, resource_id)`
  - `idx_audit_seq_hash (sequence_number, current_hash)`

### 2.6 Table: `password_reset_tokens`
Single-use password reset tokens.
- `id`: `VARCHAR(36)` Primary Key (UUID v4)
- `user_id`: `VARCHAR(36)` Foreign Key -> `users.id` (ON DELETE CASCADE)
- `token_hash`: `VARCHAR(64)` Unique, Indexed
- `expires_at`: `DATETIME` Indexed (15-minute TTL)
- `used`: `BOOLEAN` Default `FALSE`
- `created_at`: `DATETIME` UTC
