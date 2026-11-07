# TrustVault Development Log & Engineering Prompts

This log documents five actual development stages during the engineering of TrustVault, detailing initial prompt specifications, observed tool outputs, identified bugs, and implemented fixes.

---

### Entry 1 — 2026-11-05: Argon2id Password Hasher Initialization
- **Context & Prompt**: Initialize core security utilities in `app/core/security.py` using RFC 9106 recommended parameters (64 MB memory cost, 2 iterations, Argon2id type).
- **Observed Tool Output**:
  ```text
  ImportError while loading conftest '/app/applet/tests/conftest.py'.
  ...
  /usr/local/lib/python3.11/dist-packages/argon2/_password_hasher.py:114: in __init__
      raise TypeError(e)
  TypeError: 'type' must be a Type (got int).
  ```
- **Identified Issue**: `_ph = PasswordHasher(..., type=2)` passed an integer instead of the `argon2.Type` enum required by the installed `argon2-cffi` version.
- **Code Change**: Imported `Type` from `argon2` and set `type=Type.ID` in `app/core/security.py`:
  ```python
  from argon2 import PasswordHasher, Type
  _ph = PasswordHasher(
      time_cost=2,
      memory_cost=65536,
      parallelism=1,
      hash_len=32,
      type=Type.ID,
  )
  ```

---

### Entry 2 — 2026-11-05: Pydantic RFC Reserved TLD Validation in Test Environments
- **Context & Prompt**: Validate registration and authentication request schemas using Pydantic.
- **Observed Tool Output**:
  ```text
  pydantic_core._pydantic_core.ValidationError: 1 validation error for RegisterRequest
  email
    value is not a valid email address: The part after the @-sign is a special-use or reserved name that cannot be used with email. [type=value_error, input_value='tester1@trustvault.local']
  ```
- **Identified Issue**: `pydantic.EmailStr` (powered by `email-validator`) rejects `.local` TLDs under RFC 6762 (mDNS special-use domain), causing tests with local domain names to fail schema validation with HTTP 422.
- **Code Change**: Swapped `EmailStr` in request schemas to use an enterprise-compliant regex `pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"` and migrated model configs to Pydantic V2 `ConfigDict(from_attributes=True)`.

---

### Entry 3 — 2026-11-05: Rate Limiter Double-Counting on Failed Login Attempts
- **Context & Prompt**: Protect `/api/auth/login` with sliding window rate limiting (5 attempts per minute).
- **Observed Tool Output**:
  ```text
  FAILED tests/security/test_rate_limiting.py::test_login_brute_force_rate_limiting
  assert r_fail.status_code == 401
  assert 429 == 401
  + where 429 = <Response [429 Too Many Requests]>.status_code
  ```
- **Identified Issue**: `RateLimiter.is_rate_limited()` appended the current timestamp on every invocation, and then `login()` additionally called `RateLimiter.record_failure()` on credential failure. This caused failed logins to be recorded twice per attempt, triggering 429 on attempt 3 rather than after 5 failed attempts.
- **Code Change**: Added `record: bool = True` parameter to `RateLimiter.is_rate_limited()`. In `login()`, called `is_rate_limited(..., record=False)` so that only `record_failure()` logs failures, allowing exactly 5 attempts before enforcing rate limits.

---

### Entry 4 — 2026-11-05 [Authorization Focus]: Immediate Revocation Workflow Enforcement
- **Context & Prompt**: Enforce mandatory immediate permission revocation where User A revokes User B's access, and User B's subsequent requests are blocked instantly without relying on token expiration or cached state.
- **Observed Tool Output**:
  ```text
  tests/security/test_immediate_revocation.py::test_mandatory_immediate_revocation_workflow PASSED [ 37%]
  ```
- **Architectural Verification**:
  - `DELETE /api/permissions/{id}` removes row from `document_permissions` table within database transaction.
  - `require_document_access()` in `app/core/permissions.py` re-queries the authoritative database table on every read, preview, update, and download request.
  - Verified that User B's retry to download the document returns HTTP 403/404, and an `ACCESS_DENIED` event is automatically appended to the SHA-256 audit chain.

---

### Entry 5 — 2026-11-05 [Audit Focus]: SHA-256 Tamper-Evident Hash Chain Verification
- **Context & Prompt**: Implement cryptographic hash chaining of all security-relevant audit records and verify detection of tampered or deleted events.
- **Observed Tool Output**:
  ```text
  tests/unit/test_hash_chain.py::test_audit_hash_chain_creation_and_verification PASSED [ 75%]
  tests/unit/test_hash_chain.py::test_audit_hash_chain_detects_tampered_payload PASSED [ 79%]
  tests/unit/test_hash_chain.py::test_audit_hash_chain_detects_deleted_event PASSED [ 83%]
  ```
- **Architectural Verification**:
  - Genesis event initialized with `previous_hash = "0" * 64`.
  - Canonical JSON serialization with sorted keys guarantees deterministic SHA-256 digests.
  - Direct database mutation of an event's payload in `test_audit_hash_chain_detects_tampered_payload` was immediately detected by `AuditService.verify_chain()`, pinpointing the exact sequence number and failure reason.
  - Deletion of an intermediate event was identified as a sequence gap and broken link.
