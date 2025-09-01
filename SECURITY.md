# Security Considerations

This document outlines important security practices and built‑in protections in `axum-gate`, plus guidance for deploying it safely in production environments.

---

## 1. Password / Secret Security

- **Modern KDF**: Uses Argon2id with per‑secret random salt.
- **No Plain Text Storage**: Only salted Argon2 hashes are persisted.
- **Constant‑Time Verification**: Credential verification always performs an Argon2 hash check (even for non‑existent accounts) using a dummy hash to eliminate user enumeration via timing.
- **Unicode & Length Handling**: Arbitrary UTF‑8 secrets are supported; extremely large inputs should still be constrained at your application boundary (recommend enforcing sane max lengths).

### (Planned) Configurable Argon2 Parameters

A forthcoming update (see CHANGELOG) introduces an `Argon2Config` builder offering:
- Memory cost (KiB)
- Time cost (iterations)
- Parallelism
- Presets: `HighSecurity` (default), `Interactive`, `DevFast`
  
Default settings are intentionally conservative (security first) so you do **not** need different code paths for debug vs. release. You may *opt in* to weaker parameters explicitly (e.g. for CI speed) using provided preset methods once the patch lands.

---

## 2. JWT Token Security

- **Signature Validation**: All tokens are verified with the configured signing key.
- **Expiration Enforcement**: Standard `exp` claim is validated.
- **Issuer Validation**: The `iss` claim must match the expected issuer configured in the Gate.
- **Tamper Detection**: Any modification invalidates the signature.
- **Header Consistency Check**: The library enforces that decoded headers match the encoding header (defense‑in‑depth against algorithm substitution).

### Key Management Guidance

- **Ephemeral Default**: The default codec generates a random key each process start—ideal for tests, **not for production** (all sessions invalidate on restart).
- **Production**: Load a stable secret (env var, file, KMS, HashiCorp Vault, etc.). Rotate keys periodically; if you require seamless rotation, introduce a small wrapper that keeps (active, next) keys and attempts both for decode.

---

## 3. Cookie Security

When using cookie‑based auth:
```rust
let cookie_template = axum_gate::cookie::CookieBuilder::new("auth-cookie", "")
    .secure(true)                // HTTPS only
    .http_only(true)             // Unavailable to JS - mitigates XSS credential theft
    .same_site(cookie::SameSite::Strict) // Strong CSRF mitigation
    .path("/")
    .domain("example.com");
```

Recommendations:
- Use a stable, explicit cookie name (prefix with `__Host-` if you can: requires Secure + no Domain attribute + Path=/).
- Always set `secure(true)` in production.
- Use `SameSite=Strict` or `Lax`; if you must allow cross‑site, add a secondary CSRF token mechanism.

---

## 4. Authorization Security

- **Default Deny**: A `Gate` with no policy denies all requests.
- **Least Privilege**: Combine roles, groups, and permissions narrowly; avoid broad “admin” grants for public endpoints.
- **Role Hierarchy**: Supervisor traversal is explicit via `require_role_or_supervisor`.
- **Fine‑Grained Permissions**: Deterministic 64‑bit IDs from normalized names; collisions are extraordinarily improbable and validated.

---

## 5. Permission System Safety

- **Deterministic Hashing**: 64‑bit identifiers derived from SHA‑256 prefix lower collision probability dramatically.
- **Validation Macro**: `validate_permissions![ ... ]` adds compile‑time and test‑time assurance.
- **Runtime Validation**: `PermissionCollisionChecker` & `ApplicationValidator` help guard dynamic permission sets (config/database sourced).
- **Duplicates vs Collisions**: The validators distinguish identical strings (duplicates) from true hash collisions (the latter are practically nonexistent but still reported if ever encountered).

---

## 6. Timing Attack Mitigation

Implemented protections:

| Vector | Mitigation |
|--------|------------|
| User enumeration via timing | Always performs Argon2 verification with dummy hash for absent accounts. |
| Distinguishing “wrong user” vs “wrong password” | Unified `InvalidCredentials` result. |
| Early returns shortening path | Logic defers branching until after constant‑time combination. |

You do *not* need to add artificial delays; the hashing dominates timing uniformly.

---

## 7. Rate Limiting & Brute Force Defense

Argon2 is intentionally expensive; still add:
- **Global & per‑IP rate limiting** (e.g. tower middleware).
- **Progressive backoff / account lockout** policy after N failures (optional, beware enumeration side‑channels).
- **Central logging & alerting** for anomaly detection.

---

## 8. CSRF Considerations

- Cookie authentication is susceptible to CSRF if `SameSite=None`.
- Recommended:
  - Prefer `SameSite=Strict` for sensitive panels.
  - For cross‑site POST needs, implement a double‑submit or synchronizer token (not bundled here).
  - Consider using bearer tokens (header‑based) for APIs consumed by third parties (planned feature).

---

## 9. Session & Logout Behavior

- Stateless JWT means logout is client‑side cookie removal.
- For *forced* invalidation (compromised account):
  - Introduce a server‑side denylist (keyed by `jti` or account ID + issued_at threshold).
  - Alternatively, rotate signing key (global invalidation).
- Consider embedding a short `exp` and refreshing tokens periodically (sliding session window pattern) in future enhancements.

---

## 10. Operational Hardening Checklist

| Area | Recommendation |
|------|---------------|
| Transport | Enforce HTTPS; HSTS on parent domain. |
| JWT Signing Key | Stable, high‑entropy secret (≥32 bytes). Rotate periodically. |
| Argon2 Parameters | Use default high‑security preset; tune memory to your latency budget (monitor p95). |
| Rate Limiting | Apply per‑IP & global on login endpoint. |
| Monitoring | Log success/failure counts, anomaly spikes. |
| Auditing | Record role/permission change events. |
| Dependency Updates | Track `argon2`, `jsonwebtoken`, and `axum` CVEs. |
| Backups | Securely backup persistent stores (if using DB backends). |
| Secrets Handling | Store secrets outside the repository, inject at runtime (env, secret manager). |
| CSRF | Use `SameSite` cookies or explicit tokens. |

---

## 11. Storage Security

- **Separation**: Optional deployment of account metadata and secret storage to distinct infrastructure.
- **Least Privilege Credentials**: Database users should have only needed permissions.
- **Deletion Order**: Ensure application logic handles partial failures (e.g., wrap account + secret deletion in a transactional pattern if backend supports it).

---

## 12. Input Validation & Abuse Resistance

Implement upstream validation for:
- Max password length (prevents pathological Argon2 resource exhaustion).
- Allowed username patterns (log & reject suspicious payloads).
- JSON size limits (avoid large body DoS).

---

## 13. Security Testing

Areas covered by existing tests:
- Timing uniformity (login service tests).
- Permission system (grant/revoke, collision detection).
- Authorization semantics (role/group/supervisor rules).
- JWT decoding & issuer validation.

Suggested additional tests (you can add internally):
- Fuzz permission name normalization invariants.
- Property tests for permission ID determinism.
- Load tests for varied Argon2 parameter profiles.

Run existing tests:
```bash
cargo test
```
(Planned: dedicated security test groups once Argon2 configurability lands.)

---

## 14. Future / Planned Enhancements

| Feature | Security Benefit |
|---------|------------------|
| Key rotation utilities | Rolling updates without global logout. |
| Bearer token Gate | Header-based auth for SPA / API clients. |
| Argon2 config API (in progress) | Tunable defense against brute force, adaptive to hardware. |
| Rate limit helper | Turn‑key brute force mitigation. |
| Audit hooks | Unified security event stream. |

---

## 15. Reporting Vulnerabilities

If you discover a security issue:
1. **Do not** open a public issue immediately.
2. Contact the maintainer (see `Cargo.toml` author field or repository security policy).
3. Provide reproduction steps & impact assessment.
4. A coordinated disclosure timeline will be established.

---

**Stay secure**: Treat this middleware as one layer—combine it with infrastructure hardening, observability, and sound operational processes for a robust authentication surface.