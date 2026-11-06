# First-Run Setup Race Conditions in Self-Hosted Applications

## Overview

During a security research session conducted on isolated lab environments, a recurring vulnerability pattern was identified across multiple popular self-hosted applications. The pattern affects the **first-run setup flow** — the initial administrator account creation that most tools expose before any authentication is configured.

**The bug**: the setup handler checks if an admin already exists, hashes a password with bcrypt (50-100ms window), then writes the new user. No transaction, no lock, no uniqueness constraint. Two concurrent requests both pass the check.

**The result**: multiple administrator accounts created on a fresh instance, each with working credentials.

---

## Affected Software

| Software | Version | Language | Severity | Impact |
|----------|---------|----------|----------|--------|
| n8n | 2.46.6 | TypeScript | Medium-High | Session hijack (7-day cookie) |
| Uptime Kuma | latest | Node.js | High | Two persistent admin accounts |
| Grav CMS | latest (plugin api) | PHP | High | Two persistent super-admin accounts |
| Navidrome | 0.64.2 | Go | High | Two persistent admin accounts |

Four different stacks. Same bug.

---

## Technical Detail

### n8n — `POST /rest/owner/setup`

**Location**: `ownership.service.js:160-185`

```
hasInstanceOwner()  →  findOne()  →  bcrypt hash  →  save()
     CHECK              await         ~100ms          WRITE
```

The check and write are separated by two async calls including a bcrypt hash. No transaction wraps them. The save explicitly passes `{ transaction: false }`.

**Detection**: `GET /rest/settings` returns `"showSetupOnFirstLoad":true` while the instance has no owner. Unauthenticated, no trace.

**Race outcome**: both requests receive HTTP 200 and an owner session cookie. One account wins the database row; the loser's cookie remains valid for 7 days (`jwtSessionDurationHours: 168`). No automatic revocation.

**Fix**: partial unique index on the owner role (`CREATE UNIQUE INDEX ... WHERE role = 'global:owner'`).

---

### Uptime Kuma — socket.io event `setup`

**Location**: `server.js:608-628`

```
R.count("user") !== 0  →  passwordHash.generate()  →  R.store(user)
       CHECK                    bcrypt ~100ms              WRITE
```

The `needSetup` flag is set to `false` only **after** the store completes — even the in-memory mitigation fires too late.

**Detection**: the server pushes `42["setup"]` to every new unauthenticated socket.io connection while no user exists.

**Race outcome**: two separate rows in the `user` table, both `active:1`. Each attacker logs in with their own credentials. Not a winner/loser race — both accounts persist independently.

**Fix**: database constraint limiting the user table to one row (single-user model), plus an application mutex around the handler.

---

### Grav CMS — `POST /api/v1/auth/setup`

**Location**: `SetupController.php` (plugin `api`)

```
noAccountsExist()  →  $accounts->count()  →  $user->exists()  →  bcrypt  →  save()
     CHECK 1              CHECK 2                  CHECK 3         ~100ms     WRITE
```

The developer added a comment: *"Second race-guard check after acquiring accounts"*. The intent was there. The execution is incomplete — `$user->exists()` only guards against the **same username**. Two different usernames bypass all three checks.

**Detection**: `GET /api/v1/auth/setup` returns `"setup_required":true` pre-auth.

**Race outcome**: two YAML account files created on disk, both with `access.api.super: true`, each receiving an access/refresh JWT pair. Both sets of credentials work on subsequent logins.

**Fix**: atomic file lock (`flock()` or `O_EXCL` marker) acquired before the bcrypt hash.

---

### Navidrome — `POST /auth/createAdmin`

**Location**: `server/auth.go:122-145` and `persistence/user_repository.go:116-161`

```
CountAll()  →  createAdminUser(IsAdmin:true, randomID)  →  Put()
  CHECK              bcrypt + ID generation                  WRITE
```

`Put()` attempts an UPDATE by ID then falls back to INSERT. No lock, no transaction wrapping CountAll+Put, no constraint enforcing single-admin.

**Detection**: `GET /app/` exposes `window.__APP_CONFIG__` containing `firstTime:true`.

**Race outcome**: two users with distinct IDs, both `isAdmin:true`, both receiving JWTs with `adm:true` claims. Sequential logins confirm both accounts are persistent.

**Fix**: singleton marker table with `INSERT ... ON CONFLICT DO NOTHING` claimed before user creation.

---

## Not Affected

| Software | Why |
|----------|-----|
| Portainer CE 2.45.3 | Setup token generated at boot, printed only in container logs. `POST /api/users/admin/init` requires `X-Setup-Token` header. Not accessible via network. |
| NocoDB | Race produces viewer + creator roles. Only one super-admin. Public signup defaults to viewer. |
| Memos 26.11.0 | Both requests succeed but only one ADMIN role is assigned. Role injection blocked. |

---

## The Pattern

Every vulnerable product follows the same three-step sequence:

1. **Existence check** — "is this the first user?"
2. **Expensive operation** — bcrypt hash, ~50-100ms
3. **Write** — create the account

Steps 1 and 3 are never atomic. The bcrypt hash in step 2 widens the race window to the point where two simple concurrent HTTP requests reliably exploit it.

The fix is known and demonstrated by Portainer: gate the setup behind a secret that is not accessible via the network. Alternatively, wrap steps 1-3 in a transaction or acquire a lock before step 2.

---

## Detection Signatures

For each affected product, the setup window is observable without authentication:

| Product | Endpoint | Indicator |
|---------|----------|-----------|
| n8n | `GET /rest/settings` | `"showSetupOnFirstLoad":true` |
| Uptime Kuma | socket.io connection | `42["setup"]` push |
| Grav | `GET /api/v1/auth/setup` | `"setup_required":true` |
| Navidrome | `GET /app/` | `firstTime:true` in `__APP_CONFIG__` |
| Portainer | `POST /api/users/admin/init` | `400` without `X-Setup-Token` |

---

## Disclosure Status

All findings are documented. No public disclosure has been made. Responsible disclosure to each project's security channel is planned.

---

*Research conducted on isolated lab environments. No production systems were affected.*
